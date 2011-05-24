#!/usr/bin/env python

import datetime
import fnmatch
import getopt
import glob
import mimetypes
import os
import platform
import re
import shutil
import signal
import stat
import sys
import tarfile
import tempfile
import xml.dom.minidom

import base64
try:
    from hashlib import md5
except ImportError:
    from md5 import md5

def OutputAndExit(message):
  sys.stderr.write('%s\n' % message)
  sys.exit(1)

# make sure we are using the boto version included with s3push
s3push_bin_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
if not s3push_bin_dir:
  OutputAndExit('Unable to determine where s3push is installed.\n')
boto_lib_dir = s3push_bin_dir + os.sep + 'boto'
if not os.path.isdir(boto_lib_dir):
  OutputAndExit('There is no boto library under the s3push install directory.\n')
sys.path.insert(1, boto_lib_dir)

import boto
boto.UserAgent = boto.UserAgent + '/s3push'
from boto import handler

usage_string = """
SYNOPSIS
  s3push command args

  Commands:
    push [-p] [-s] [-y] src_uri dst_uri
      Copy objects from one URI to another only if they differ.
      Options:
        -p : prune.     Delete objects at destination that do not exist at source.
        -s : simulate.  Simulate actions but do not actually perform them.
        -y : yes.       Bypass confirmation prompt, assuming yes.
"""

def OutputUsageAndExit():
  sys.stderr.write(usage_string)
  sys.exit(0)

def PushCommand(args, sub_opts):
  """Implementation of push command.

    Copy objects from one URI to another only if they differ.

  Args:
    args: command-line arguments
    sub_opts: command-specific options from getopt.
  """

  # capture options
  opt_prune = False
  opt_simulate = False
  opt_yes = False
  for o, foo in sub_opts:
    if o == '-p':
      opt_prune = True
    if o == '-s':
      opt_simulate = True
    if o == '-y':
      opt_yes = True

  # capture source and destination arguments
  src_uri = boto.storage_uri(args[0])
  dst_uri = boto.storage_uri(args[1])

  # check file uris are directories and exist
  for uri in [src_uri, dst_uri]:
    if uri.is_file_uri():
      if not uri.names_container() or not os.path.exists(uri.object_name):
        OutputAndExit('uri must be a directory: %s' % uri)

  # append trailing slash to uri.object_name
  for uri in [src_uri, dst_uri]:
    if uri.object_name and not uri.object_name[-1] == '/':
      uri.object_name += '/'

  # create dictionaries
  print "loading source ..."
  if src_uri.is_file_uri():
    src_list = load_files(src_uri, prefix = dst_uri.object_name)
  else:
    src_list = load_objects(src_uri, prefix = dst_uri.object_name)
  print "loading destination  ..."
  if dst_uri.is_file_uri():
    dst_list = load_files(dst_uri, prefix = dst_uri.object_name)
  else:
    dst_list = load_objects(dst_uri, prefix = dst_uri.object_name)

  print "managing lists ..."
  # calculate deletes, find all objects in cloud without a corresponding local file
  deletes = dict((key, dst_list[key]) for key in dst_list.keys() if not key in src_list.keys())
  # calculate uploads: all local files
  uploads = dict((key, src_list[key]) for key in src_list.keys())
  # calculate nochange: local file and bucket key have the same checksum
  nochange = dict((key, src_list[key]) for key in src_list.keys() if key in dst_list.keys() and src_list[key].phash == dst_list[key].phash)
  # remove nochange from uploads
  uploads = dict((key, src_list[key]) for key in uploads.keys() if not key in nochange.keys())

  # summarize 
  print
  print "%s --> %s" % (src_uri, dst_uri)
  print
  if opt_prune:
    size_d = sum([v.psize for v in deletes.values()])
    print "deletes:   %5s     %s" % (len(deletes.keys()), readable_int(size_d))
  size_u = sum([v.psize for v in uploads.values()])
  print "uploads:   %5s     %s" % (len(uploads.keys()), readable_int(size_u))
  size_n = sum([v.psize for v in nochange.values()])
  print "unchanged: %5s     %s" % (len(nochange.keys()), readable_int(size_n))

  # exit now if no tasks
  if (not opt_prune or len(deletes.keys()) == 0) and (len(uploads.keys()) == 0):
    print
    print "Nothing to do!"
    return

  # prompt to continue
  if not opt_yes:
    print
    prompt = "Are you sure you want to continue?(y/N) "
    answer = raw_input(prompt).strip()
    if answer != 'y':
      print "Aborted."
      return

  print

  # calculate total to guage progress
  # uploads count as filesize
  # deletes count as 5k each
  total = size_u
  if opt_prune:
    total += len(deletes.items()) * 5120
  progress = 0

  # perform deletes, sort alphabetically
  if opt_prune:
    for key, uri in sorted(deletes.iteritems(), key=lambda x: x[1].pname):
      target_uri = dst_uri.clone_replace_name(key)
      print "[%2s%%]         deleting %s ..." % ((progress * 100 / total), target_uri)
      progress += 5120
      if not opt_simulate:
        target_uri.delete_key()

  # perform uploads, sort by filesize
  for key, uri in sorted(uploads.iteritems(), key=lambda x: x[1].psize):
    target_uri = dst_uri.clone_replace_name(key)
    print "[%2s%%][%s] uploading %s --> %s ..." % ((progress * 100 / total), readable_int(uri.psize), uri, target_uri)
    progress += uri.psize
    if not opt_simulate:
      PerformCopy(uri, target_uri)

  print "Finished."

def load_files(target, prefix = ''):
  """load files into dictionary

    key is destination path
    value is boto.storageuri
    all values contain pname, phash and psize attributes

  """
  lst = {}
  for root, unused_dirs, files in os.walk(target.object_name):
    for name in files:
      uri = boto.storage_uri(os.path.join(root, name))
      # calculate the bucket key by prepending the prefix to the file path relative to the target
      uri.pname = "%s%s" % (prefix, uri.object_name[len(target.object_name):])
      uri.phash = compute_md5(uri.get_key().fp)[0]
      uri.psize = os.stat(uri.object_name)[stat.ST_SIZE]
      lst[uri.pname] = uri
      #print "%s: %s" % (uri.pname, uri)
  return lst

def load_objects(target, prefix = ''):
  """load objects into dictionary

    key is destination path
    value is boto.s3.Key
    all values contain pname, phash and psize attributes

  """
  lst = {}
  bucket = target.get_bucket().list(prefix = target.object_name)
  offset = len(target.object_name)
  for obj in bucket:
    uri = target.clone_replace_name(obj.name)
    uri.pname = "%s%s" % (prefix, obj.name[offset:])
    uri.phash = obj.etag.strip("\"'")
    uri.psize = obj.size
    lst[uri.pname] = uri
    #print "%s: %s, %s" % (uri.pname, uri, obj)
  return lst

def readable_int(x):
  "Formats the number of bytes as kilo-, mega- or giga- bytes"

  K = 1024.0
  M = K * 1024
  G = M * 1024

  y = abs(x)
  if y == 0:
    return "    "
  elif y < 1000:
    return "%5s " % x
  elif y < K:
    return "%5s " % x
  elif y < M:
    return "%5.1fK" % float(x/K)
  elif y < G:
    return "%5.1fM" % float(x/M)
  else:
    return "%5.1fG" % float(x/G)

def compute_md5(fp):
    """
    :type fp: file
    :param fp: File pointer to the file to MD5 hash.  The file pointer will be
               reset to the beginning of the file before the method returns.
        
    :rtype: tuple
    :return: A tuple containing the hex digest version of the MD5 hash
             as the first element and the base64 encoded version of the
             plain digest as the second element.
    """
    BUFFER_SIZE = 1024
    m = md5()
    fp.seek(0)
    s = fp.read(BUFFER_SIZE)
    while s:
        m.update(s)
        s = fp.read(BUFFER_SIZE)
    hex_md5 = m.hexdigest()
    base64md5 = base64.encodestring(m.digest())
    if base64md5[-1] == '\n':
        base64md5 = base64md5[0:-1]
    fp.seek(0)
    return (hex_md5, base64md5)

def PerformCopy(src_uri, dst_uri, sub_opts = '', headers = {}):
  """Helper method for CopyObjsCommand.

  Args:
    src_uri: source StorageUri for copy.
    dst_uri: destination StorageUri for copy.
    sub_opts: command-specific options from getopt.
    headers: dictionary containing optional HTTP headers to pass to boto.
  """

  # Make a copy of the input headers each time so we can set a different
  # MIME type for each object.
  metadata = headers.copy()
  canned_acl = None
  for o, a in sub_opts:
    if o == "-a":
      canned_acls = dst_uri.canned_acls()
      if a not in canned_acls:
        OutputAndExit('Invalid canned ACL "%s".' % a)
      canned_acl = a
    elif o == "-t":
      mimetype_tuple = mimetypes.guess_type(src_uri.object_name)
      mime_type = mimetype_tuple[0]
      content_encoding = mimetype_tuple[1]
      if mime_type:
        metadata['Content-Type'] = mime_type
        print '\t[Setting Content-Type=%s]' % mime_type
      else:
        print '\t[Unknown content type -> using application/octet stream]'
      if content_encoding:
        metadata['Content-Encoding'] = content_encoding

  src_key = src_uri.get_key(False, headers)
  if not src_key:
    OutputAndExit('"%s" does not exist.' % src_uri)

  # Separately handle cases to avoid extra file and network copying of
  # potentially very large files/objects.

  if (src_uri.is_cloud_uri() and dst_uri.is_cloud_uri() and
      src_uri.provider == dst_uri.provider):
    # Object -> object, within same provider (uses x-<provider>-copy-source
    # metadata HTTP header to request copying at the server). (Note: boto
    # does not currently provide a way to pass canned_acl when copying from
    # object-to-object through x-<provider>-copy-source):
    src_bucket = src_uri.get_bucket(False, headers)
    dst_bucket = dst_uri.get_bucket(False, headers)
    dst_bucket.copy_key(dst_uri.object_name, src_bucket.name,
                        src_uri.object_name, metadata)
    return

  dst_key = dst_uri.new_key(False, headers)
  if src_uri.is_file_uri() and dst_uri.is_cloud_uri():
    # File -> object:
    fname_parts = src_uri.object_name.split('.')
    dst_key.set_contents_from_file(src_key.fp, metadata, policy=canned_acl)
  elif src_uri.is_cloud_uri() and dst_uri.is_file_uri():
    # Object -> file:
    src_key.get_file(dst_key.fp, headers)
  elif src_uri.is_file_uri() and dst_uri.is_file_uri():
    # File -> file:
    dst_key.set_contents_from_file(src_key.fp, metadata)
  else:
    # We implement cross-provider object copy through a local temp file:
    tmp = tempfile.TemporaryFile()
    src_key.get_file(tmp, headers)
    tmp.seek(0)
    dst_key.set_contents_from_file(tmp, metadata)


def main():

  # If user enters no commands just print the usage info.
  if len(sys.argv) == 1:
    OutputUsageAndExit()

  try:
    opts, args = getopt.getopt(sys.argv[1:], 'psy')
    if len(args) < 2 or len(args) > 2:
      OutputAndExit('Wrong number of arguments.')
  except getopt.GetoptError, e:
    OutputAndExit(e.msg)

  PushCommand(args, opts)

if __name__ == '__main__':
  main()
  sys.exit(0)

