# s3push
****
A simple command-line utility to perform a smart copy of local files to and from Amazon S3 as well as Google Storage.

## Features
 - Source files are only transferred if they differ from files at the destination; diff via MD5 checksum.
 - A summary containing the file count and byte count of files to be transferred is presented before copying begins.
 - The total percent complete is shown after every file transfer.
 - Files to be deleted are sorted alphabetically.
 - Files to be transferred are sorted by size, the smallest first. 

## Syntax
		s3push [-p] [-s] [-y] src_uri dst_uri
### Options
		-p : prune.     Delete objects at dst_uri that do not exist at src_uri.
		-s : simulate.  Simulate actions but do not actually perform them.
		-y : yes.       Bypass confirmation prompt, assuming yes.
### Arguments
                src_uri         The source of files to transfer to the destination.
                dst_uri         The destination URI.
                                Note:  URIs may be any valid storage URI supported by the underlying boto library.
### Examples
                s3push . s3://bucket
                Push the contents of the current directory to the S3 bucket named "bucket".

                s3push . s3://bucket/prefix1
                Push the contents of the current directory to the S3 bucket named "bucket", prefixing all objects with "prefix1".
                Note that a trailing slash will be automatically appended if missing.

                s3push s3://bucket .
                Push the contents of the S3 bucket back down the the current directory.

                s3push s3://bucket gs://bucket
                Push the contents of the S3 bucket "bucket" the a bucket of the same name at Google Storage.

## Roadmap
 - add progress bar for individual files
 - cache md5 calculation of local files between runs

