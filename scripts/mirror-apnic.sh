#!/bin/sh -
# $Id$

cd `dirname $0`

rsync --archive --itemize-changes --compress --delete rsync://repository.apnic.net/APNIC/ repository.apnic.net/APNIC/
