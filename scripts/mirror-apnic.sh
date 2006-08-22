#!/bin/sh -
# $Id$

cd `dirname $0`

rsync -aiz --delete rsync://repository.apnic.net/APNIC/ repository.apnic.net/APNIC/
