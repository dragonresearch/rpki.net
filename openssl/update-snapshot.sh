#!/bin/sh -
# $Id$
#
# Fetch today's OpenSSL snapshot and do everything needed to make it
# the current code other than the svn commit.

version="1.0.0-stable-SNAP-$(date +%Y%m%d)"

tarball="openssl-${version}.tar.gz"

/usr/bin/fetch -m -p "ftp://ftp.openssl.org/snapshot/${tarball}" || exit

/bin/rm -f openssl

for i in *.tar.gz
do
  if [ "$i" != "$tarball" ]
  then
    /bin/rm -rf "${i%.tar.gz}"
    /usr/local/bin/svn rm "$i"
  fi
done

/usr/bin/awk -v version="$version" '/^VERSION = / {$NF = version} {print}' Makefile >Makefile.$$ &&
/bin/mv Makefile.$$ Makefile

/usr/local/bin/svn add "$tarball"
