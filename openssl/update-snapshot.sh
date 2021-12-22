#!/bin/sh -
# $Id$
#
# Fetch today's OpenSSL tarball and do everything needed to make it
# the current code other than the git commit.

#version="1.0.0-stable-SNAP-$(date +%Y%m%d)"

version="1.1.1l"

tarball="openssl-${version}.tar.gz"

case $version in
  *SNAP*) directory=snapshot;;
  *)      directory=source;;
esac

/bin/test -f "${tarball}" ||
/usr/bin/fetch -m -p " https://www.openssl.org/${directory}/${tarball}" ||
exit

/bin/rm -f openssl

for i in *.tar.gz
do
  if [ "$i" != "$tarball" ]
  then
    /bin/rm -rf "${i%.tar.gz}"
    /usr/local/bin/git rm "$i"
  fi
done

/usr/bin/awk -v version="$version" '/^VERSION = / {$NF = version} {print}' Makefile.in >Makefile.in.$$ &&
/bin/mv Makefile.in.$$ Makefile.in

/usr/local/bin/git add -v "$tarball"
/usr/local/bin/git add -v -u
