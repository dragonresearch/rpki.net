#!/bin/sh -
# $Id$

set -e

uname=`/usr/bin/uname`

case "$uname" in

FreeBSD)
	cd freebsd
	. install.sh
	;;

*)
	echo 1>&2 "Don't know how to install rcynic jail on platform $uname"
	exit 1
	;;
esac
