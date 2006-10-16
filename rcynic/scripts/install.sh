#!/bin/sh -
# $Id$

set -e

uname=`/usr/bin/uname`

case "$uname" in

FreeBSD)
	cd freebsd
	/bin/sh setup-jail.sh
	cd ..
	echo "Installing rcynic..."
	/usr/bin/install -m 555 -o root -g wheel -p ../rcynic /var/rcynic/bin/rcynic
	;;

*)
	echo 1>&2 "Don't know how to install rcynic jail on platform $uname"
	exit 1
	;;
esac
