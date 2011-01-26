#!/bin/sh -
# $Id$

set -e

case "$1" in

freebsd*) cd freebsd; . ./install.sh;;
darwin*)  cd darwin;  . ./install.sh;;
linux*)	  cd linux;   . ./install.sh;;

*)	echo 1>&2 "Don't know how to install rcynic jail on platform $uname"
	exit 1;;
esac
