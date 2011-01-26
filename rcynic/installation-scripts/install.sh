#!/bin/sh -
# $Id$

set -e

case "${host_os}" in

freebsd*) cd freebsd; . ./install.sh;;
darwin*)  cd darwin;  . ./install.sh;;
linux*)	  cd linux;   . ./install.sh;;

*)	echo 1>&2 "Don't know how to install rcynic jail on platform ${host_os}"
	exit 1;;
esac
