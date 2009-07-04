#!/bin/sh -
# $Id$

set -x

if test -z "$STY"
then

  exec screen -L sh $0 ${1+"$@"}

else

  screen python ../rpkid/irdbd.py
  screen python ../rpkid/rpkid.py
  screen python ../rpkid/pubd.py

  #if test -n "$*"; then sleep 5; "$@"; fi

fi
