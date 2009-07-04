#!/bin/sh -
# $Id$

set -x

if test -z "$STY"
then

  exec screen -L sh $0 ${1+"$@"}

else

  #screen python ../rpkid/irdbd.py
  #screen python ../rpkid/rpkid.py
  #screen python ../rpkid/pubd.py

  python ../rpkid/irdbd.py &
  python ../rpkid/rpkid.py &
  python ../rpkid/pubd.py &
  
  #if test -n "$*"; then sleep 5; "$@"; fi

  # Apparently Control-C-ing out of this kills the daemons, which is
  # what we want but was a surprise to me.  Probably SIGHUP effect due
  # to running under screen, or something like that.
  wait

fi
