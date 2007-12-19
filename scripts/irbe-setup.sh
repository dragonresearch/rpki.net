#!/bin/sh -
# $Id$
#
# Run irbe-setup.py, under screen if possible.

#make test

if test -n "$STY"
then
  screen python rpkid.py
else
  python rpkid.py >>rpkid.log 2>&1 & rpkid=$!
  trap "kill $rpkid" 0 1 2 3 13 15
fi

sleep 5

exec python irbe-setup.py
