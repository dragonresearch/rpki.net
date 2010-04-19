#!/bin/sh -
# $Id$

# Copyright (C) 2009-2010  Internet Systems Consortium ("ISC")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.
 
set -x

export TZ=UTC MYRPKI_RNG=`pwd`/myrpki.rng

test -z "$STY"  && exec screen -L sh $0

screen -X split
screen -X focus

for i in ../rpkid/smoketest.*.yaml
do
  rm -rf test
  python sql-cleaner.py 
  screen python yamltest.py -p yamltest.pid $i
  date
  sleep 180
  for j in . . . . . . . . . .
  do
    sleep 30
    date
    ../rcynic/rcynic
    ../rcynic/show.sh
    date
  done
  test -r yamltest.pid && kill -INT `cat yamltest.pid`
  sleep 30
  make backup
done
