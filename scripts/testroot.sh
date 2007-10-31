#!/bin/sh -
# $Id$
#
# Script to test against testroot.py.
#
# This blows away rpkid's database and rebuilds it with what we need
# for this test.  In the long run we must do better than this, but
# gotta start somewhere.

if test ! -r testroot.cer -o ! -r testroot.key
then
  ../openssl/openssl/apps/openssl req -new -newkey rsa:2048 -nodes -keyout testroot.key -out testroot.req -config testroot.cnf
  ../openssl/openssl/apps/openssl x509 -req -in testroot.req -out testroot.cer -extfile testroot.cnf -extensions req_x509_ext -signkey testroot.key -text -sha256
  rm -f testroot.req
fi
