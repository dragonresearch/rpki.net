#!/bin/sh -
# $Id$
#
# Copyright (C) 2009  Internet Systems Consortium ("ISC")
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

# Postprocess output of timer debug log.  I'll probably never need
# this again, but I'd rather not have to write it a second time.

awk '
  /<timer/ {
    time = $2; tag = $3; $1 = $2 = $3 = "";
    print tag, time, $0;
  }
  ' ${1-screenlog.0} |
sort |
sed '
  s===;
  /testbed\[/d;
  s= datetime([0-9, ]*)==;
  s=<bound method.*>>==;
  s=/u/sra/rpki/subvert-rpki.hactrn.net/[a-z]*/rpki/==;
  s= timedelta([0-9, ]*)==;
  s= None = =;
  s=  at = =;
  s= to from = from =
  ' |
awk '
  BEGIN {
    SUBSEP = "<";
  }
  {
    #print;
    state[$1, $5] = $3;
  }
  /Creating/ {
    created[$1, $5] = $NF;
  }
  END {
    for (i in state)
      print i, state[i], created[i];
  }
  ' |
sort
