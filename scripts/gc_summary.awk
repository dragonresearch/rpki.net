#!/usr/bin/awk -f

# $Id$
# 
# Copyright (C) 2010  Internet Systems Consortium ("ISC")
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

# Use gnuplot to graph interesting data from gc_summary lines in rpkid logs.

BEGIN {
  target  = ENVIRON["TARGET"]  ? ENVIRON["TARGET"]  : "tuple";
  outtype = ENVIRON["OUTTYPE"] ? ENVIRON["OUTTYPE"] : "png";
  outname = ENVIRON["OUTNAME"] ? ENVIRON["OUTNAME"] : "";
  print "set xdata time";
  print "set timefmt '%Y-%m-%dT%H:%M:%S'";
  #print "set format x '%d%b'";
  print "set format x '%T'";
  print "set key right bottom";
  if (outname) {
    print "set terminal", outtype;
    print "set output '" outname "." outtype "'";
    print "set term png size 1024,1024";
  }
  if (ARGC <= 2) {
    print "plot '-' using 1:2 with linespoints title 'rpkid use of", target, "objects'";
  } else {
    cmd = "plot '-' using 1:2 with linespoints title '" ARGV[1] "'";
    for (i = 2; i < ARGC; i++)
      cmd = cmd ", '-' using 1:2 with linespoints title '" ARGV[i] "'";
    print cmd;
  }
}

FILENAME != filename && filename {
  print "e";
}

FILENAME != filename {
  print "#", FILENAME
  filename = FILENAME;
  proc = "";
}

$6 == target && proc != $3 && proc {
  print "";
}  

$6 == target && proc != $3 {
  proc = $3;
}  

$6 == target {
  print "#", $0;
  print $1 "T" $2, $5;
}

END {
  print "e";
  if (!outname)
    print "pause mouse any";
}
