"""
Fix problems in asns.csv generated from RIPE's database.

RIPE's database contains inconsistancies, overlaps, and format errors
that make it impossible to feed the output of ripe-to-csv.awk directly
into testbed-rootcert.py without OpenSSL rejecting the resulting
root.conf.  This script takes a brute force approach to fixing this:
it converts all ASNs to range form, runs the resulting file through
the unix sort program to put the data into canonical order, then reads
it back, merging overlaps, and writing the result in a form acceptable
to testbed-rootcert.py.

Since we're doing all this anyway, the script also merges adjacent
blocks.

Ordinarily, it would be dangerous to have the same program act as both
the source and sink of a pipeline, particularly for such a large data
set, as the chance of deadlock would approach 100%, but in this case
we know that the sort program must consume and buffer (somehow) all of
its input before writing a single line of output, so a single script
can safely act as a filter both before and after sort.

$Id$

Copyright (C) 2010  Internet Systems Consortium ("ISC")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import sys, subprocess

sorter = subprocess.Popen(("sort", "-T.", "-n"),
                          stdin = subprocess.PIPE,
                          stdout = subprocess.PIPE)

for line in sys.stdin:
  handle, asn = line.split()

  if "-" in asn:
    range_min, range_max = asn.split("-")
  else:
    range_min, range_max = asn, asn

  sorter.stdin.write("%d %d\n" % (long(range_min), long(range_max)))

sorter.stdin.close()

prev_min = None
prev_max = None

def show():
  if prev_min and prev_max:
    sys.stdout.write("x\t%s-%s\n" % (prev_min, prev_max))

for line in sorter.stdout:
  this_min, this_max = line.split()
  this_min = long(this_min)
  this_max = long(this_max)

  if prev_min and prev_max and prev_max + 1 >= this_min:
    prev_min = min(prev_min, this_min)
    prev_max = max(prev_max, this_max)

  else:
    show()
    prev_min = this_min
    prev_max = this_max

show()

sorter.stdout.close()

sys.exit(sorter.wait())
