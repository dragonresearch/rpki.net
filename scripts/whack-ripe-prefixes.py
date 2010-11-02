"""
Fix problems in prefixes.csv generated from RIPE's database.

RIPE's database contains inconsistancies, overlaps, and format errors
that make it impossible to feed the output of ripe-to-csv.awk directly
into testbed-rootcert.py without OpenSSL rejecting the resulting
root.conf.  This script takes a brute force approach to fixing this:
it converts all prefixes and address ranges into pairs of unsigned
decimal integers representing range min and range max, runs the
resulting 3+ million entry file through the unix sort program to put
the data into canonical order, then reads it back, merging overlaps
and converting everything back to ranges of IP addresses, and writing
the result in a form acceptable to testbed-rootcert.py.

Since we're doing all this anyway, the script also merges adjacent
address blocks, not because OpenSSL can't handle them (it can) but
because doing so cuts out a lot of unnecessary I/O.

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

import sys, subprocess, rpki.ipaddrs

sorter = subprocess.Popen(("sort", "-T.", "-n"),
                          stdin = subprocess.PIPE,
                          stdout = subprocess.PIPE)

for line in open("../rpki.testbed/ripe/prefixes.csv"):
  handle, prefix = line.split()

  if "-" in prefix:
    range_min, range_max = prefix.split("-")
    range_min = rpki.ipaddrs.parse(range_min)
    range_max = rpki.ipaddrs.parse(range_max)

  else:
    address, length = prefix.split("/")
    address = rpki.ipaddrs.parse(address)
    mask = (1L << (address.bits - int(length))) - 1
    range_min = address & ~mask
    range_max = address |  mask

  sorter.stdin.write("%d %d\n" % (long(range_min), long(range_max)))

sorter.stdin.close()

prev_min = None
prev_max = None

def address(number):
  if number > 0xffffffff:
    return rpki.ipaddrs.v6addr(number)
  else:
    return rpki.ipaddrs.v4addr(number)

def show():
  if prev_min and prev_max:
    sys.stdout.write("x\t%s-%s\n" % (address(prev_min), address(prev_max)))

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
