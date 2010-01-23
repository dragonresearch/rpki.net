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

import sys, os

class datapoint(object):

  outtype = os.getenv("OUTTYPE", "png")
  outname = os.getenv("OUTNAME", "")
  timefmt = os.getenv("TIMEFMT", "%T")

  raw = []
  filenames = []

  def __init__(self, filename, timestamp, process, count, typesig):
    self.filename = filename
    self.timestamp = timestamp
    self.process = process
    self.count = count
    self.typesig = typesig
    self.key = "%s %s" % (filename, typesig)
    self.raw.append(self)
    if filename not in self.filenames:
      self.filenames.append(filename)

  def __cmp__(self, other):
    c = cmp(self.key, other.key)
    return c if c else cmp(self.timestamp, other.timestamp)

  @classmethod
  def plot(cls):

    changed = {}
    for i in cls.raw:
      if i.key not in changed:
        changed[i.key] = set()
      changed[i.key].add(i.count)
    changed = set(k for k, v in changed.iteritems() if len(v) > 10)

    print "set xdata time"
    print "set timefmt '%Y-%m-%dT%H:%M:%S'"
    print "set format x '%s'" % cls.timefmt
    if cls.outname:
      print "set terminal", cls.outtype
      print "set output '%s.%s'" % (cls.outname, cls.outtype)
      print "set term png size 1024,1024"
    print "plot", ", ".join("'-' using 1:2 with linespoints title '%s'" % i for i in changed)

    cls.raw.sort()

    key = None
    proc = None
    for i in cls.raw:
      if i.key not in changed:
        continue
      if key is not None and i.key != key:
        print "e"
      elif proc is not None and i.process != proc:
        print ""
      key = i.key
      proc = i.process
      print "#", i.key
      print i.timestamp, i.count
    print "e"
    if not cls.outname:
      print "pause mouse any"


for filename in sys.argv[1:]:
  for line in open(filename):
    line = line.split()
    if line[3] == "gc_summary:" and line[4].isdigit() and line[5].startswith("(") and line[-1].endswith(")"):
      datapoint(filename = filename,
                timestamp = line[0] + "T" + line[1],
                process   = line[2],
                count     = line[4],
                typesig   = " ".join(line[5:]))
 
datapoint.plot()
