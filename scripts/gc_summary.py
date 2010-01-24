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

import sys, os, time

class datapoint(object):

  outtype = os.getenv("OUTTYPE", "png")
  outname = os.getenv("OUTNAME", "")
  timefmt = os.getenv("TIMEFMT", "%T")
  pretend = os.getenv("PRETEND_EVERYTHING_CHANGED", False)
  threshold = int(os.getenv("THRESHOLD", "100"))

  raw = []
  filenames = []

  def __init__(self, filename, timestamp, process, count, typesig, line):
    self.filename = filename
    self.timestamp = timestamp
    self.process = process
    self.count = count
    self.typesig = typesig
    self.line = line
    self.key = "%s %s" % (filename, typesig)
    self.raw.append(self)
    if filename not in self.filenames:
      self.filenames.append(filename)

  def __cmp__(self, other):
    c = cmp(self.key, other.key)
    return c if c else cmp(self.timestamp, other.timestamp)

  @classmethod
  def plot(cls):

    print "# [%s] Looking for interesting records" % time.strftime("%T")
    changed = {}
    for i in cls.raw:
      if i.key not in changed:
        changed[i.key] = set()
      changed[i.key].add(i.count)
    if cls.pretend:
      changed = set(changed.iterkeys())
    else:
      changed = set(k for k, v in changed.iteritems() if max(v) - min(v) > cls.threshold)

    if not changed:
      print "# [%s] Apparently nothing worth reporting" % time.strftime("%T")
      print "print 'Nothing to plot'"
      return

    print "# [%s] Header" % time.strftime("%T")
    print "set xdata time"
    print "set timefmt '%Y-%m-%dT%H:%M:%S'"
    print "set format x '%s'" % cls.timefmt
    if cls.outname:
      print "set terminal", cls.outtype
      print "set output '%s.%s'" % (cls.outname, cls.outtype)
      print "set term png size 1024,1024"
    print "plot", ", ".join("'-' using 1:2 with linespoints title '%s'" % i for i in changed)

    print "# [%s] Sorting" % time.strftime("%T")
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
      print "#", i.key, i.line
      print i.timestamp, i.count
    print "e"
    if not cls.outname:
      print "pause mouse any"

for filename in sys.argv[1:]:
  print "# [%s] Reading %s" % (time.strftime("%T"), filename)
  for line in open(filename):
    if "gc_summary:" in line:
      word = line.split(None, 6)
      if word[4].isdigit() and word[5].startswith("(") and word[5].endswith(")"):
        datapoint(filename = filename,
                  timestamp = word[0] + "T" + word[1],
                  process   = word[2],
                  count     = int(word[4]),
                  typesig   = word[5],
                  line      = line.strip())
 
print "# [%s] Plotting" % time.strftime("%T")
datapoint.plot()
