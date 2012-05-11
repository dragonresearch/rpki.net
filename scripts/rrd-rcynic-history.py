"""
Parse traffic data out of rynic XML output, whack it a bit, and stuff
it into one or more RRDs (Round Robin Databases -- see rrdtool).

Haven't decided yet whether to draw the resulting pictures here or
elsewhere.

This is an initial adaptation of analyze-rcynic-history.py, which uses
gnuplot and a shelve database.  It's also my first attempt to do
anything with rrdtool, so no doubt I'll get half of it wrong.

$Id$

Copyright (C) 2011-2012  Internet Systems Consortium ("ISC")

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

import mailbox
import sys
import urlparse
import os
import time

from xml.etree.cElementTree import (ElementTree as ElementTree,
                                    fromstring  as ElementTreeFromString)

os.putenv("TZ", "UTC")
time.tzset()

def parse_utc(s):
  return int(time.mktime(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ")))

class Host(object):
  """
  A host object represents all the data collected for one host for a given session.
  """

  def __init__(self, hostname, session_timestamp):
    self.hostname = hostname
    self.session_timestamp = session_timestamp
    self.elapsed = 0
    self.connection_count = 0
    self.dead_connections = 0
    self.uris = set()
    self.total_connection_time = 0

  def add_connection(self, elt):
    elapsed = parse_utc(elt.get("finished")) - parse_utc(elt.get("started"))
    self.connection_count      += 1
    self.elapsed               += elapsed
    self.total_connection_time += elapsed
    if elt.get("error") is not None:
      self.dead_connections    += 1

  def add_object_uri(self, u):
    self.uris.add(u)

  def finalize(self):
    self.object_count = len(self.uris)
    del self.uris

  def safe_division(self, numerator, denominator):
    if self.failed:
      return "U"
    try:
      return float(numerator) / float(denominator)
    except ZeroDivisionError:
      return "U"

  @property
  def failed(self):
    return 1 if self.dead_connections else 0

  @property
  def seconds_per_object(self):
    return self.safe_division(self.elapsed, self.object_count)

  @property
  def objects_per_connection(self):
    return self.safe_division(self.object_count, self.connection_count)

  @property
  def average_connection_time(self):
    return self.safe_division(self.total_connection_time, self.connection_count)

  def save(self, rrdtable):
    self.finalize()
    rrdtable.add(self.hostname,
                 (self.session_timestamp,
                  self.connection_count,
                  self.object_count,
                  self.objects_per_connection,
                  self.seconds_per_object,
                  self.average_connection_time,
                  self.failed))

class Session(dict):
  """
  A session corresponds to one XML file.  This is a dictionary of Host
  objects, keyed by hostname.
  """

  def __init__(self, session_timestamp):
    self.session_timestamp = session_timestamp

  @property
  def hostnames(self):
    return set(self.iterkeys())

  def add_connection(self, elt):
    hostname = urlparse.urlparse(elt.text.strip()).hostname
    if hostname not in self:
      self[hostname] = Host(hostname, self.session_timestamp)
    self[hostname].add_connection(elt)

  def add_object_uri(self, u):
    h = urlparse.urlparse(u).hostname
    if h and h in self:
      self[h].add_object_uri(u)

  def save(self, rrdtable):
    for h in self.itervalues():
      h.save(rrdtable)

class RRDTable(dict):
  """
  Final data we're going to be sending to rrdtool.  We need to buffer
  it until we're done because we have to sort it.  Might be easier
  just to sort the maildir, then again it might be easier to get rid
  of the maildir too once we're dealing with current data.  We'll see.
  """

  def add(self, hostname, data):
    if hostname not in self:
      self[hostname] = []
    self[hostname].append(data)

  def sort(self):
    for data in self.itervalues():
      data.sort()

  def save(self):
    for hostname, data in self.iteritems():
      for datum in data:
        print "rrdtool update %s.rrd %s" % (hostname, ":".join(str(d) for d in datum))

      
mb = mailbox.Maildir("/u/sra/rpki/rcynic-xml", factory = None, create = False)

rrdtable = RRDTable()

for i, key in enumerate(mb.iterkeys(), 1):
  sys.stderr.write("\r%s %d/%d..." % ("|\\-/"[i & 3], i, len(mb)))

  assert not mb[key].is_multipart()
  input = ElementTreeFromString(mb[key].get_payload())
  date = input.get("date")
  sys.stderr.write("%s..." % date)
  session = Session(parse_utc(date))
  for elt in input.findall("rsync_history"):
    session.add_connection(elt)
  for elt in input.findall("validation_status"):
    if elt.get("generation") == "current":
      session.add_object_uri(elt.text.strip())
  session.save(rrdtable)

  # XXX
  if i > 4:
    break

sys.stderr.write("\n")

print
print

rrdtable.sort()
rrdtable.save()
