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

  def __init__(self, hostname, timestamp):
    self.hostname = hostname
    self.timestamp = timestamp
    self.elapsed = 0
    self.connections = 0
    self.failures = 0
    self.uris = set()

  def add_connection(self, elt):
    self.elapsed += parse_utc(elt.get("finished")) - parse_utc(elt.get("started"))
    self.connections += 1
    if elt.get("error") is not None:
      self.failures += 1

  def add_object_uri(self, u):
    self.uris.add(u)

  @property
  def failed(self):
    return 1 if self.failures > 0 else 0

  @property
  def objects(self):
    return len(self.uris)

  field_table = (("timestamp",          None,           None,                   None),
                 ("connections",        "GAUGE",        "Connections",          "FF0000"),
                 ("objects",            "GAUGE",        "Objects",              "00FF00"),
                 ("elapsed",            "GAGUE",        "Fetch Time",           "0000FF"),
                 ("failed",             "ABSOLUTE",     "Failed",               "00FFFF"))

  @property
  def field_values(self):
    return tuple(str(getattr(self, field[0])) for field in self.field_table)

  @classmethod
  def field_ds_specifiers(cls, heartbeat = 24 * 60 * 60, minimum = 0, maximum = "U"):
    return ["DS:%s:%s:%s:%s:%s" % (field[0], field[1], heartbeat, minimum, maximum)
            for field in cls.field_table if field[1] is not None]

  @classmethod
  def field_graph_specifiers(cls, hostname):
    result = []
    for field in cls.field_table:
      if field[1] is not None:
        result.append("DEF:%s=%s.rrd:%s:AVERAGE" % (field[0], hostname, field[0]))
        result.append("'LINE1:%s#%s:%s'" % (field[0], field[3], field[2]))
    return result

  def save(self, rrdtable):
    rrdtable.add(self.hostname, self.field_values)

class Session(dict):
  """
  A session corresponds to one XML file.  This is a dictionary of Host
  objects, keyed by hostname.
  """

  def __init__(self, timestamp):
    self.timestamp = timestamp

  @property
  def hostnames(self):
    return set(self.iterkeys())

  def add_connection(self, elt):
    hostname = urlparse.urlparse(elt.text.strip()).hostname
    if hostname not in self:
      self[hostname] = Host(hostname, self.timestamp)
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

  @property
  def oldest(self):
    return min(min(datum[0] for datum in data) for data in self.itervalues())

  rras = tuple("RRA:AVERAGE:0.5:%s:9600" % steps for steps in (1, 4, 24))

  def create(self):
    start = self.oldest
    ds_list = Host.field_ds_specifiers()
    ds_list.extend(self.rras)
    for hostname in self:
      print "rrdtool create %s.rrd --start %s --step 3600 %s" % (hostname, start, " ".join(ds_list))

  def update(self):
    for hostname, data in self.iteritems():
      for datum in data:
        print "rrdtool update %s.rrd %s" % (hostname, ":".join(str(d) for d in datum))

  def graph(self):
    for hostname in self:
      print "rrdtool graph %s.png --start -90d %s" % (hostname, " ".join(Host.field_graph_specifiers(hostname)))

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
  #if i > 4: break

sys.stderr.write("\n")

print
print

rrdtable.create()
rrdtable.sort()
rrdtable.update()
rrdtable.graph()
