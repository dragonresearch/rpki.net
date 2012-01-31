"""
Parse traffic data out of rynic XML output, whack it a bit, print some
summaries and run gnuplot to draw some pictures.

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

show_plot      = True
plot_all_hosts = False
plot_to_one    = True
plot_to_many   = True

import mailbox, sys, urlparse, os, getopt, datetime, subprocess

from xml.etree.cElementTree import (ElementTree as ElementTree,
                                    fromstring  as ElementTreeFromString)

def parse_utc(s):
  return datetime.datetime.strptime(s,  "%Y-%m-%dT%H:%M:%SZ")

class Rsync_History(object):
  """
  An Rsync_History object represents one rsync connection.
  """

  def __init__(self, elt):
    self.error = elt.get("error")
    self.uri = elt.text.strip()
    self.hostname = urlparse.urlparse(self.uri).hostname or None
    self.elapsed = parse_utc(elt.get("finished")) - parse_utc(elt.get("started"))

class Host(object):
  """
  A host object represents all the data collected for one host.  Note
  that it (usually) contains a list of all the sessions in which this
  host appears.

  This is probably keeping far too much data, and needs to be pruned
  to keep memory consumption to something sane.
  """

  def __init__(self, hostname, session_id):
    self.hostname = hostname
    self.session_id = session_id
    self.elapsed = datetime.timedelta(0)
    self.connection_count = 0
    self.dead_connections = 0
    self.uris = set()
    self.total_connection_time = datetime.timedelta(0)

  def add_rsync_history(self, h):
    self.connection_count      += 1
    self.elapsed               += h.elapsed
    self.dead_connections      += int(h.error is not None)
    self.total_connection_time += h.elapsed

  def add_uri(self, u):
    self.uris.add(u)

  def finalize(self):
    self.object_count = len(self.uris)
    del self.uris

  @property
  def failure_rate_percentage(self):
    return float(self.dead_connections * 100) / float(self.connection_count)

  @property
  def seconds_per_object(self):
    return float(self.elapsed.total_seconds()) / float(self.object_count)

  @property
  def objects_per_connection(self):
    return float(self.object_count) / float(self.connection_count)

  @property
  def average_connection_time(self):
    return float(self.total_connection_time.total_seconds()) / float(self.connection_count)

  class Format(object):

    def __init__(self, attr, title, fmt):
      self.attr = attr
      self.title = title
      self.width = len(title) - int("%" in fmt)
      self.fmt = "%%%d%s" % (self.width, fmt)
      self.oops = "*" * self.width

    def __call__(self, obj):
      try:
        return self.fmt % getattr(obj, self.attr)
      except ZeroDivisionError:
        return self.oops

  format = (Format("connection_count",        "Connections",        "d"),
            Format("object_count",            "Objects",            "d"),
            Format("objects_per_connection",  "Objects/Connection", ".3f"),
            Format("seconds_per_object",      "Seconds/Object",     ".3f"),
            Format("failure_rate_percentage", "Failure Rate",       ".3f%%"),
            Format("average_connection_time", "Average Connection", ".3f"),
            Format("hostname",                "Hostname",           "s"))

  separator = " " * 2

  header = separator.join(fmt.title for fmt in format)

  def __str__(self):
    return self.separator.join(fmt(self) for fmt in self.format)

  format_dict = dict((fmt.attr, fmt) for fmt in format)

  def format_field(self, name):
    return self.format_dict[name](self).strip()

class Session(dict):
  """
  A session corresponds to one XML file.  This is a dictionary of Host
  objects, keyed by hostname.

  We might need some kind of .finalize() method which throws away
  unnecessary data to keep memory consumption down after we've read
  the whole session.  Most likely this would just be a pass through to
  a Host.finalize() method which would do the real work.
  """

  def __init__(self, session_id = None):
    self.session_id = session_id

  @property
  def hostnames(self):
    return set(self.iterkeys())

  def get_plot_row(self, name, hostnames):
    return (self.session_id,) + tuple(self[h].format_field(name) if h in self else "" for h in hostnames)

  def add_rsync_history(self, h):
    if h.hostname not in self:
      self[h.hostname] = Host(h.hostname, self.session_id)
    self[h.hostname].add_rsync_history(h)

  def add_uri(self, u):
    h = urlparse.urlparse(u).hostname
    if h and h in self:
      self[h].add_uri(u)

  def finalize(self):
    for h in self.itervalues():
      h.finalize()

mb = mailbox.Maildir("/u/sra/rpki/rcynic-xml", factory = None, create = False)

sessions = []

for i, msg in enumerate(mb.itervalues()):

  sys.stderr.write("\r%s %d/%d..." % ("|\\-/"[i & 3], i, len(mb)))

  assert not msg.is_multipart()

  input = ElementTreeFromString(msg.get_payload())

  session = Session(input.get("date"))
  sessions.append(session)

  for elt in input.findall("rsync_history"):
    session.add_rsync_history(Rsync_History(elt))

  for elt in input.findall("validation_status"):
    if elt.get("generation") == "current":
      session.add_uri(elt.text.strip())

  session.finalize()

sys.stderr.write("\n")

def plotter(f, hostnames, field, logscale = False):
  plotlines = sorted(session.get_plot_row(field, hostnames) for session in sessions)
  title = Host.format_dict[field].title
  n = len(hostnames) + 1
  assert all(n == len(plotline) for plotline in plotlines)
  if "%%" in Host.format_dict[field].fmt:
    f.write('set format y "%.0f%%"\n')
  else:
    f.write('set format y\n')
  if logscale:
    f.write("set logscale y\n")
  else:
    f.write("unset logscale y\n")
  f.write("""
          set xdata time
          set timefmt '%Y-%m-%dT%H:%M:%SZ'
          #set format x '%m/%d'
          set format x '%b%d'
          #set title '""" + title + """'
          plot""" + ",".join(" '-' using 1:2 with lines title '%s'" % h for h in hostnames) + "\n")
  for i in xrange(1, n):
    for plotline in plotlines:
      f.write("%s %s\n" % (plotline[0], plotline[i].rstrip("%")))
    f.write("e\n")

def plot_many(hostnames, fields):
  for field in fields:
    for logscale in (False, True):
      gnuplot = subprocess.Popen(("gnuplot",), stdin = subprocess.PIPE)
      gnuplot.stdin.write("set terminal pdf\n")
      gnuplot.stdin.write("set output '%s-%s.pdf'\n" % (field, "log" if logscale else "linear"))
      plotter(gnuplot.stdin, hostnames, field, logscale = logscale)
      gnuplot.stdin.close()
      gnuplot.wait()

def plot_one(hostnames, fields):
  gnuplot = subprocess.Popen(("gnuplot",), stdin = subprocess.PIPE)
  gnuplot.stdin.write("set terminal pdf\n")
  gnuplot.stdin.write("set output 'analyze-rcynic-history.pdf'\n")
  for field  in fields:
    if field != "hostname":
      plotter(gnuplot.stdin, hostnames, field, logscale = False)
      plotter(gnuplot.stdin, hostnames, field, logscale = True)
  gnuplot.stdin.close()
  gnuplot.wait()

if show_plot:

  if plot_all_hosts:
    hostnames = set()
    for session in sessions:
      hostnames.update(session.hostnames)
    hostnames = sorted(hostnames)

  else:
    hostnames = ("rpki.apnic.net", "rpki.ripe.net", "repository.lacnic.net",
                 "rpki.afrinic.net", "arin.rpki.net", "rgnet.rpki.net")

  fields = [fmt.attr for fmt in Host.format if fmt.attr != "hostname"]
  if plot_to_one:
    plot_one(hostnames, fields)
  if plot_to_many:
    plot_many(hostnames, fields)
