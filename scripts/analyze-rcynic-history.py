"""
Parse traffic data out of rynic XML output, whack it a bit, print some
summaries and run gnuplot to draw some pictures.

$Id$

Copyright (C) 2011  Internet Systems Consortium ("ISC")

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

show_summary   = True
show_sessions  = True
show_plot      = True
plot_all_hosts = False

import mailbox, sys, urlparse, os, getopt, datetime, subprocess

from xml.etree.cElementTree import (ElementTree as ElementTree,
                                    fromstring  as ElementTreeFromString)

class Rsync_History(object):

  timestamp_format = "%Y-%m-%dT%H:%M:%SZ"

  def __init__(self, elt):
    self.started  = datetime.datetime.strptime(elt.get("started"),  self.timestamp_format)
    self.finished = datetime.datetime.strptime(elt.get("finished"), self.timestamp_format)
    self.error = elt.get("error")
    self.uri = elt.text.strip()
    self.hostname = urlparse.urlparse(self.uri).hostname or None
    self.elapsed = self.finished - self.started

  def __cmp__(self, other):
    return (cmp(self.started,  other.started) or
            cmp(self.finished, other.finished) or
            cmp(self.hostname, other.hostname))

class Host(object):

  def __init__(self, hostname, session_id = None):
    self.hostname = hostname
    self.session_ids = []
    if session_id is not None:
      self.session_ids.append(session_id)
    self.elapsed = datetime.timedelta(0)
    self.connection_count = 0
    self.dead_connections = 0
    self.uris = set()

  def __add__(self, other):
    assert self.hostname == other.hostname
    result = self.__class__(self.hostname)
    for a in ("elapsed", "connection_count", "dead_connections", "session_ids"):
      setattr(result, a, getattr(self, a) + getattr(other, a))
    result.uris = self.uris | other.uris
    return result

  def add_rsync_history(self, h):
    self.connection_count += 1
    self.elapsed += h.elapsed
    self.dead_connections += int(h.error is not None)

  def add_uri(self, u):
    self.uris.add(u)

  @property
  def session_id(self):
    assert len(self.session_ids) == 1
    return self.session_ids[0]

  @property
  def session_count(self):
    return len(self.session_ids)

  @property
  def object_count(self):
    return len(self.uris)

  @property
  def failure_rate_percentage(self):
    return float(self.dead_connections * 100) / float(self.connection_count)

  @property
  def seconds_per_object(self):
    return (float((self.elapsed.days * 24 * 3600 + self.elapsed.seconds) * 10**6 +
                  self.elapsed.microseconds) /
            float(self.object_count * self.session_count * 10**6))

  @property
  def objects_per_connection(self):
    return (float(self.object_count * self.session_count) /
            float(self.connection_count))

  @property
  def scaled_connections(self):
    return float(self.connection_count) / float(self.session_count)

  @property
  def scaled_elapsed(self):
    return self.elapsed / self.session_count

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

  format = (Format("scaled_elapsed",          "Rsync Time",         ".10s"),
            Format("scaled_connections",      "Connections",        "d"),
            Format("object_count",            "Objects",            "d"),
            Format("objects_per_connection",  "Objects/Connection", ".3f"),
            Format("seconds_per_object",      "Seconds/Object",     ".3f"),
            Format("failure_rate_percentage", "Failure Rate",       ".3f%%"),
            Format("hostname",                "Hostname",           "s"))

  separator = " " * 2

  header = separator.join(fmt.title for fmt in format)

  def __str__(self):
    return self.separator.join(fmt(self) for fmt in self.format)

  format_dict = dict((fmt.attr, fmt) for fmt in format)

  def format_field(self, name):
    return self.format_dict[name](self).strip()

class Session(dict):

  def __init__(self, session_id = None):
    self.session_id = session_id

  @property
  def hostnames(self):
    return set(self.iterkeys())

  def get_plot_row(self, name, hostnames):
    return (self.session_id,) + tuple(self[h].format_field(name) if h in self else "" for h in hostnames)

  def __add__(self, other):
    result = self.__class__()
    for h in self.hostnames | other.hostnames:
      if h in self and h in other:
        result[h] = self[h] + other[h]
      elif h in self:
        result[h] = self[h]
      else:
        result[h] = other[h]
    return result

  def add_rsync_history(self, h):
    if h.hostname not in self:
      self[h.hostname] = Host(h.hostname, self.session_id)
    self[h.hostname].add_rsync_history(h)

  def add_uri(self, u):
    h = urlparse.urlparse(u).hostname
    if h and h in self:
      self[h].add_uri(u)

  def dump(self, title, f = sys.stdout):
    f.write("\n" + title + "\n" + Host.header + "\n")
    for h in sorted(self):
      f.write(str(self[h]) + "\n")

mb = mailbox.Maildir("/u/sra/rpki/rcynic-xml", factory = None, create = False)

sessions = []

for msg in mb.itervalues():

  sys.stderr.write(".")

  assert not msg.is_multipart()

  input = ElementTreeFromString(msg.get_payload())

  session = Session(input.get("date"))
  sessions.append(session)

  for elt in input.findall("rsync_history"):
    session.add_rsync_history(Rsync_History(elt))

  for elt in input.findall("validation_status"):
    if elt.get("generation") == "current":
      session.add_uri(elt.text.strip())

sys.stderr.write("\n")

summary = sum(sessions, Session())

if show_summary:
  summary.dump("Summary (%d sessions)" % len(sessions))

if show_sessions:
  for i, session in enumerate(sessions, 1):
    session.dump("Session #%d (%s)" % (i, session.session_id))

def plotter(f, hostnames, field, logscale = False):
  plotlines = sorted(session.get_plot_row(field, hostnames) for session in sessions)
  title = Host.format_dict[field].title
  n = len(hostnames) + 1
  assert all(n == len(plotline) for plotline in plotlines)
  if "%%" in Host.format_dict[field].fmt:
    f.write('set format y "%.0f%%"\n')
  if logscale:
    f.write("set logscale y\n")
  else:
    f.write("unset logscale y\n")
  f.write("""
          set xdata time
          set timefmt '%Y-%m-%dT%H:%M:%SZ'
          #set format x '%H:%M:%S'
          #set format x '%m-%d'
          #set format x '%a%H'
          #set format x '%H:%M'
          #set format x '%a%H:%M'
          set format x "%a\\n%H:%M"
          set title '""" + title + """'
          plot""" + ",".join(" '-' using 1:2 with lines title '%s'" % h for h in hostnames) + "\n")
  for i in xrange(1, n):
    for plotline in plotlines:
      f.write("%s %s\n" % (plotline[0], plotline[i].rstrip("%")))
    f.write("e\n")

if show_plot:
  if plot_all_hosts:
    hostnames = tuple(sorted(summary.hostnames))
  else:
    hostnames = ("rpki.apnic.net", "rpki.ripe.net", "repository.lacnic.net", "rpki.afrinic.net",
                 "arin.rpki.net", "rgnet.rpki.net",
                 "rpki.surfnet.nl", "rpki.antd.nist.gov")
  gnuplot = subprocess.Popen(("gnuplot",), stdin = subprocess.PIPE)
  gnuplot.stdin.write("set terminal pdf; set output 'analyze-rcynic-history.pdf'\n")
  for fmt in Host.format:
    if fmt.attr not in ("scaled_elapsed", "hostname"):
      plotter(gnuplot.stdin, hostnames, fmt.attr, logscale = False)
      plotter(gnuplot.stdin, hostnames, fmt.attr, logscale = True)
  gnuplot.stdin.close()
  gnuplot.wait()
