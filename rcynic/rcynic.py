"""
Render rcynic's XML output to very basic (X)HTML.  This is a Python
reimplementation of rcynic.xsl, which had gotten too slow and complex.

$Id$

Copyright (C) 2010-2012 Internet Systems Consortium, Inc. ("ISC")

Permission to use, copy, modify, and/or distribute this software for any
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

import sys
import urlparse
import os
import getopt
import time
import subprocess
import copy

try:
  from lxml.etree            import (ElementTree, Element, SubElement, Comment)
except ImportError:
  from xml.etree.ElementTree import (ElementTree, Element, SubElement, Comment)

session = None

opt = {
  "refresh"                     : 1800,
  "suppress-zero-columns"       : True,
  "use-colors"                  : True,
  "show-detailed-status"        : True,
  "show-problems"               : False,
  "show-summary"                : True,
  "show-timestamps"             : True,
  "show-graphs"                 : False,
  "suppress-backup-whining"     : True,
  "one-file-per-section"        : False,
  "rrdtool-binary"              : "rrdtool" }

def usage(msg = 0):
  f = sys.stderr if msg else sys.stdout
  f.write("Usage: %s %s [options] [input_file [output_file_or_directory]]\n" % (sys.executable, sys.argv[0]))
  f.write("Options:\n")
  for i in sorted(opt):
    if "_" not in i and not isinstance(opt[i], bool):
      f.write("   --%-30s (%s)\n" % (i + " <value>", opt[i]))
  for i in sorted(opt):
    if "_" not in i and isinstance(opt[i], bool):
      f.write("   --[no-]%-25s (--%s%s)\n" % (i, "" if opt[i] else "no-", i))
  if msg:
    f.write("\n")
  sys.exit(msg)

def parse_options():

  opts = ["help"]
  for i in opt:
    if isinstance(opt[i], bool):
      opts.append(i)
      opts.append("no-" + i)
    else:
      opts.append(i + "=")

  try:
    opts, argv = getopt.getopt(sys.argv[1:], "h?", opts)
    for o, a in opts:
      if o in ("-?", "-h", "--help"):
        usage(0)
      negated = o.startswith("--no-")
      o = o[5:] if negated else o[2:]
      if isinstance(opt[o], bool):
        opt[o] = not negated
      elif isinstance(opt[o], int):
        opt[o] = int(a)
      else:
        opt[o] = a
  except Exception, e:
    usage("%s: %s" % (e.__class__.__name__, str(e)))

  opt["input_file"] = argv[0] if len(argv) > 0 and argv[0] != "-" else None
  output_foo = argv[1] if len(argv) > 1 and argv[1] != "-" else None

  if len(argv) > 2:
    usage("Unexpected arguments")

  opt["output_directory"] = opt["output_file"] = None

  if opt["one-file-per-section"] or opt["show-graphs"]:
    opt["output_directory"] = output_foo
  else:
    opt["output_file"] = output_foo

  if opt["one-file-per-section"] or opt["show-graphs"]:
    if opt["output_directory"] is None:
      usage("--show-graphs and --one-file-per-section require an output directory")
    if not os.path.isdir(opt["output_directory"]):
      os.makedirs(opt["output_directory"])

def parse_utc(s):
  return int(time.mktime(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ")))

class Label(object):

  def __init__(self, elt):
    self.code = elt.tag
    self.mood = elt.get("kind")
    self.text = elt.text.strip()
    self.count = 0

  def get_count(self):
    return self.count

class Validation_Status(object):

  def __init__(self, elt, label_map):
    self.uri = elt.text.strip()
    self.timestamp = elt.get("timestamp")
    self.generation = elt.get("generation")
    self.hostname = urlparse.urlparse(self.uri).hostname or None
    self.fn2 = os.path.splitext(self.uri)[1] or None if self.generation else None
    self.label = label_map[elt.get("status")]

  @property
  def code(self):
    return self.label.code

  @property
  def mood(self):
    return self.label.mood

  @property
  def accepted(self):
    return self.label.code == "object_accepted"

  @property
  def rejected(self):
    return self.label.code == "object_rejected"

  @property
  def is_current(self):
    return self.generation == "current"

  @property
  def is_backup(self):
    return self.generation == "backup"
  

class Host(object):

  def __init__(self):
    self.elapsed = 0
    self.connections = 0
    self.failures = 0
    self.uris = set()
    self.graph = None
    self.counters = {}
    self.totals = {}

  def add_connection(self, elt):
    self.elapsed += parse_utc(elt.get("finished")) - parse_utc(elt.get("started"))
    self.connections += 1
    if elt.get("error") is not None:
      self.failures += 1

  def add_validation_status(self, v):
    if v.generation == "current":
      self.uris.add(v.uri)
    self.counters[(v.fn2, v.generation, v.label)] = self.get_counter(v.fn2, v.generation, v.label) + 1
    self.totals[v.label] = self.get_total(v.label) + 1
    v.label.count += 1

  def get_counter(self, fn2, generation, label):
    return self.counters.get((fn2, generation, label), 0)

  def get_total(self, label):
    return self.totals.get(label, 0)

  @property
  def failed(self):
    return 1 if self.failures > 0 else 0

  @property
  def objects(self):
    return len(self.uris)

  field_table = (("connections", "GAUGE"),
                 ("objects",     "GAUGE"),
                 ("elapsed",     "GAUGE"),
                 ("failed",      "ABSOLUTE"))

  @classmethod
  def field_ds_specifiers(cls, heartbeat = 24 * 60 * 60, minimum = 0, maximum = "U"):
    return ["DS:%s:%s:%s:%s:%s" % (field[0], field[1], heartbeat, minimum, maximum)
            for field in cls.field_table]

  @property
  def field_values(self):
    return tuple(str(getattr(self, field[0])) for field in self.field_table)

  @classmethod
  def field_defs(cls, filebase):
    return ["DEF:%s=%s.rrd:%s:AVERAGE" % (field[0], filebase, field[0])
            for field in cls.field_table]

  def save_graph_maybe(self, elt):
    if self.graph is None:
      self.graph = copy.copy(elt)

class Session(object):

  def __init__(self):
    self.hosts = {}

    if opt["input_file"] is None:
      self.root = ElementTree(file = sys.stdin).getroot()
    else:
      self.root = ElementTree(file = opt["input_file"]).getroot()

    self.rcynic_version = self.root.get("rcynic-version")
    self.rcynic_date = self.root.get("date")
    self.timestamp = parse_utc(self.rcynic_date)

    self.labels = [Label(elt) for elt in self.root.find("labels")]
    label_map = dict((label.code, label) for label in self.labels)

    self.validation_status = [Validation_Status(elt, label_map)
                              for elt in self.root.findall("validation_status")]

    if opt["suppress-backup-whining"]:
      accepted_current = set(v.uri for v in self.validation_status
                             if v.is_current and v.accepted)
      self.validation_status = [v for v in self.validation_status
                                if not v.is_backup
                                or v.uri not in accepted_current]

    for elt in self.root.findall("rsync_history"):
      self.add_connection(elt)

    fn2s = set()
    generations = set()

    for v in self.validation_status:
      self.maybe_add_host(v.hostname).add_validation_status(v)
      fn2s.add(v.fn2)
      generations.add(v.generation)

    if opt["suppress-zero-columns"]:
      self.labels = [l for l in self.labels if l.count > 0]

    self.unique_hostnames   = sorted(self.hosts)
    self.unique_fn2s        = sorted(fn2s)
    self.unique_generations = sorted(generations)

  def maybe_add_host(self, hostname):
    if hostname not in self.hosts:
      self.hosts[hostname] = Host()
    return self.hosts[hostname]

  def add_connection(self, elt):
    hostname = urlparse.urlparse(elt.text.strip()).hostname
    self.maybe_add_host(hostname).add_connection(elt)

  def get_sum(self, fn2, generation, label):
    return sum(h.get_counter(fn2, generation, label)
               for h in self.hosts.itervalues())

  def graph(self):
    self.rrd_update()
    self.rrd_graph()

  def rrd_run(self, cmd):
    try:
      cmd = [str(i) for i in cmd]
      cmd.insert(0, opt["rrdtool-binary"])
      return subprocess.check_output(cmd).splitlines()
    except OSError, e:
      usage("Problem running %s, perhaps you need to set --rrdtool-binary?  (%s)" % (
        opt["rrdtool-binary"], e))

  rras = tuple("RRA:AVERAGE:0.5:%s:9600" % steps for steps in (1, 4, 24))

  def rrd_update(self):
    for hostname, h in self.hosts.iteritems():
      filename = os.path.join(opt["output_directory"], hostname) + ".rrd"
      if not os.path.exists(filename):
        cmd = ["create", filename, "--start", self.timestamp - 1, "--step", "3600"]
        cmd.extend(Host.field_ds_specifiers())
        cmd.extend(self.rras)
        self.rrd_run(cmd)
      self.rrd_run(["update", filename,
                    "%s:%s" % (self.timestamp, ":".join(str(v) for v in h.field_values))])

  graph_opts = (
    "--width", "1200",
    "--vertical-label", "Sync time (seconds)",
    "--right-axis-label", "Objects (count)",
    "--lower-limit", "0",
    "--right-axis", "1:0" )

  graph_cmds = (

    # Split elapsed into separate data sets, so we can color
    # differently to indicate how succesful transfer was.  Intent is
    # that exactly one of these be defined for every value in elapsed.

    "CDEF:success=failed,UNKN,elapsed,IF",
    "CDEF:failure=connections,1,EQ,failed,*,elapsed,UNKN,IF",
    "CDEF:partial=connections,1,NE,failed,*,elapsed,UNKN,IF",

    # Show connection timing first, as color-coded semi-transparent
    # areas with opaque borders.  Intent is to make the colors stand
    # out, since they're a major health indicator.  Transparency is
    # handled via an alpha channel (fourth octet of color code).  We
    # draw this stuff first so that later lines can overwrite it.

    "AREA:success#00FF0080:Sync time (success)",
    "AREA:partial#FFA50080:Sync time (partial failure)",
    "AREA:failure#FF000080:Sync time (total failure)",

    "LINE1:success#00FF00",             # Green
    "LINE1:partial#FFA500",             # Orange
    "LINE1:failure#FF0000",             # Red

    # Now show object counts, as a simple black line.

    "LINE1:objects#000000:Objects",     # Black

    # Add averages over period to chart legend.

    "VDEF:avg_elapsed=elapsed,AVERAGE",
    "VDEF:avg_connections=connections,AVERAGE",
    "VDEF:avg_objects=objects,AVERAGE",
    "COMMENT:\j",
    "GPRINT:avg_elapsed:Average sync time (seconds)\: %5.2lf",
    "GPRINT:avg_connections:Average connection count\: %5.2lf",
    "GPRINT:avg_objects:Average object count\: %5.2lf" )

  graph_periods = (("week",  "-1w"),
                   ("month", "-31d"),
                   ("year",  "-1y"))

  def rrd_graph(self):
    for hostname in self.hosts:
      html = HTML("Charts for %s" % hostname, "%s_graphs" % hostname)
      filebase = os.path.join(opt["output_directory"], hostname)
      for period, start in self.graph_periods:
        cmds = [ "graph", "%s_%s.png" % (filebase, period),
                 "--title", hostname,
                 "--start", start,
                 "--imginfo", "@imginfo %s %lu %lu" ]
        cmds.extend(self.graph_opts)
        cmds.extend(Host.field_defs(filebase))
        cmds.extend(self.graph_cmds)
        imginfo = [i for i in self.rrd_run(cmds) if i.startswith("@imginfo")]
        assert len(imginfo) == 1
        filename, width, height = imginfo[0].split()[1:]
        html.BodyElement("h2").text = "%s over last %s" % (hostname, period)
        img = html.BodyElement("img", src = os.path.basename(filename), width = width, height = height)
        self.hosts[hostname].save_graph_maybe(img)
        html.BodyElement("br")
      html.BodyElement("a", href = "index.html").text = "Back"
      html.close()

#

class HTML(object):

  def __init__(self, title, filebase = "index"):

    assert filebase == "index" or opt["output_directory"] is not None
    assert opt["output_file"] is None or opt["output_directory"] is None

    self.filebase = filebase

    self.html = Element("html")
    self.html.append(Comment(" Generators:\n" + 
                             "  " + session.rcynic_version + "\n" +
                             "  $Id$\n"))
    self.head = SubElement(self.html, "head")
    self.body = SubElement(self.html, "body")

    title += " " + session.rcynic_date
    SubElement(self.head, "title").text = title
    SubElement(self.body, "h1").text = title

    if opt["refresh"]:
      SubElement(self.head, "meta", { "http-equiv" : "Refresh", "content" : str(opt["refresh"]) })

    SubElement(self.head, "style", type = "text/css").text = '''
      table           { rules : all; border: 1 }
      th, td          { text-align: center; padding: 4px }
      td.uri          { text-align: left }
      thead tr th,
      tfoot tr td     { font-weight: bold }
'''

    if opt["use-colors"]:
      SubElement(self.head, "style", type = "text/css").text = '''
      .good           { background-color: #77ff77 }
      .warn           { background-color: yellow }
      .bad            { background-color: #ff5500 }
'''

  def close(self):
    if opt["output_file"] is not None:
      output = opt["output_file"]
    elif opt["output_directory"] is not None:
      output = os.path.join(opt["output_directory"], self.filebase + ".html")
    else:
      output = sys.stdout
    ElementTree(element = self.html).write(output)

  def BodyElement(self, tag, **attrib):
    return SubElement(self.body, tag, **attrib)

  def counter_table(self, data_func, total_func):
    table = self.BodyElement("table", rules = "all", border = "1")
    thead = SubElement(table, "thead")
    tfoot = SubElement(table, "tfoot")
    tbody = SubElement(table, "tbody")
    tr = SubElement(thead, "tr")
    SubElement(tr, "th")
    for label in session.labels:
      SubElement(tr, "th").text = label.text
    for fn2 in session.unique_fn2s:
      for generation in session.unique_generations:
        counters = [data_func(fn2, generation, label) for label in session.labels]
        if sum(counters) > 0:
          tr = SubElement(tbody, "tr")
          SubElement(tr, "td").text = ((generation or "") + " " + (fn2 or "")).strip()
          for label, count in zip(session.labels, counters):
            td = SubElement(tr, "td")
            if count > 0:
              td.set("class", label.mood)
              td.text = str(count)
    tr = SubElement(tfoot, "tr")
    SubElement(tr, "td").text = "Total"
    counters = [total_func(label) for label in session.labels]
    for label, count in zip(session.labels, counters):
      td = SubElement(tr, "td")
      if count > 0:
        td.set("class", label.mood)
        td.text = str(count)

  def detail_table(self, validation_status):
    table = self.BodyElement("table", rules = "all", border = "1")
    thead = SubElement(table, "thead")
    tbody = SubElement(table, "tbody")
    tr = SubElement(thead, "tr")
    if opt["show-timestamps"]:
      SubElement(tr, "th").text = "Timestamp"
    SubElement(tr, "th").text = "Generation"
    SubElement(tr, "th").text = "Status"
    SubElement(tr, "th").text = "URI"
    for v in validation_status:
      tr = SubElement(tbody, "tr", { "class" : v.mood })
      if opt["show-timestamps"]:
        SubElement(tr, "td").text = v.timestamp
      SubElement(tr, "td").text = v.generation
      SubElement(tr, "td").text = v.label.text
      SubElement(tr, "td", { "class" : "uri"}).text = v.uri


def main():

  global session
  
  os.putenv("TZ", "UTC")
  time.tzset()

  parse_options()

  session = Session()

  if opt["show-graphs"]:
    session.graph()

  if not opt["one-file-per-section"]:
    html = HTML("rcynic summary")

  if opt["show-summary"]:
    if opt["one-file-per-section"]:
      html = HTML("Grand Totals", "grand_totals")
    else:
      html.BodyElement("br")
      html.BodyElement("h2").text = "Grand Totals"
    html.counter_table(session.get_sum, Label.get_count)
    if opt["one-file-per-section"]:
      html.close()
    else:
      html.BodyElement("br")
      html.BodyElement("h2").text = "Summaries by Repository Host"
    for hostname in session.unique_hostnames:
      if opt["one-file-per-section"]:
        html = HTML("Summary for %s" % hostname, "%s_summary" % hostname)
      else:
        html.BodyElement("br")
        html.BodyElement("h3").text = hostname
      html.counter_table(session.hosts[hostname].get_counter, session.hosts[hostname].get_total)
      if opt["show-graphs"]:
        html.BodyElement("br")
        html.BodyElement("a", href = "%s_graphs.html" % hostname).append(session.hosts[hostname].graph)
      if opt["one-file-per-section"]:
        html.close()

  if opt["show-problems"]:
    if opt["one-file-per-section"]:
      html = HTML("Problems", "problems")
    else:
      html.BodyElement("br")
      html.BodyElement("h2").text = "Problems"
    html.detail_table((v for v in session.validation_status if v.mood != "good"))
    if opt["one-file-per-section"]:
      html.close()

  if opt["show-detailed-status"]:
    if opt["one-file-per-section"]:
      html = HTML("Validation Status", "session.validation_status")
    else:
      html.BodyElement("br")
      html.BodyElement("h2").text = "Validation Status"
    html.detail_table(session.validation_status)
    if opt["one-file-per-section"]:
      html.close()

  if not opt["one-file-per-section"]:
    html.close()

if __name__ == "__main__":
  main()
