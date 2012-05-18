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

opt = {
  "refresh"                     : 1800,
  "suppress-zero-columns"       : True,
  "use-colors"                  : True,
  "show-detailed-status"        : True,
  "show-problems"               : False,
  "show-summary"                : True,
  "show-graphs"                 : False,
  "suppress-backup-whining"     : True,
  "one-file-per-section"        : False,
  "rrdtool-binary"              : "rrdtool" }

def usage(msg = 0):
  f = sys.stderr if msg else sys.stdout
  f.write("Usage: %s %s [options] [input_file [output_file_or_directory]]\n" % (sys.executable, sys.argv[0]))
  f.write("Options:\n")
  for i in sorted(opt):
    if not isinstance(opt[i], bool):
      f.write("   --%-30s (%s)\n" % (i + " <value>", opt[i]))
  for i in sorted(opt):
    if isinstance(opt[i], bool):
      f.write("   --[no-]%-25s (--%s%s)\n" % (i, "" if opt[i] else "no-", i))
  if msg:
    f.write("\n")
  sys.exit(msg)

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

input_file  = argv[0] if len(argv) > 0 else None
output_foo = argv[1] if len(argv) > 1 else None

if len(argv) > 2:
  usage("Unexpected arguments")

output_directory = output_file = None

if opt["one-file-per-section"] or opt["show-graphs"]:
  output_directory = output_foo
  if output_directory is None:
    usage("--show-graphs and --one-file-per-section require an output directory")
  if not os.path.isdir(output_directory):
    os.makedirs(output_directory)
else:
  output_file = output_foo

del output_foo

html = None
body = None

def parse_utc(s):
  return int(time.mktime(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ")))

class Label(object):

  def __init__(self, elt, pos):
    self.code = elt.tag
    self.mood = elt.get("kind")
    self.text = elt.text.strip()
    self.pos  = pos
    self.sum  = 0

  def __cmp__(self, other):
    return cmp(self.pos, other.pos)

class Validation_Status(object):

  @classmethod
  def set_label_map(cls, labels):
    cls.label_map = dict((l.code, l) for l in labels)

  def __init__(self, elt):
    self.uri = elt.text.strip()
    self.timestamp = elt.get("timestamp")
    self.generation = elt.get("generation")
    self.hostname = urlparse.urlparse(self.uri).hostname or None
    self.fn2 = os.path.splitext(self.uri)[1] or None if self.generation else None
    self.label = self.label_map[elt.get("status")]

  def stand_up_and_be_counted(self):
    self.label.sum += 1

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

  def add_connection(self, elt):
    self.elapsed += parse_utc(elt.get("finished")) - parse_utc(elt.get("started"))
    self.connections += 1
    if elt.get("error") is not None:
      self.failures += 1

  def add_validation_status(self, v):
    if v.generation == "current":
      self.uris.add(v.uri)
    self.counters[(v.fn2, v.generation, v.code)] = self.get_counter(v.fn2, v.generation, v.code) + 1
    self.counters[v.code] = self.get_total(v.code) + 1

  def get_counter(self, fn2, generation, code):
    return self.counters.get((fn2, generation, code), 0)

  def get_total(self, code):
    return self.counters.get(code, 0)

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

class Session(dict):

  def __init__(self, timestamp):
    dict.__init__(self)
    self.timestamp = timestamp

  def maybe_add_host(self, hostname):
    if hostname not in self:
      self[hostname] = Host()
    return self[hostname]

  def add_connection(self, elt):
    hostname = urlparse.urlparse(elt.text.strip()).hostname
    self.maybe_add_host(hostname).add_connection(elt)

  def add_validation_status(self, v):
    self.maybe_add_host(v.hostname).add_validation_status(v)

  def run(self, *cmd):
    try:
      return subprocess.check_output([str(i) for i in (opt["rrdtool-binary"],) + cmd]).splitlines()
    except OSError, e:
      usage("Problem running %s, perhaps you need to set --rrdtool-binary?  (%s)" % (opt["rrdtool-binary"], e))

  rras = tuple("RRA:AVERAGE:0.5:%s:9600" % steps for steps in (1, 4, 24))

  def save(self):
    for hostname, h in self.iteritems():
      filename = os.path.join(output_directory, hostname) + ".rrd"
      if not os.path.exists(filename):
        cmd = ["create", filename, "--start", self.timestamp - 1, "--step", "3600"]
        cmd.extend(Host.field_ds_specifiers())
        cmd.extend(self.rras)
        self.run(*cmd)
      self.run("update", filename,
               "%s:%s" % (self.timestamp, ":".join(str(v) for v in h.field_values)))

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

  def graph(self):
    for hostname in self:
      start_html("Charts for %s" % hostname)
      filebase = os.path.join(output_directory, hostname)
      for period, start in self.graph_periods:
        cmds = [ "graph", "%s_%s.png" % (filebase, period),
                 "--title", hostname,
                 "--start", start,
                 "--imginfo", "@imginfo %s %lu %lu" ]
        cmds.extend(self.graph_opts)
        cmds.extend(Host.field_defs(filebase))
        cmds.extend(self.graph_cmds)
        imginfo = [i for i in self.run(*cmds) if i.startswith("@imginfo")]
        assert len(imginfo) == 1
        filename, width, height = imginfo[0].split()[1:]
        SubElement(body, "h2").text = "%s over last %s" % (hostname, period)
        img = SubElement(body, "img", src = os.path.basename(filename), width = width, height = height)
        self[hostname].save_graph_maybe(img)
        SubElement(body, "br")
      SubElement(body, "a", href = "index.html").text = "Back"
      finish_html("%s_graphs" % hostname)

#

table_css = { "rules" : "all", "border" : "1"}
uri_css   = { "class" : "uri" }

def start_html(title):

  global html
  global body

  html = Element("html")
  html.append(Comment(" Generators:\n" +
                      "  " + input.getroot().get("rcynic-version") + "\n" +
                      "  $Id$\n"))
  head = SubElement(html, "head")
  body = SubElement(html, "body")

  title += " " + input.getroot().get("date")
  SubElement(head, "title").text = title
  SubElement(body, "h1").text = title

  if opt["refresh"]:
    SubElement(head, "meta", { "http-equiv" : "Refresh", "content" : str(opt["refresh"]) })

  SubElement(head, "style", type = "text/css").text = '''
    th, td          { text-align: center; padding: 4px }
    td.uri          { text-align: left }
    thead tr th,
    tfoot tr td     { font-weight: bold }
'''

  if opt["use-colors"]:
    SubElement(head, "style", type = "text/css").text = '''
    .good           { background-color: #77ff77 }
    .warn           { background-color: yellow }
    .bad            { background-color: #ff5500 }
'''

def finish_html(name = "index"):
  global html
  global body
  assert name == "index" or output_directory is not None
  assert output_file is None or output_directory is None
  if output_file is not None:
    output = output_file
  elif output_directory is not None:
    output = os.path.join(output_directory, name + ".html")
  else:
    output = sys.stdout
  ElementTree(element = html).write(output)
  html = None
  body = None

# Main

os.putenv("TZ", "UTC")
time.tzset()

input = ElementTree(file = sys.stdin if input_file is None else input_file)

session = Session(parse_utc(input.getroot().get("date")))

labels = [Label(elt, i) for i, elt in enumerate(input.find("labels"))]

Validation_Status.set_label_map(labels)
validation_status = [Validation_Status(elt) for elt in input.findall("validation_status")]

if opt["suppress-backup-whining"]:
  accepted_current = set(v.uri for v in validation_status if v.is_current and v.accepted)
  validation_status = [v for v in validation_status if not v.is_backup or v.uri not in accepted_current]
  del accepted_current

for elt in input.findall("rsync_history"):
  session.add_connection(elt)

for v in validation_status:
  v.stand_up_and_be_counted()
  session.add_validation_status(v)

if opt["suppress-zero-columns"]:
  labels = [l for l in labels if l.sum > 0]

if opt["show-graphs"]:
  session.save()
  session.graph()

if not opt["one-file-per-section"]:
  start_html("rcynic summary")

if opt["show-summary"]:

  unique_hostnames   = sorted(set(v.hostname   for v in validation_status))
  unique_fn2s        = sorted(set(v.fn2        for v in validation_status))
  unique_generations = sorted(set(v.generation for v in validation_status))

  if opt["one-file-per-section"]:
    start_html("Grand Totals")
  else:
    SubElement(body, "br")
    SubElement(body, "h2").text = "Grand Totals"

  table = SubElement(body, "table", table_css)
  thead = SubElement(table, "thead")
  tfoot = SubElement(table, "tfoot")
  tbody = SubElement(table, "tbody")
  tr = SubElement(thead, "tr")
  SubElement(tr, "th")
  for l in labels:
    SubElement(tr, "th").text = l.text
  for fn2 in unique_fn2s:
    for generation in unique_generations:
      counters = [sum(h.get_counter(fn2, generation, l.code) for h in session.itervalues()) for l in labels]
      if sum(counters) > 0:
        tr = SubElement(tbody, "tr")
        SubElement(tr, "td").text = ((generation or "") + " " + (fn2 or "")).strip()
        for l, c in zip(labels, counters):
          td = SubElement(tr, "td")
          if c > 0:
            td.set("class", l.mood)
            td.text = str(c)
  tr = SubElement(tfoot, "tr")
  SubElement(tr, "td").text = "Total"
  for l in labels:
    SubElement(tr, "td", { "class" : l.mood }).text = str(l.sum)

  if opt["one-file-per-section"]:
    finish_html("grand_totals")
  else:
    SubElement(body, "br")
    SubElement(body, "h2").text = "Summaries by Repository Host"

  for hostname in unique_hostnames:
    if opt["one-file-per-section"]:
      start_html("Summary for %s" % hostname)
    else:
      SubElement(body, "br")
      SubElement(body, "h3").text = hostname
    table = SubElement(body, "table", table_css)
    thead = SubElement(table, "thead")
    tfoot = SubElement(table, "tfoot")
    tbody = SubElement(table, "tbody")
    tr = SubElement(thead, "tr")
    SubElement(tr, "th")
    for l in labels:
      SubElement(tr, "th").text = l.text
    for fn2 in unique_fn2s:
      for generation in unique_generations:
        counters = [session[hostname].get_counter(fn2, generation, l.code) for l in labels]
        if sum(counters) > 0:
          tr = SubElement(tbody, "tr")
          SubElement(tr, "td").text = ((generation or "") + " " + (fn2 or "")).strip()
          for l, c in zip(labels, counters):
            td = SubElement(tr, "td")
            if c > 0:
              td.set("class", l.mood)
              td.text = str(c)
    tr = SubElement(tfoot, "tr")
    SubElement(tr, "td").text = "Total"
    counters = [session[hostname].get_total(l.code) for l in labels]
    for l, c in zip(labels, counters):
      td = SubElement(tr, "td")
      if c > 0:
        td.set("class", l.mood)
        td.text = str(c)
    if opt["show-graphs"]:
      SubElement(body, "br")
      SubElement(body, "a", href = "%s_graphs.html" % hostname).append(session[hostname].graph)
    if opt["one-file-per-section"]:
      finish_html("%s_summary" % hostname)

if opt["show-problems"]:

  if opt["one-file-per-section"]:
    start_html("Problems")
  else:
    SubElement(body, "br")
    SubElement(body, "h2").text = "Problems"
  table = SubElement(body, "table", table_css)
  thead = SubElement(table, "thead")
  tbody = SubElement(table, "tbody")
  tr = SubElement(thead, "tr")
  SubElement(tr, "th").text = "Status"
  SubElement(tr, "th").text = "URI"
  for v in validation_status:
    if v.mood != "good":
      tr = SubElement(tbody, "tr", { "class" : v.mood })
      SubElement(tr, "td").text = v.label.text
      SubElement(tr, "td", uri_css).text = v.uri
  if opt["one-file-per-section"]:
    finish_html("problems")

if opt["show-detailed-status"]:

  if opt["one-file-per-section"]:
    start_html("Validation Status")
  else:
    SubElement(body, "br")
    SubElement(body, "h2").text = "Validation Status"
  table = SubElement(body, "table", table_css)
  thead = SubElement(table, "thead")
  tbody = SubElement(table, "tbody")
  tr = SubElement(thead, "tr")
  SubElement(tr, "th").text = "Timestamp"
  SubElement(tr, "th").text = "Generation"
  SubElement(tr, "th").text = "Status"
  SubElement(tr, "th").text = "URI"
  for v in validation_status:
    tr = SubElement(tbody, "tr", { "class" : v.mood })
    SubElement(tr, "td").text = v.timestamp
    SubElement(tr, "td").text = v.generation
    SubElement(tr, "td").text = v.label.text
    SubElement(tr, "td", uri_css).text = v.uri
  if opt["one-file-per-section"]:
    finish_html("validation_status")

if not opt["one-file-per-section"]:
  finish_html()
