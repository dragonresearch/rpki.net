"""
Render rcynic's XML output to basic (X)HTML with some rrdtool graphis.

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
import textwrap

try:
  from lxml.etree            import (ElementTree, Element, SubElement, Comment)
except ImportError:
  from xml.etree.ElementTree import (ElementTree, Element, SubElement, Comment)

session = None

opt = {
  "refresh"                     : 1800,
  "show-detailed-status"        : True,
  "show-problems"               : False,
  "show-graphs"                 : True,
  "update-rrds"                 : True,
  "rrdtool-binary"              : "rrdtool",
  "suckerfish-javascript"       : False,
  "png-height"                  : 190,
  "png-width"                   : 1350,
  "svg-height"                  : 600,
  "svg-width"                   : 1200 }

def usage(msg = 0):
  f = sys.stderr if msg else sys.stdout
  f.write("Usage: %s %s [options] input_file output_directory\n" % (sys.executable, sys.argv[0]))
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

  if len(argv) > 2:
    usage("Unexpected arguments")

  try:
    opt["input_file"] = argv[0]
    opt["output_directory"] = argv[1]
  except IndexError:
    usage("Missing required arguments")

  if not os.path.isdir(opt["output_directory"]):
    try:
      os.makedirs(opt["output_directory"])
    except OSError, e:
      sys.exit("Couldn't create output directory: %s" % e)


def parse_utc(s):
  return int(time.mktime(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ")))

class Label(object):

  moods = ["bad", "warn", "good"]

  def __init__(self, elt):
    self.code = elt.tag
    self.mood = elt.get("kind")
    self.text = elt.text.strip()
    self.count = 0

  def get_count(self):
    return self.count

  @property
  def sort_key(self):
    try:
      return self.moods.index(self.mood)
    except ValueError:
      return len(self.moods)

class Validation_Status(object):

  def __init__(self, elt, label_map):
    self.uri = elt.text.strip()
    self.timestamp = elt.get("timestamp")
    self.generation = elt.get("generation")
    self.hostname = urlparse.urlparse(self.uri).hostname or None
    self.fn2 = os.path.splitext(self.uri)[1] or None if self.generation else None
    self.label = label_map[elt.get("status")]

  def sort_key(self):
    return (self.label.sort_key, self.timestamp, self.hostname, self.fn2, self.generation)

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
  
  @property
  def is_problem(self):
    return self.label.mood != "good"

  @property
  def is_connection_problem(self):
    return self.label.mood != "good" and self.label.code.startswith("rsync_transfer_")

  @property
  def is_object_problem(self):
    return self.label.mood != "good" and not self.label.code.startswith("rsync_transfer_")

class Problem_Mixin(object):
  
  @property
  def connection_problems(self):
    result = [v for v in self.validation_status if v.is_connection_problem]
    result.sort(key = Validation_Status.sort_key)
    return result

  @property
  def object_problems(self):
    result = [v for v in self.validation_status if v.is_object_problem]
    result.sort(key = Validation_Status.sort_key)
    return result

class Host(Problem_Mixin):

  def __init__(self, hostname, timestamp):
    self.hostname = hostname
    self.timestamp = timestamp
    self.elapsed = 0
    self.connections = 0
    self.failures = 0
    self.uris = set()
    self.graph = None
    self.counters = {}
    self.totals = {}
    self.validation_status = []

  def add_connection(self, elt):
    self.elapsed += parse_utc(elt.get("finished")) - parse_utc(elt.get("started"))
    self.connections += 1
    if elt.get("error") is not None:
      self.failures += 1

  def add_validation_status(self, v):
    self.validation_status.append(v)
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

  rras = tuple("RRA:AVERAGE:0.5:%s:9600" % steps
               for steps in (1, 4, 24))

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

  graph_opts = (
    "--vertical-label", "Sync time (seconds)",
    "--right-axis-label", "Objects (count)",
    "--lower-limit", "0",
    "--right-axis", "1:0",
    "--dynamic-labels",
    "--full-size-mode" )

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

  def rrd_run(self, cmd):
    try:
      cmd = [str(i) for i in cmd]
      cmd.insert(0, opt["rrdtool-binary"])
      return subprocess.check_output(cmd).splitlines()
    except OSError, e:
      usage("Problem running %s, perhaps you need to set --rrdtool-binary?  (%s)" % (
        opt["rrdtool-binary"], e))

  def rrd_update(self):
    filename = os.path.join(opt["output_directory"], self.hostname) + ".rrd"
    if not os.path.exists(filename):
      cmd = ["create", filename, "--start", self.timestamp - 1, "--step", "3600"]
      cmd.extend(self.field_ds_specifiers())
      cmd.extend(self.rras)
      self.rrd_run(cmd)
    self.rrd_run(["update", filename,
                  "%s:%s" % (self.timestamp, ":".join(str(v) for v in self.field_values))])

  def rrd_graph(self, html):
    filebase = os.path.join(opt["output_directory"], self.hostname)
    for period, start in self.graph_periods:
      for format in ("png", "svg"):
        cmds = [ "graph", "%s_%s.%s" % (filebase, period, format),
                 "--title", "%s last %s" % (self.hostname, period),
                 "--start", start,
                 "--width", opt[format + "-width"],
                 "--height", opt[format + "-height"],
                 "--imgformat", format.upper() ]
        cmds.extend(self.graph_opts)
        cmds.extend(self.field_defs(filebase))
        cmds.extend(self.graph_cmds)
        self.rrd_run(cmds)
      img = Element("img", src = "%s_%s.png" % (self.hostname, period),
                    width  = str(opt["png-width"]),
                    height = str(opt["png-height"]))
      if self.graph is None:
        self.graph = copy.copy(img)
      html.BodyElement("h2").text = "%s over last %s" % (self.hostname, period)
      html.BodyElement("a", href = "%s_%s_svg.html" % (self.hostname, period)).append(img)
      html.BodyElement("br")
      svg_html = HTML("%s over last %s" % (self.hostname, period),
                      "%s_%s_svg" % (self.hostname, period))
      svg_html.body.append(ElementTree(file = "%s_%s.svg" % (filebase, period)).getroot())
      svg_html.close()

  
class Session(Problem_Mixin):

  def __init__(self):
    self.hosts = {}

    if opt["input_file"] == "-":
      self.root = ElementTree(file = sys.stdin).getroot()
    else:
      self.root = ElementTree(file = opt["input_file"]).getroot()

    self.rcynic_version = self.root.get("rcynic-version")
    self.rcynic_date = self.root.get("date")
    self.timestamp = parse_utc(self.rcynic_date)

    self.labels = [Label(elt) for elt in self.root.find("labels")]
    self.load_validation_status()

    for elt in self.root.findall("rsync_history"):
      self.get_host(urlparse.urlparse(elt.text.strip()).hostname).add_connection(elt)

    generations = set()
    fn2s = set()

    for v in self.validation_status:
      self.get_host(v.hostname).add_validation_status(v)
      generations.add(v.generation)
      fn2s.add(v.fn2)

    self.labels = [l for l in self.labels if l.count > 0]

    self.hostnames   = sorted(self.hosts)
    self.generations = sorted(generations)
    self.fn2s        = sorted(fn2s)

  def load_validation_status(self):
    label_map = dict((label.code, label) for label in self.labels)
    full_validation_status = [Validation_Status(elt, label_map)
                              for elt in self.root.findall("validation_status")]
    accepted_current = set(v.uri for v in full_validation_status
                           if v.is_current and v.accepted)
    self.validation_status = [v for v in full_validation_status
                              if not v.is_backup
                              or v.uri not in accepted_current]

  def get_host(self, hostname):
    if hostname not in self.hosts:
      self.hosts[hostname] = Host(hostname, self.timestamp)
    return self.hosts[hostname]

  def get_sum(self, fn2, generation, label):
    return sum(h.get_counter(fn2, generation, label)
               for h in self.hosts.itervalues())

  def rrd_update(self):
    if opt["update-rrds"]:
      for h in self.hosts.itervalues():
        h.rrd_update()

css = '''
  /*
   * Cascading style sheet for rcynic-html output.  Much of this
   * comes, indirectly, at a remove of many years, from
   * http://www.htmldog.com/articles/suckerfish/dropdowns/example/
   */

  th, td {
    text-align: center; padding: 4px;
  }

  td.uri {
    text-align: left;
  }

  thead tr th, tfoot tr td {
    font-weight: bold;
  }

  .good {
    background-color: #77ff77;
  }

  .warn {
    background-color: yellow;
  }

  .bad {
    background-color: #ff5500;
  }

  body {
    font-family: arial, helvetica, serif;
  }

  #nav, #nav ul {
    float: left;
    width: 100%;
    list-style: none;
    line-height: 1;
    background: white;
    font-weight: normal;
    padding: 0;
    border: solid black;
    border-width: 1px 0;
    margin: 0 0 1em 0;
  }

  #nav a, #nav span {
    display: block;
    color: black;
    text-decoration: none;
    padding: 0.25em 0.75em;
  }

  #nav li {
    float: left;
    padding: 0;
  }

  /*
   * There's no useful way to set a width here, we have to set it as a style
   * attribute in  the <ul/> elements.  CSS2, maybe, someday.
   */
  #nav li ul {
    position: absolute;
    left: -999em;
    height: auto;
    border-width: 1px;
    margin: 0;
  }

  #nav li li {
    width: 100%;
  }

  #nav li:hover ul ul, #nav li:hover ul ul ul, #nav li.sfhover ul ul, #nav li.sfhover ul ul ul {
    left: -999em;
  }

  #nav li:hover ul, #nav li li:hover ul, #nav li li li:hover ul, #nav li.sfhover ul, #nav li li.sfhover ul, #nav li li li.sfhover ul {
    left: auto;
  }

  #nav li:hover, #nav li.sfhover {
    background: white;
  }
'''

suckerfish = '''
  // The amazing Suckerfish hack to let Internet Exploder use CSS dropdowns.
  // See http://www.htmldog.com/articles/suckerfish/dropdowns/

  sfHover = function() {
    var sfEls = document.getElementById("nav").getElementsByTagName("li");
    for (var i = 0; i < sfEls.length; i++) {
      sfEls[i].onmouseover = function() {
        this.className += " sfhover";
      }
      sfEls[i].onmouseout = function() {
        this.className = this.className.replace(new RegExp(" sfhover\\b"), "");
      }
    }
  }

  if (window.attachEvent)
    window.attachEvent("onload", sfHover);
'''

class HTML(object):

  css_name = "rcynic-html.css"
  suckerfish_name = "suckerfish.js"

  @classmethod
  def write_static_files(cls):
    f = open(os.path.join(opt["output_directory"], cls.css_name), "w")
    f.write(textwrap.dedent(css))
    f.close()
    if opt["suckerfish-javascript"]:
      f = open(os.path.join(opt["output_directory"], cls.suckerfish_name), "w")
      f.write(textwrap.dedent(suckerfish))
      f.close()

  def __init__(self, title, filebase):

    self.filename = os.path.join(opt["output_directory"], filebase + ".html")

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

    hostwidth = max(len(hostname) for hostname in session.hostnames)

    SubElement(self.head, "link", href = self.css_name, rel = "stylesheet", type = "text/css")
    if opt["suckerfish-javascript"]:
      SubElement(self.head, "script", src = self.suckerfish_name, type = "text/javascript")

    toc = SubElement(self.body, "ul", id = "nav")
    SubElement(SubElement(toc, "li"), "a", href = "index.html").text = "Overview"
    li = SubElement(toc, "li")
    SubElement(li, "span").text = "Repositories"
    hul = SubElement(li, "ul", style = "width: %sem" % hostwidth)
    for hostname in session.hostnames:
      SubElement(SubElement(hul, "li"), "a", href = "%s.html" % hostname).text = hostname
    SubElement(SubElement(toc, "li"), "a", href = "problems.html").text = "Problems"
    SubElement(SubElement(toc, "li"), "a", href = "details.html").text = "Per-object details"
    SubElement(self.body, "br")

  def close(self):
    ElementTree(element = self.html).write(self.filename)

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
    for fn2 in session.fn2s:
      for generation in session.generations:
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
    return table

  def detail_table(self, records):
    if records:
      table = self.BodyElement("table", rules = "all", border = "1")
      thead = SubElement(table, "thead")
      tbody = SubElement(table, "tbody")
      tr = SubElement(thead, "tr")
      SubElement(tr, "th").text = "Timestamp"
      SubElement(tr, "th").text = "Generation"
      SubElement(tr, "th").text = "Status"
      SubElement(tr, "th").text = "URI"
      for v in records:
        tr = SubElement(tbody, "tr", { "class" : v.mood })
        SubElement(tr, "td").text = v.timestamp
        SubElement(tr, "td").text = v.generation
        SubElement(tr, "td").text = v.label.text
        SubElement(tr, "td", { "class" : "uri"}).text = v.uri
      return table
    else:
      self.BodyElement("p").text = "None found"
      return None

def main():

  global session
  
  os.putenv("TZ", "UTC")
  time.tzset()

  parse_options()
  HTML.write_static_files()

  session = Session()
  session.rrd_update()

  for hostname in session.hostnames:
    html = HTML("Host Details For %s" % hostname, hostname)
    html.counter_table(session.hosts[hostname].get_counter, session.hosts[hostname].get_total)
    if opt["show-graphs"]:
      session.hosts[hostname].rrd_graph(html)
    html.BodyElement("h2").text = "Connection Problems"
    html.detail_table(session.hosts[hostname].connection_problems)
    html.BodyElement("h2").text = "Object Problems"
    html.detail_table(session.hosts[hostname].object_problems)
    html.close()

  html = HTML("rcynic Summary", "index")
  html.BodyElement("h2").text = "Grand Totals"
  html.counter_table(session.get_sum, Label.get_count)
  for hostname in session.hostnames:
    html.BodyElement("br")
    html.BodyElement("hr")
    html.BodyElement("br")
    html.BodyElement("h2").text = "Overview For Repository %s" % hostname
    html.counter_table(session.hosts[hostname].get_counter, session.hosts[hostname].get_total)
    if opt["show-graphs"]:
      html.BodyElement("br")
      html.BodyElement("a", href = "%s.html" % hostname).append(session.hosts[hostname].graph)
  html.close()

  html = HTML("Problems", "problems")
  html.BodyElement("h2").text = "Connection Problems"
  html.detail_table(session.connection_problems)
  html.BodyElement("h2").text = "Object Problems"
  html.detail_table(session.object_problems)
  html.close()

  html = HTML("All Details", "details")
  html.detail_table(session.validation_status)
  html.close()


if __name__ == "__main__":
  main()
