"""
Render rcynic's XML output to very basic (X)HTML.  This is a Python
reimplementation of rcynic.xsl, which had gotten too slow and complex.

$Id$

Copyright (C) 2010-2011 Internet Systems Consortium, Inc. ("ISC")

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

import sys, urlparse, os, getopt

from xml.etree.ElementTree import (ElementTree, Element, SubElement, Comment)

opt = {
  "refresh"               : 1800,
  "suppress_zero_columns" : True,
  "use_colors"            : True,
  "show_detailed_status"  : True,
  "show_problems"         : False,
  "show_summary"          : True,
  "one_file_per_section"  : False }

def usage(msg = 0):
  f = sys.stderr if msg else sys.stdout
  f.write("Usage: %s %s [options] [input_file [output_file]]\n" % (sys.executable, sys.argv[0]))
  f.write("Options:\n")
  for i in sorted(opt):
    f.write("   --%s <value>   (default %s)\n" % (i, opt[i]))
  if msg:
    f.write("\n")
  sys.exit(msg)

bool_map = {
  "yes" : True,  "y" : True,  "true"  : True,  "on"   : True,  "1" : True,
  "no"  : False, "n" : False, "false" : False, "off"  : False, "0" : False }

try:
  opts, argv = getopt.getopt(sys.argv[1:], "h?", ["help"] + ["%s=" % s for s in opt])
  for o, a in opts:
    if o in ("-?", "-h", "--help"):
      usage(0)
    elif o == "--refresh":
      opt["refresh"] = int(a)
    else:
      opt[o[2:]] = bool_map[a.lower()]
except KeyError:
  usage("Bad boolean value given to %s switch: %s" % (o, a))
except (ValueError, getopt.GetoptError), e:
  usage(str(e))

input_file  = argv[0] if len(argv) > 0 else None
output_file = argv[1] if len(argv) > 1 else None

if len(argv) > 2:
  usage("Unexpected arguments")

if opt["one_file_per_section"] and (output_file is None or "%s" not in output_file):
  usage('--one_file_per_section" requires specifying an output file name containing %s')

class Label(object):

  def __init__(self, elt):
    self.code = elt.tag
    self.mood = elt.get("kind")
    self.text = elt.text.strip()
    self.sum  = 0

class Validation_Status(object):

  def __init__(self, elt, map):
    self.uri = elt.text.strip()
    self.timestamp = elt.get("timestamp")
    self.generation = elt.get("generation")
    self.hostname = urlparse.urlparse(self.uri).hostname or None
    self.fn2 = os.path.splitext(self.uri)[1] or None if self.generation else None
    self.label = map[elt.get("status")]
    self.label.sum += 1

  @property
  def code(self):
    return self.label.code

  @property
  def mood(self):
    return self.label.mood

html = None
body = None

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

  if opt["use_colors"]:
    SubElement(head, "style", type = "text/css").text = '''
    .good           { background-color: #77ff77 }
    .warn           { background-color: yellow }
    .bad            { background-color: #ff5500 }
'''

def finish_html(name = None):
  global html
  global body
  if output_file is None:
    output = sys.stdout
  elif name is None:
    output = output_file
  else:
    output = output_file % name
  ElementTree(element = html).write(output)
  html = None
  body = None

input = ElementTree(file = sys.stdin if input_file is None else input_file)
labels = [Label(elt) for elt in input.find("labels")]
label_map = dict((l.code, l) for l in labels)
validation_status = [Validation_Status(elt, label_map) for elt in input.findall("validation_status")]
del label_map
if opt["suppress_zero_columns"]:
  labels = [l for l in labels if l.sum > 0]

if not opt["one_file_per_section"]:
  start_html("rcynic summary")

if opt["show_summary"]:

  unique_hostnames   = sorted(set(v.hostname   for v in validation_status))
  unique_fn2s        = sorted(set(v.fn2        for v in validation_status))
  unique_generations = sorted(set(v.generation for v in validation_status))

  if opt["one_file_per_section"]:
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
      if any(v.fn2 == fn2 and v.generation == generation for v in validation_status):
        tr = SubElement(tbody, "tr")
        SubElement(tr, "td").text = ((generation or "") + " " + (fn2 or "")).strip()
        for l in labels:
          value = sum(int(v.fn2 == fn2 and v.generation == generation and v.code == l.code) for v in validation_status)
          td = SubElement(tr, "td")
          if value > 0:
            td.set("class", l.mood)
            td.text = str(value)
  tr = SubElement(tfoot, "tr")
  SubElement(tr, "td").text = "Total"
  for l in labels:
    SubElement(tr, "td", { "class" : l.mood }).text = str(l.sum)

  if opt["one_file_per_section"]:
    finish_html("grand_totals")
  else:
    SubElement(body, "br")
    SubElement(body, "h2").text = "Summaries by Repository Host"

  for hostname in unique_hostnames:
    if opt["one_file_per_section"]:
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
        if any(v.hostname == hostname and v.fn2 == fn2 and v.generation == generation for v in validation_status):
          tr = SubElement(tbody, "tr")
          SubElement(tr, "td").text = ((generation or "") + " " + (fn2 or "")).strip()
          for l in labels:
            value = sum(int(v.hostname == hostname and v.fn2 == fn2 and v.generation == generation and v.code == l.code) for v in validation_status)
            td = SubElement(tr, "td")
            if value > 0:
              td.set("class", l.mood)
              td.text = str(value)
    tr = SubElement(tfoot, "tr")
    SubElement(tr, "td").text = "Total"
    for l in labels:
      value = sum(int(v.hostname == hostname and v.code == l.code) for v in validation_status)
      td = SubElement(tr, "td")
      if value > 0:
        td.set("class", l.mood)
        td.text = str(value)
    if opt["one_file_per_section"]:
      finish_html("%s_summary" % hostname)

if opt["show_problems"]:

  if opt["one_file_per_section"]:
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
  if opt["one_file_per_section"]:
    finish_html("problems")

if opt["show_detailed_status"]:

  if opt["one_file_per_section"]:
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
  if opt["one_file_per_section"]:
    finish_html("validation_status")

if not opt["one_file_per_section"]:
  finish_html()
