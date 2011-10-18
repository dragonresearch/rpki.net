"""
Python translation of rcynic.xsl, which has gotten too slow and complex.

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

import sys, urlparse, os

from xml.etree.cElementTree import (ElementTree, Element, SubElement, Comment)

refresh = 1800
suppress_zero_columns = True
show_total = True
use_colors = True
show_detailed_status = True
show_problems = False
show_summary = True

#input = ElementTree(file = sys.stdin)
input = ElementTree(file = "rcynic.xml")

html = Element("html")
html.append(Comment(" Generators:\n  " +
                    input.getroot().get("rcynic-version") +
                    "\n  $Id$\n"))
head = SubElement(html, "head")
body = SubElement(html, "body")

title = "rcynic summary %s" % input.getroot().get("date")
SubElement(head, "title").text = title
SubElement(body, "h1").text = title

if refresh:
  SubElement(head, "meta", { "http-equiv" : "Refresh", "content" : str(refresh) })

css = '''
  td              { text-align: center; padding: 4px }
  td.uri          { text-align: left }
  td.host         { text-align: left }
'''

if use_colors:
  css += '''\
  tr.good,td.good { background-color: #77ff77 }
  tr.warn,td.warn { background-color: yellow }
  tr.bad,td.bad   { background-color: #ff5500 }
'''

SubElement(head, "style", type = "text/css").text = css

class Label(object):

  def __init__(self, elt):
    self.tag = elt.tag
    self.kind = elt.get("kind")
    self.text = elt.text.strip()

class Host_Datum(object):

  def __init__(self, elt):
    self.uri = elt.text.strip()
    self.status = elt.get("status")
    self.timestamp = elt.get("timestamp")
    self.generation = elt.get("generation")
    self.hostname = urlparse.urlparse(self.uri).hostname
    self.label = label_map[self.status]
    self.mood = self.label.kind
    self.fn2 = os.path.splitext(self.uri)[1] or None
    if not self.generation:
      self.fn2 = None

  def __cmp__(self, other):
    return cmp(self.uri, other.uri) or cmp(self.generation, other.generation)

class Total(object):

  # This probably should merge into the Label class, right now I'm
  # just trying to do straight translation to keep from getting too
  # confused by all the different attribute names.

  def __init__(self, label, host_data):
    self.label = label
    self.name = label.tag
    self.mood = label.kind
    self.text = label.text
    self.sum = sum(int(h.status == self.name) for h in host_data)
    self.show = self.sum > 0 or not suppress_zero_columns

labels = [Label(elt) for elt in input.find("labels")]
label_map = dict((label.tag, label) for label in labels)

if show_summary:

  host_data = [Host_Datum(elt) for elt in input.findall("validation_status")]
  #host_data.sort()

  unique_hostnames   = set(h.hostname   for h in host_data)
  unique_fn2s        = set(h.fn2        for h in host_data)
  unique_generations = set(h.generation for h in host_data)

  totals  = [Total(label, host_data) for label in labels]
  columns = sum(total.sum for total in totals)

  if show_summary:

    SubElement(body, "br")
    SubElement(body, "h2").text = "Grand Totals"
    table = SubElement(body, "table", { "class" : "summary", "rules" : "all", "border" : "1"})
    thead = SubElement(table, "thead")
    tr = SubElement(thead, "tr")
    SubElement(tr, "td")
    for t in totals:
      if t.show:
        elt = SubElement(tr, "td")
        elt = SubElement(elt, "b")
        elt.text = t.text
    tbody = SubElement(table, "tbody")
    tr = SubElement(tbody, "tr")
    elt = SubElement(tr, "td")
    elt = SubElement(elt, "b")
    elt.text = "Total"
    for t in totals:
      if t.show:
        SubElement(tr, "td", { "class" : t.mood }).text = str(t.sum)
    
    SubElement(body, "br")
    SubElement(body, "h2").text = "Summaries by Repository Host"

    for hostname in sorted(unique_hostnames):
      SubElement(body, "br")
      SubElement(body, "h3").text = hostname
      table = SubElement(body, "table", { "class" : "summary", "rules" : "all", "border" : "1"})
      thead = SubElement(table, "thead")
      tr = SubElement(thead, "tr")
      SubElement(tr, "td")
      for t in totals:
        if t.show:
          elt = SubElement(tr, "td")
          elt = SubElement(elt, "b")
          elt.text = t.text
      tbody = SubElement(table, "tbody")
      for fn2 in sorted(unique_fn2s):
        for generation in sorted(unique_generations):
          if any(h.hostname == hostname and h.fn2 == fn2 and h.generation == generation for h in host_data):
            tr = SubElement(tbody, "tr")
            SubElement(tr, "td").text = (generation or "") + " " + (fn2 or "")
            for t in totals:
              if t.show:
                value = sum(int(h.hostname == hostname and h.fn2 == fn2 and h.generation == generation and h.status == t.name) for h in host_data)
                elt = SubElement(tr, "td")
                if value > 0:
                  elt.set("class", t.mood)
                  elt.text = str(value)
      tr = SubElement(tbody, "tr")
      SubElement(tr, "td").text = "Total"
      for t in totals:
        if t.show:
          value = sum(int(h.hostname == hostname and h.status == t.name) for h in host_data)
          elt = SubElement(tr, "td")
          if value > 0:
            elt.set("class", t.mood)
            elt.text = str(value)

  if show_problems:

    SubElement(body, "br")
    SubElement(body, "h2").text = "Problems"
    table = SubElement(body, "table", { "class" : "problems", "rules" : "all", "border" : "1"})
    thead = SubElement(table, "thead")
    tr = SubElement(thead, "tr")
    for c in ("Status", "URI"):
      elt = SubElement(tr, "td", { "class" : c.lower() })
      SubElement(elt, "b").text = c
    tbody = SubElement(table, "tbody")
    for h in host_data:
      if h.mood != "good":
        tr = SubElement(tbody, "tr", { "class" : h.mood })
        SubElement(tr, "td", { "class" : "status" }).text = h.label.text
        SubElement(tr, "td", { "class" : "uri" }).text = h.uri
  
  if show_detailed_status:

    SubElement(body, "br")
    SubElement(body, "h2").text = "Validation Status"
    table = SubElement(body, "table", { "class" : "details", "rules" : "all", "border" : "1"})
    thead = SubElement(table, "thead")
    tr = SubElement(thead, "tr")
    for c in ("Timestamp", "Generation", "Status", "URI"):
      elt = SubElement(tr, "td", { "class" : c.lower() })
      SubElement(elt, "b").text = c
    tbody = SubElement(table, "tbody")
    for h in host_data:
      tr = SubElement(tbody, "tr", { "class" : h.mood })
      SubElement(tr, "td", { "class" : "timestamp" }).text = h.timestamp
      SubElement(tr, "td", { "class" : "generation" }).text = h.generation
      SubElement(tr, "td", { "class" : "status" }).text = h.label.text
      SubElement(tr, "td", { "class" : "uri" }).text = h.uri

ElementTree(element = html).write(sys.stdout)
