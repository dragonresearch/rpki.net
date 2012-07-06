"""
Flat text summary of rcynic.xml.

$Id$

Copyright (C) 2012 Internet Systems Consortium, Inc. ("ISC")

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
import textwrap

try:
  from lxml.etree            import ElementTree
except ImportError:
  from xml.etree.ElementTree import ElementTree

class Label(object):

  def __init__(self, elt):
    self.tag = elt.tag
    self.width = max(len(s) for s in elt.text.split())
    self.lines = textwrap.wrap(elt.text.strip(), width = self.width)
    self.counter = 0

  def line(self, n):
    try:
      return " " + self.lines[n].center(self.width) + " "
    except IndexError:
      return " " * (self.width + 2)

  def add(self):
    self.counter += 1

  @property
  def total(self):
    return " " + str(self.counter).rjust(self.width) + " "

  @property
  def visible(self):
    return self.counter > 0

class Host(object):

  def __init__(self):
    self.counters = {}

  def add(self, label):
    self.counters[label] = self.counters.get(label, 0) + 1
    label.add()

  def total(self, label):
    if label in self.counters:
      return " " + str(self.counters[label]).rjust(label.width) + " "
    else:
      return " " * (label.width + 2)

class Session(object):

  def __init__(self, labels):
    self.hosts = {}
    self.labels = labels
    self.map = dict((label.tag, label) for label in labels)

  def add(self, elt):
    label = self.map[elt.get("status")]
    hostname = urlparse.urlparse(elt.text.strip()).hostname
    if hostname not in self.hosts:
      self.hosts[hostname] = Host()
    self.hosts[hostname].add(label)

  def show(self):
    visible = [label for label in self.labels if label.visible]
    hostnames = sorted(hostname for hostname in self.hosts if hostname is not None)
    hostwidth = max(len(hostname) for hostname in hostnames + ["Hostname"])
    separator = "+-%s-+-%s-+" % (
      "-" * hostwidth, 
      "-+-".join("-" * label.width for label in visible))
    print separator
    for i in xrange(max(len(label.lines) for label in visible)):
      print "| %s |%s|" % (
        ("Hostname" if i == 0 else "").ljust(hostwidth),
        "|".join(label.line(i) for label in visible))
    print separator
    for hostname in hostnames:
      print "| %s |%s|" % (
        hostname.ljust(hostwidth),
        "|".join(self.hosts[hostname].total(label) for label in visible))
    if hostnames:
      print separator
    print "| %s |%s|" % (
        "Total".ljust(hostwidth),
        "|".join(label.total for label in visible))
    print separator


def main():
  for filename in ([sys.stdin] if len(sys.argv) < 2 else sys.argv[1:]):
    etree = ElementTree(file = filename)
    session = Session([Label(elt) for elt in etree.find("labels")])
    for elt in etree.findall("validation_status"):
      session.add(elt)
    session.show()

if __name__ == "__main__":
  main()
