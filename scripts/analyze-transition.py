"""
Compare rcynic.xml files, tell the user what became invalid, and why.

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

try:
  from lxml.etree            import ElementTree
except ImportError:
  from xml.etree.ElementTree import ElementTree

class Object(object):

  def __init__(self, session, uri, generation):
    self.session = session
    self.uri = uri
    self.generation = generation
    self.labels = []

  def add(self, label):
    self.labels.append(label)

  def __cmp__(self, other):
    return cmp(self.labels, other.labels)

  @property
  def valid(self):
    return "object_accepted" in self.labels

class Session(dict):

  def __init__(self, name):
    self.name = name
    tree = ElementTree(file = name)
    labels = tuple((elt.tag.strip(), elt.text.strip()) for elt in tree.find("labels"))
    self.labels = tuple(pair[0] for pair in labels)
    self.descrs = dict(labels)
    self.date = tree.getroot().get("date")
    for elt in tree.findall("validation_status"):
      generation = elt.get("generation")
      status = elt.get("status")
      uri = elt.text.strip()
      if status.startswith("rsync_transfer_") or generation == "backup":
        continue
      if uri not in self:
        self[uri] = Object(self, uri, generation)
      self[uri].add(status)

old_db = new_db = None

for arg in sys.argv[1:]:

  old_db = new_db
  new_db = Session(arg)
  if old_db is None:
    continue

  for uri in sorted(set(old_db) - set(new_db)):
    print new_db.date, uri, "dropped"

  for uri in sorted(set(old_db) & set(new_db)):
    old = old_db[uri]
    new = new_db[uri]
    if old.valid and not new.valid:
      print new_db.date, uri, "invalid", " ".join(sorted(set(new.labels) - set(old.labels) - set(("object_accepted", "object_rejected"))))
