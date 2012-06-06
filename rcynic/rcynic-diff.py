"""
Diff a series of rcynic.xml files, sort of.

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

show_backup_generation = False

class Object(object):

  def __init__(self, uri, generation):
    self.uri = uri
    self.generation = generation
    self.labels = []

  def add(self, label):
    self.labels.append(label)

  def __cmp__(self, other):
    return cmp(self.labels, other.labels)

  def show(self):
    if show_backup_generation:
      print " ", self.uri, self.generation, ",".join(self.labels)
    else:
      print " ", self.uri, ",".join(self.labels)

class Session(dict):

  def __init__(self, name):
    self.name = name
    for elt in ElementTree(file = name).findall("validation_status"):
      generation = elt.get("generation")
      status = elt.get("status")
      uri = elt.text.strip()
      if show_backup_generation:
        key = (uri, generation)
      elif generation == "backup":
        continue
      else:
        key = uri
      if key not in self:
        self[key] = Object(uri, generation)
      self[key].add(status)

old_db = new_db = None

for arg in sys.argv[1:]:

  old_db = new_db
  new_db = Session(arg)

  if old_db is None:
    continue

  only_old = set(old_db) - set(new_db)
  only_new = set(new_db) - set(old_db)
  common   = set(old_db) & set(new_db)

  if only_old or common or only_new:
    print "Comparing", old_db.name, "with", new_db.name
    print

  if only_old:
    print "Only in", old_db.name
    for key in sorted(only_old):
      old_db[key].show()
    print

  for key in sorted(common):
    if old_db[key] != new_db[key]:
      print "Changed:"
      old_db[key].show()
      new_db[key].show()
      print

  if only_new:
    print "Only in", new_db.name
    for key in sorted(only_new):
      new_db[key].show()
    print
