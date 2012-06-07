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
show_rsync_transfer = False

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

def show(old = None, new = None):
  assert old is not None or new is not None
  assert old is None or new is None or old.uri == new.uri
  if old is None:
    obj = new
    labels = ["+" + label for label in new.labels]
  elif new is None:
    obj = old
    labels = ["-" + label for label in old.labels]
  else:
    obj = new
    labels = []
    for label in new.session.labels:
      if label in new.labels and label in old.labels:
        labels.append(label)
      elif label in new.labels:
        labels.append("+" + label)
      elif label in old.labels:
        labels.append("-" + label)
  labels = " ".join(labels)
  if show_backup_generation:
    print " ", obj.uri, obj.generation, labels
  else:
    print " ", obj.uri, labels

class Session(dict):

  def __init__(self, name):
    self.name = name
    tree = ElementTree(file = name)
    self.labels = [elt.tag.strip() for elt in tree.find("labels")]
    for elt in tree.findall("validation_status"):
      generation = elt.get("generation")
      status = elt.get("status")
      uri = elt.text.strip()
      if not show_rsync_transfer and status.startswith("rsync_transfer_"):
        continue
      if show_backup_generation:
        key = (uri, generation)
      elif generation == "backup":
        continue
      else:
        key = uri
      if key not in self:
        self[key] = Object(self, uri, generation)
      self[key].add(status)

old_db = new_db = None

for arg in sys.argv[1:]:

  old_db = new_db
  new_db = Session(arg)

  if old_db is None:
    continue

  only_old = set(old_db) - set(new_db)
  only_new = set(new_db) - set(old_db)
  changed =  set(key for key in (set(old_db) & set(new_db)) if old_db[key] != new_db[key])

  if only_old or changed or only_new:
    print "Comparing", old_db.name, "with", new_db.name
    for key in sorted(only_old):
      show(old = old_db[key])
    for key in sorted(changed):
      show(old = old_db[key], new = new_db[key])
    for key in sorted(only_new):
      show(new = new_db[key])
    print
