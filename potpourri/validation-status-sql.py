#!/usr/bin/env python

# $Id$
#
# Copyright (C) 2013-2014 2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2011-2012  Internet Systems Consortium ("ISC")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL AND ISC DISCLAIM ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL DRL OR
# ISC BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
# DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA
# OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
# TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
Parse rcynic XML output, stuff the data that validation_status script
would print into an SQL database for subsequent analysis.
"""

import os
import sys
import time
import mailbox
import sqlite3
import argparse
import lxml.etree
import subprocess

parser = argparse.ArgumentParser(
  description     = __doc__,
  formatter_class = argparse.ArgumentDefaultsHelpFormatter)
group = parser.add_mutually_exclusive_group(required = True)
group.add_argument("--mailbox", "--mb",
                   help = "Maildir mailbox containing rcynic XML output")
group.add_argument("--tarballs",
                   help = "directory tree of tar files containing containing rcynic XML output")
parser.add_argument("--database", "--db",
                    default = "validation-status-sql.db",
                    help = "name for SQLite3 database")
parser.add_argument("--path-within-tarball",
                    default = "var/rcynic/data/rcynic.xml",
                    help = "name of file to extract from tarball(s)")
parser.add_argument("--tar-extensions", nargs = "+",
                    default = ".tar .tar.gz .tgz .tar.bz2 .tbz .tar.xz .txz".split(),
                    help = "extensions to recognize as indicating tar files")
args = parser.parse_args()

creating = not os.path.exists(args.database)
db = sqlite3.connect(args.database)
db.text_factory = str
db.execute("PRAGMA foreign_keys = on")

if creating:
  db.executescript('''
    CREATE TABLE sessions (
          id              INTEGER PRIMARY KEY NOT NULL,
          session         DATETIME NOT NULL,
          UNIQUE          (session));

    CREATE TABLE uris (
          id              INTEGER PRIMARY KEY NOT NULL,
          uri             TEXT NOT NULL,
          UNIQUE          (uri));

    CREATE TABLE codes (
          id              INTEGER PRIMARY KEY NOT NULL,
          code            TEXT NOT NULL,
          UNIQUE          (code));

    CREATE TABLE generations (
          id              INTEGER PRIMARY KEY NOT NULL,
          generation      TEXT,
          UNIQUE          (generation));

    CREATE TABLE events (
          id              INTEGER PRIMARY KEY NOT NULL,
          timestamp       DATETIME NOT NULL,
          session_id      INTEGER NOT NULL REFERENCES sessions(id)    ON DELETE RESTRICT ON UPDATE RESTRICT,
          generation_id   INTEGER NOT NULL REFERENCES generations(id) ON DELETE RESTRICT ON UPDATE RESTRICT,
          code_id         INTEGER NOT NULL REFERENCES codes(id)       ON DELETE RESTRICT ON UPDATE RESTRICT,
          uri_id          INTEGER NOT NULL REFERENCES uris(id)        ON DELETE RESTRICT ON UPDATE RESTRICT,
          UNIQUE          (timestamp, generation_id, code_id, uri_id));

    CREATE VIEW status AS
         SELECT events.id, session, timestamp, generation, uri, code
         FROM events
         JOIN sessions    ON sessions.id    = events.session_id
         JOIN uris        ON uris.id        = events.uri_id
         JOIN codes       ON codes.id       = events.code_id
         JOIN generations ON generations.id = events.generation_id;
    ''')


def string_id(table, value):
  field = table.rstrip("s")
  try:
    if value is None:
      return db.execute("SELECT id FROM %s WHERE %s IS NULL" % (table, field)).fetchone()[0]
    else:
      return db.execute("SELECT id FROM %s WHERE %s = ?" % (table, field), (value,)).fetchone()[0]
  except:
    return db.execute("INSERT INTO %s (%s) VALUES (?)" % (table, field), (value,)).lastrowid


def parse_xml(xml):
  try:
    session_id = db.execute("INSERT INTO sessions (session) VALUES (datetime(?))", (xml.get("date"),)).lastrowid
  except sqlite3.IntegrityError:
    return

  with db:
    db.executemany("INSERT INTO events (session_id, timestamp, generation_id, code_id, uri_id) VALUES (?, datetime(?), ?, ?, ?)",
                   ((session_id,
                     x.get("timestamp"),
                     string_id("generations", x.get("generation")),
                     string_id("codes", x.get("status")),
                     string_id("uris", x.text.strip()))
                    for x in xml.findall("validation_status")))


def parse_tarball(fn):
  print "Processing", fn
  parse_xml(lxml.etree.ElementTree(
    file = subprocess.Popen(("tar", "Oxf", fn, args.path_within_tarball), stdout = subprocess.PIPE).stdout).getroot())


if args.mailbox:
  mb = mailbox.Maildir(args.mailbox, factory = None, create = False)
  for i, key in enumerate(mb.iterkeys(), 1):
    sys.stderr.write("\r%s %d/%d..." % ("|\\-/"[i & 3], i, len(mb)))
    parse_xml(lxml.etree.XML(mb[key].get_payload()))
  sys.stderr.write("\n")

elif not os.path.isdir(args.tarballs):
  parse_tarball(args.tarballs)

else:
  if os.path.isdir(args.tarballs):
    for root, dirs, files in os.walk(args.tarballs):
      for fn in files:
        if any(fn.endswith(ext) for ext in args.tar_extensions):
          parse_tarball(os.path.join(root, fn))


db.close()
