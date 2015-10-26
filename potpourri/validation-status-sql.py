#!/usr/bin/env python

# $Id$
#
# Copyright (C) 2013-2014 Dragon Research Labs ("DRL")
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

class Parser(object):

    @staticmethod
    def main():
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
                            help = "SQLite3 database")
        parser.add_argument("--path-within-tarball",
                            default = "var/rcynic/data/rcynic.xml",
                            help = "rcynic.xml path name within tarball(s)")
        parser.add_argument("--tar-extensions", nargs = "+",
                            default = ".tar .tar.gz .tgz .tar.bz2 .tbz .tar.xz .txz".split(),
                            help = "extensions to recognize as indicating tar files")
        args = parser.parse_args()
        if args.mailbox:
            ParserMailbox(args)
        else:
            ParserTarball(args)

    def __init__(self, args):
        self.args = args
        self.init_sql()
        self.init_hook()
        self.index1()
        self.parsed = 1
        for self.current, self.iterval in enumerate(self.iterator, 1):
            self.parse_xml()
        if self.parsed > 1:
            sys.stderr.write("\n")
        self.index2()
        self.db.close()


    def init_sql(self):
        creating = not os.path.exists(self.args.database)
        self.db = sqlite3.connect(self.args.database)
        self.db.text_factory = str
        self.db.executescript('''
          PRAGMA foreign_keys  = off;
          PRAGMA synchronous   = off;
          PRAGMA count_changes = off;
          ''')

        if creating:
            self.db.executescript('''
                CREATE TABLE sessions (
                      session_id      INTEGER PRIMARY KEY NOT NULL,
                      session         DATETIME NOT NULL,
                      handle          TEXT NOT NULL
                );

                CREATE TABLE uris (
                      uri_id          INTEGER PRIMARY KEY NOT NULL,
                      uri             TEXT NOT NULL
                );

                CREATE TABLE codes (
                      code_id         INTEGER PRIMARY KEY NOT NULL,
                      code            TEXT NOT NULL
                );

                CREATE TABLE generations (
                      generation_id   INTEGER PRIMARY KEY NOT NULL,
                      generation      TEXT NOT NULL
                );

                CREATE TABLE events (
                      id              INTEGER PRIMARY KEY NOT NULL,
                      timestamp       DATETIME NOT NULL,
                      session_id      INTEGER NOT NULL REFERENCES sessions    (session_id)      ON DELETE RESTRICT ON UPDATE RESTRICT,
                      generation_id   INTEGER NOT NULL REFERENCES generations (generation_id)   ON DELETE RESTRICT ON UPDATE RESTRICT,
                      code_id         INTEGER NOT NULL REFERENCES codes       (code_id)         ON DELETE RESTRICT ON UPDATE RESTRICT,
                      uri_id          INTEGER NOT NULL REFERENCES uris        (uri_id)          ON DELETE RESTRICT ON UPDATE RESTRICT
                );

                CREATE VIEW status AS
                     SELECT id, handle, session, timestamp, generation, code, uri
                     FROM               events
                     NATURAL JOIN       sessions
                     NATURAL JOIN       uris
                     NATURAL JOIN       codes
                     NATURAL JOIN       generations;
                ''')


    def index1(self):
        self.db.executescript('''
          CREATE UNIQUE INDEX IF NOT EXISTS sessions_index         ON sessions     (session);
          CREATE UNIQUE INDEX IF NOT EXISTS handles_index          ON sessions     (handle);
          CREATE UNIQUE INDEX IF NOT EXISTS uris_index             ON uris         (uri);
          CREATE UNIQUE INDEX IF NOT EXISTS codes_index            ON codes        (code);
          CREATE UNIQUE INDEX IF NOT EXISTS generations_index      ON generations  (generation);
          ''')


    def index2(self):
        self.db.executescript('''
          CREATE UNIQUE INDEX IF NOT EXISTS events_index           ON events       (uri_id, timestamp, code_id, generation_id);
          ''')


    def string_id(self, table, value):
        field = table.rstrip("s")
        try:
            return self.db.execute("SELECT %s_id FROM %s WHERE %s = ?" % (field, table, field), (value,)).fetchone()[0]
        except:
            return self.db.execute("INSERT INTO %s (%s) VALUES (?)" % (table, field), (value,)).lastrowid


    def parse_xml(self):
        sys.stderr.write("\r%s %d/%d/%d...%s   " % ("|\\-/"[self.current & 3],
                                                    self.current, self.parsed, self.total, self.handle))
        if self.db.execute("SELECT handle FROM sessions WHERE handle = ?", (self.handle,)).fetchone():
            return
        xml = self.read_xml()
        with self.db:
            session_id = self.db.execute("INSERT INTO sessions (session, handle) VALUES (strftime('%s', ?), ?)",
                                         (xml.get("date"), self.handle)).lastrowid
            self.db.executemany("INSERT INTO events (session_id, timestamp, generation_id, code_id, uri_id) "
                                "VALUES (?, strftime('%s', ?), ?, ?, ?)",
                                ((session_id,
                                  x.get("timestamp"),
                                  self.string_id("generations", x.get("generation", "none")),
                                  self.string_id("codes",       x.get("status")),
                                  self.string_id("uris",        x.text.strip()))
                                 for x in xml.findall("validation_status")))
        self.parsed += 1


class ParserTarball(Parser):

    def init_hook(self):
        self.total = 0
        for fn in self.iter_tarball_names():
            self.total += 1
        self.iterator = self.iter_tarball_names()

    @property
    def handle(self):
        return self.iterval

    def read_xml(self):
        return lxml.etree.ElementTree(
            file = subprocess.Popen(("tar", "Oxf", self.iterval, self.args.path_within_tarball),
                                    stdout = subprocess.PIPE).stdout).getroot()

    def iter_tarball_names(self):
        if os.path.isdir(self.args.tarballs):
            for root, dirs, files in os.walk(self.args.tarballs):
                for fn in files:
                    if any(fn.endswith(ext) for ext in self.args.tar_extensions):
                        yield os.path.join(root, fn)
        else:
            yield self.args.tarballs


class ParserMailbox(Parser):

    def init_hook(self):
        self.mb = mailbox.Maildir(self.args.mailbox, factory = None, create = False)
        self.total = len(self.mb)
        self.iterator = self.mb.iterkeys()

    @property
    def handle(self):
        return self.mb[self.iterval].get("Message-ID")

    def read_xml(self):
        return lxml.etree.XML(self.mb[self.iterval].get_payload())


if __name__ == "__main__":
    try:
        Parser.main()
    except KeyboardInterrupt:
        pass
