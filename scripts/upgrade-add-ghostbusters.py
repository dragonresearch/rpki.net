"""
Add SQL tables needed for Ghostbusters support.
Most of the code here lifted from rpki-sql-setup.py

$Id$

Copyright (C) 2009--2011  Internet Systems Consortium ("ISC")

Permission to use, copy, modify, and distribute this software for any
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

import getopt, sys, rpki.config, warnings

from rpki.mysql_import import MySQLdb

def fix(name, *statements):
  db = MySQLdb.connect(db     = cfg.get("sql-database", section = name),
                       user   = cfg.get("sql-username", section = name),
                       passwd = cfg.get("sql-password", section = name))
  cur = db.cursor()
  for statement in statements:
    cur.execute(statement)
  db.commit()
  db.close()

cfg_file = None

opts, argv = getopt.getopt(sys.argv[1:], "c:h?", ["config=", "help"])
for o, a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  if o in ("-c", "--config"):
    cfg_file = a

cfg = rpki.config.parser(cfg_file, "myrpki")

fix("irdbd", """
    CREATE TABLE ghostbuster_request (
            ghostbuster_request_id  SERIAL NOT NULL,
            self_handle             VARCHAR(40) NOT NULL,
            parent_handle           VARCHAR(40),
            vcard                   LONGBLOB NOT NULL,
            PRIMARY KEY             (ghostbuster_request_id)
    ) ENGINE=InnoDB;
""")

fix("rpkid", """
    CREATE TABLE ghostbuster (
            ghostbuster_id          SERIAL NOT NULL,
            vcard                   LONGBLOB NOT NULL,
            cert                    LONGBLOB NOT NULL,
            ghostbuster             LONGBLOB NOT NULL,
            published               DATETIME,
            self_id                 BIGINT UNSIGNED NOT NULL,
            ca_detail_id            BIGINT UNSIGNED NOT NULL,
            PRIMARY KEY             (ghostbuster_id),
            CONSTRAINT              ghostbuster_self_id
            FOREIGN KEY             (self_id) REFERENCES self (self_id) ON DELETE CASCADE,
            CONSTRAINT              ghostbuster_ca_detail_id
            FOREIGN KEY             (ca_detail_id) REFERENCES ca_detail (ca_detail_id) ON DELETE CASCADE
    ) ENGINE=InnoDB;
""")
