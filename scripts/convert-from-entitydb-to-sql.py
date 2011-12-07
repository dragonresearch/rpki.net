"""
Merge XML entitydb and OpenSSL command-line BPKI into SQL IRDB.

This is a work in progress, don't use it unless you really know what
you're doing.

$Id$

Copyright (C) 2011  Internet Systems Consortium ("ISC")

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

import sys, os, time, getopt
import rpki.config
from rpki.mysql_import import MySQLdb
from lxml.etree import ElementTree

if os.getlogin() != "sra":
  sys.exit("I //said// this was a work in progress")

cfg_file = "rpki.conf"
entitydb = "entitydb"

opts, argv = getopt.getopt(sys.argv[1:], "c:e:h?", ["config=", "entitydb=", "help"])
for o, a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  if o in ("-c", "--config"):
    cfg_file = a
  elif o in ("-e", "--entitydb"):
    entitydb = a
if argv:
  sys.exit("Unexpected arguments %s" % argv)

cfg = rpki.config.parser(cfg_file, "irdbd")

sql_database = cfg.get("sql-database")
sql_username = cfg.get("sql-username")
sql_password = cfg.get("sql-password")

db = MySQLdb.connect(user = sql_username, db = sql_database, passwd = sql_password)
cur = db.cursor()

cur.execute("SHOW TABLES")

tables = [r[0] for r in cur.fetchall()]

for table in tables:
  if "old_" + table not in tables and table in ("registrant",
                                                "registrant_asn",
                                                "registrant_net",
                                                "roa_request",
                                                "roa_request_prefix",
                                                "ghostbuster_request"):
    print "Renaming %s to old_%s" % (table, table)
    cur.execute("ALTER TABLE %s RENAME TO old_%s" % (table, table))

from django.conf import settings

settings.configure(
  DATABASES = { "default" : {
    "ENGINE"   : "django.db.backends.mysql",
    "NAME"     : sql_database,
    "USER"     : sql_username,
    "PASSWORD" : sql_password,
    "HOST"     : "",
    "PORT"     : "" }},
  INSTALLED_APPS = ("rpki.irdb",),
)

import rpki.irdb

import django.core.management

django.core.management.call_command("syncdb", verbosity = 4)

def ns(tag):
  return "{http://www.hactrn.net/uris/rpki/myrpki/}" + tag

e = ElementTree(file = os.path.join(entitydb, "identity.xml")).getroot()

t = ns("identity")

if e.tag == t:
  print "Found", t, "handle", e.get("handle")
else:
  print "Didn't find", t, "found", e.tag, "instead, oops"

cur.close()
db.close()
