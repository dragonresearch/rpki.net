"""
Automated setup of all the pesky SQL stuff we need.  Prompts for MySQL
root password, pulls other information from rpki.conf.

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

from __future__ import with_statement

import os, getopt, sys, rpki.config, getpass, warnings

# Silence warning while loading MySQLdb in Python 2.6, sigh
if hasattr(warnings, "catch_warnings"):
  with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    import MySQLdb
else:
  import MySQLdb

import _mysql_exceptions

warnings.simplefilter("error", _mysql_exceptions.Warning)

schema_dir = os.path.normpath(sys.path[0])

def read_schema(filename):
  """
  Convert an SQL file into a list of SQL statements.
  """
  lines = []
  f = open(filename)
  for line in f:
    line = " ".join(line.split())
    if line and not line.startswith("--"):
      lines.append(line)
  f.close()
  return [statement.strip() for statement in " ".join(lines).rstrip(";").split(";")]

def sql_setup(name):
  """
  Create a new SQL database and construct all its tables.
  """
  database = cfg.get("sql-database", section = name)
  username = cfg.get("sql-username", section = name)
  password = cfg.get("sql-password", section = name)
  schema = read_schema(os.path.join(schema_dir, "%s.sql" % name))

  print "Creating database", database
  cur = rootdb.cursor()
  try:
    cur.execute("DROP DATABASE IF EXISTS %s" %  database)
  except:
    pass
  cur.execute("CREATE DATABASE %s" % database)
  cur.execute("GRANT ALL ON %s.* TO %s@localhost IDENTIFIED BY %%s" % (database, username), (password,))
  rootdb.commit()

  db = MySQLdb.connect(db = database, user = username, passwd = password)
  cur = db.cursor()
  for statement in schema:
    if statement.upper().startswith("DROP TABLE"):
      continue
    if verbose:
      print "+", statement
    cur.execute(statement)
  db.commit()
  db.close()

cfg_file = None

verbose = False

opts, argv = getopt.getopt(sys.argv[1:], "c:hv?", ["config=", "help", "verbose"])
for o, a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  if o in ("-v", "--verbose"):
    verbose = True
  if o in ("-c", "--config"):
    cfg_file = a

cfg = rpki.config.parser(cfg_file, "myrpki")

rootdb = MySQLdb.connect(db = "mysql", user = "root", passwd = getpass.getpass("Please enter your MySQL root password: "))

sql_setup("irdbd")
sql_setup("rpkid")

if cfg.getboolean("run_pubd", False):
  sql_setup("pubd")

rootdb.close()
