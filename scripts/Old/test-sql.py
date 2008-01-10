# $Id$

# Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

import MySQLdb, rpki.config

def test(filename, section):

  print "[Checking " + filename + "]\n"

  cfg = rpki.config.parser(filename, section)

  db = MySQLdb.connect(user   = cfg.get("sql-username"),
                       db     = cfg.get("sql-database"),
                       passwd = cfg.get("sql-password"))

  cur = db.cursor()

  def duh(db, cmd, header):
    cur.execute(cmd)
    print header
    print "-" * len(header)
    print cur.description
    for i in cur.fetchall():
      print i[0]
    print

  duh(db, "SHOW DATABASES", "Databases")
  duh(db, "SELECT DATABASE()", "Current database")
  duh(db, "SHOW TABLES", "Current tables")

  db.close()

print MySQLdb.Timestamp(2007,6,9,9,45,51), MySQLdb.DateFromTicks(1000), \
      MySQLdb.Binary("Hi, Mom!"), MySQLdb.STRING, MySQLdb.BINARY, MySQLdb.NUMBER, MySQLdb.NULL, "\n"

test("re.conf",   "rpki")
test("irbe.conf", "irdb")
