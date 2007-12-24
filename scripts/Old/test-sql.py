# $Id$

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
