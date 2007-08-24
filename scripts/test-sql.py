# $Id$

import MySQLdb, ConfigParser

cfg = ConfigParser.ConfigParser()
cfg.read("re.conf")

db = MySQLdb.connect(user = "rpki", db = "rpki", passwd = cfg.get("rpki", "password"))
cur = db.cursor()

def duh(cmd, header):
  cur.execute(cmd)
  print header
  print "-" * len(header)
  print cur.description
  for i in cur.fetchall():
    print i[0]
  print

duh("SHOW DATABASES", "Databases")

duh("SELECT DATABASE()", "Current database")

duh("USE rpki", "Select database")

duh("SELECT DATABASE()", "Current database")

duh("SHOW TABLES", "Current tables")

print MySQLdb.Timestamp(2007,6,9,9,45,51), MySQLdb.DateFromTicks(1000), MySQLdb.Binary("Hi, Mom!"), MySQLdb.STRING, MySQLdb.BINARY, MySQLdb.NUMBER, MySQLdb.NULL

cur.close()
db.close()
