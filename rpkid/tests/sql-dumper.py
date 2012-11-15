"""
Dump backup copies of SQL tables used by these programs.

$Id$

Copyright (C) 2009--2012 Internet Systems Consortium ("ISC")

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

import subprocess
import rpki.config
from rpki.mysql_import import MySQLdb

cfg = rpki.config.parser(None, "yamltest", allow_missing = True)

for name in ("rpkid", "irdbd", "pubd"):

  username = cfg.get("%s_sql_username" % name, name[:4])
  password = cfg.get("%s_sql_password" % name, "fnord")

  cmd = ["mysqldump", "-u", username, "-p" + password, "--databases"]

  db = MySQLdb.connect(user = username, passwd = password)
  cur = db.cursor()

  cur.execute("SHOW DATABASES")
  cmd.extend(r[0] for r in cur.fetchall() if r[0][:4] == name[:4] and r[0][4:].isdigit())

  cur.close()
  db.close()

  subprocess.check_call(cmd, stdout = open("backup.%s.sql" % name, "w"))
