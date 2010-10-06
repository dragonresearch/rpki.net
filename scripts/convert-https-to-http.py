"""
Conversion tool for flag day on which we rip TLS (HTTPS) support out
of rpkid and friends.

Usage: python convert-https-to-http.py [ { -c | --config } configfile ]
                                       [ { -e | --entitydb } entitydbdir ]
                                       [ { -h | --help } ]

Default configuration file is myrpki.conf, override with --config option.

$Id$

Copyright (C) 2010  Internet Systems Consortium ("ISC")

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

import getopt, sys, os, warnings, lxml.etree, rpki.config

cfg_file = "myrpki.conf"
entitydb_dir = "entitydb"
convert_sql = True

opts, argv = getopt.getopt(sys.argv[1:], "c:e:h?", ["config=", "entitydb=", "help"])
for o, a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  elif o in ("-c", "--config"):
    cfg_file = a
  elif o in ("-e", "--entitydb"):
    entitydb_dir = a
if argv:
  sys.exit("Unexpected arguments %s" % argv)

print "Checking", cfg_file
f = open(cfg_file + ".new", "w")
for line in open(cfg_file, "r"):
  cmd, sep, comment = line.partition("#")
  if "https" in cmd:
    line = cmd.replace("https", "http") + sep + comment
    print "Rewrote line:", " ".join(line.split())
  f.write(line)
f.close()
os.rename(cfg_file + ".new", cfg_file)

def localname(s):
  return s.partition("}")[-1]

for root, dirs, files in os.walk(entitydb_dir):
  for filename in files:
    if filename.endswith(".xml"):
      filename = os.path.join(root, filename)
      print "Checking", filename
      tree = lxml.etree.ElementTree(file = filename)
      changed = False
      for e in tree.getiterator():
        p = e.getparent()
        if (e.tag in ("{http://www.hactrn.net/uris/rpki/myrpki/}bpki_https_cert",
                      "{http://www.hactrn.net/uris/rpki/myrpki/}bpki_https_glue",
                      "{http://www.hactrn.net/uris/rpki/myrpki/}bpki_https_certificate") or
            (e.tag == "{http://www.hactrn.net/uris/rpki/myrpki/}bpki_server_ta" and
             p.tag == "{http://www.hactrn.net/uris/rpki/myrpki/}parent")):
          print "Deleting element %s/%s" % (localname(p.tag), localname(e.tag))
          p.remove(e)
          changed = True
          continue
        for k, v in e.items():
          if v.startswith("https://"):
            e.set(k, v.replace("https://", "http://"))
            print "Rewrote attribute %s/@%s to %s" % (localname(e.tag), k, e.get(k))
            changed = True
      if changed:
        tree.write(filename + ".new")
        os.rename(filename + ".new", filename)


# Automatic conversion of SQL is particularly dangerous, so we only do it on request

if convert_sql:

  if hasattr(warnings, "catch_warnings"):
    with warnings.catch_warnings():
      warnings.simplefilter("ignore", DeprecationWarning)
      import MySQLdb
  else:
    import MySQLdb

  cfg = rpki.config.parser(cfg_file, "myrpki")

  print "Converting SQL tables"

  def do_sql(section, *cmds):
    if cfg.getboolean("run_" + section):
      db = MySQLdb.connect(user   = cfg.get("sql-username", section = section),
                           db     = cfg.get("sql-database", section = section),
                           passwd = cfg.get("sql-password", section = section))
      cur = db.cursor()
      ok = True
      for cmd in cmds:
        try:
          print "SQL[%s]: %s" % (section, cmd)
          cur.execute(cmd)
        except MySQLdb.Error, e:
          print str(e)
          ok = False
      if ok:
        print "SQL[%s]: Comitting" % section
        db.commit()
      else:
        print "SQL[%s]: NOT comitting due to previous errors" % section
      db.close()


  do_sql("rpkid",
         "ALTER TABLE repository ADD COLUMN last_cms_timestamp DATETIME",
         "ALTER TABLE parent ADD COLUMN last_cms_timestamp DATETIME",
         "ALTER TABLE parent DROP COLUMN bpki_https_cert",
         "ALTER TABLE parent DROP COLUMN bpki_https_glue",
         "ALTER TABLE child ADD COLUMN last_cms_timestamp DATETIME",
         "ALTER TABLE ca CHANGE COLUMN parent_id parent_id BIGINT UNSIGNED NOT NULL")

  do_sql("pubd",
         "ALTER TABLE client ADD COLUMN last_cms_timestamp DATETIME")
