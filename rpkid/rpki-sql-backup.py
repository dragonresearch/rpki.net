"""
Back up data from SQL databases, looking at config file to figure out
which databases and what credentials to use with them.

For the moment, this just writes all the SQL to stdout.

$Id$

Copyright (C) 2010-2012 Internet Systems Consortium ("ISC")

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

import subprocess, os, getopt, sys, time, rpki.config

os.environ["TZ"] = "UTC"
time.tzset()

cfg_file = None

opts, argv = getopt.getopt(sys.argv[1:], "c:h?", ["config=", "help"])
for o, a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  elif o in ("-c", "--config"):
    cfg_file = a

cfg = rpki.config.parser(cfg_file, "myrpki")

def dump(section):
  subprocess.check_call(
    ("mysqldump", "--add-drop-database",
     "-u",  cfg.get("sql-username", section = section),
     "-p" + cfg.get("sql-password", section = section),
     "-B",  cfg.get("sql-database", section = section)))

if cfg.getboolean("start_rpkid", False):
  dump("irdbd")

if cfg.getboolean("start_irdbd", False):
  dump("rpkid")

if cfg.getboolean("start_pubd",  False):
  dump("pubd")
