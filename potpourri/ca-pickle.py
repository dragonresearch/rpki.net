#!/usr/bin/env python

# $Id$

"""
Package up state of an old (pre-rpkidb, pre-pubdb, pre-Django 1.8)
RPKI CA installation as a Python pickle database, for later re-loading
into a more recent version of the code using a companion script.
"""

import os
import sys
import cPickle
import argparse
import subprocess
import rpki.config
import rpki.version
import rpki.autoconf

from rpki.mysql_import import MySQLdb, _mysql_exceptions

parser = argparse.ArgumentParser(description = __doc__)
parser.add_argument("-c", "--config",
                    help = "specify alternate location for rpki.conf")
parser.add_argument("-p", "--protocol",
                    choices = (0, 1, 2), type = int, default = 2,
                    help = "pickling protocol to use")
parser.add_argument("output",
                    help = "output file")
args = parser.parse_args()

cfg = rpki.config.parser(args.config)

databases = {}

for section in ("rpkid", "irdbd", "pubd"):
    db = MySQLdb.connect(db     = cfg.get(section = section, option = "sql-database"),
                         user   = cfg.get(section = section, option = "sql-username"),
                         passwd = cfg.get(section = section, option = "sql-password"))
    tables = {}

    cur = db.cursor()
    cur.execute("SHOW TABLES")
    table_names = tuple(row[0] for row in cur.fetchall())
    cur.close()

    cur = db.cursor(MySQLdb.cursors.DictCursor)
    for name in table_names:
        cur.execute("SELECT * FROM " + name)
        tables[name] = cur.fetchall()
    cur.close()

    db.close()

    databases[section] = tables

filenames     = [cfg.filename]
raw_config    = dict((section, {}) for section in cfg.cfg.sections())
cooked_config = dict((section, {}) for section in cfg.cfg.sections())

for section in cfg.cfg.sections():
    for option in cfg.cfg.options(section):
        raw_config   [section][option] = cfg.cfg.get(section = section, option = option)
        cooked_config[section][option] =     cfg.get(section = section, option = option)
        if os.path.isfile(   cooked_config[section][option]):
            filenames.append(cooked_config[section][option])

# Sigh, even here we need special hacks for rootd, which handles filenames a bit differently.
rootd_dir = cfg.get(section = "rootd", option = "rpki-root-dir", default = "")
for option in ("rpki-root-crl", "rpki-root-manifest", "rpki-subject-cert"):
    fn = os.path.join(rootd_dir, cfg.get(section = "rootd", option = option, default = ""))
    if os.path.isfile(fn):
        filenames.append(fn)

for i, fn in enumerate(filenames):
    filenames[i] = os.path.abspath(fn)

files = {}

for filename in filenames:
    with open(filename, "rb") as f:
        files[filename] = f.read()

world = dict(
    VERSION   = rpki.version.VERSION,
    RPKI_CONF = filenames[0],
    db        = databases,
    file      = files,
    raw       = raw_config,
    cfg       = cooked_config)

xz = subprocess.Popen(
    ("xz", "-C", "sha256"),
    stdin = subprocess.PIPE,
    stdout = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0600))

cPickle.dump(world, xz.stdin, args.protocol)

xz.stdin.flush()
xz.stdin.close()

if xz.wait() != 0:
    sys.exit("XZ pickling failed with code {}".format(xz.returncode))
