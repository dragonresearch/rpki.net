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

import getopt, sys, os
from xml.etree.ElementTree import (Element, SubElement, ElementTree)

cfg_file = "myrpki.conf"
entitydb_dir = "entitydb"

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

f = open(cfg_file + ".new", "w")
for line in open(cfg_file, "r"):
  cmd, sep, comment = line.partition("#")
  if "https" in cmd:
    line = cmd.replace("https", "http") + sep + comment
  f.write(line)
f.close()
os.rename(cfg_file + ".new", cfg_file)

for root, dirs, files in os.walk(entitydb_dir):
  for filename in files:
    if filename.endswith(".xml"):
      filename = os.path.join(root, filename)
      tree = ElementTree(file = filename).getroot()
      changed = False
      for e in tree.getiterator():
        for k, v in e.items():
          if v.startswith("https://"):
            e.set(k, v.replace("https://", "http://"))
            changed = True
      if changed:
        ElementTree(tree).write(filename + ".new")
        os.rename(filename + ".new", filename)
