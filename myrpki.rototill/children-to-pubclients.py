"""
Convert children.csv to (initial) pubclients.csv.  You may wish to
play sort/join/etc games with the output of this to avoid overwriting
other publication clients you've configured.

$Id$

Copyright (C) 2009  Internet Systems Consortium ("ISC")

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

import sys, csv, myrpki, getopt, time, os, rpki.config

os.environ["TZ"] = "UTC"
time.tzset()

cfg_file = "myrpki.conf"

opts, argv = getopt.getopt(sys.argv[1:], "c:h?", ["config=", "help"])
for o, a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  if o in ("-c", "--config"):
    cfg_file = a

base = rpki.config.parser(cfg_file, "myirbe").get("rsync_base")

csv.writer(sys.stdout, dialect = myrpki.csv_dialect).writerows(
  (handle, cert, "%s/children/%s/" % (base.rstrip("/"), handle))
  for handle, expiration, cert in myrpki.csv_open("children.csv"))
