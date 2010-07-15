"""
Debugging tool for chasing a particular weird ROA problem.

Usage: python debug-roas.py [ { -c | --config } configfile ]
                            [ { -h | --help } ]

Default configuration file is rpkid.conf, override with --config option.

$Id$

Copyright (C) 2009-2010  Internet Systems Consortium ("ISC")

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

Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import os, time, getopt, sys, re
import rpki.sql, rpki.config, rpki.log, rpki.rpki_engine, rpki.left_right

class main(object):

  def __init__(self):

    os.environ["TZ"] = "UTC"
    time.tzset()

    rpki.log.use_syslog = False
    rpki.log.init("debug-roas")

    cfg_file = "rpkid.conf"

    opts, argv = getopt.getopt(sys.argv[1:], "c:h?", ["config=", "help"])
    for o, a in opts:
      if o in ("-h", "--help", "-?"):
        print __doc__
        sys.exit(0)
      elif o in ("-c", "--config"):
        cfg_file = a
    if argv:
      raise rpki.exceptions.CommandParseFailure, "Unexpected arguments %s" % argv

    self.sql = rpki.sql.session(rpki.config.parser(cfg_file, "rpkid"))

    for s in rpki.left_right.self_elt.sql_fetch_all(self):

      print "Examining <self self_handle=%r/>" % s.self_handle

      for r in s.roas():

        v4 = r.ipv4.to_resource_set() if r.ipv4 is not None else rpki.resource_set.resource_set_ipv4()
        v6 = r.ipv6.to_resource_set() if r.ipv6 is not None else rpki.resource_set.resource_set_ipv6()

        print "  Found ROA %r %s" % (r, "<%s %s>" % (r.asn, ("%s,%s" % (v4, v6)).strip(",")))

main()
