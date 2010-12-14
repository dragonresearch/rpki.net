"""
RPKI engine daemon.

Usage: python rpkid.py [ { -c | --config } configfile ]
                       [ { -h | --help } ]
                       [ { -p | --profile } outputfile ]

Default configuration file is rpkid.conf, override with --config option.

$Id$

Copyright (C) 2009--2010  Internet Systems Consortium ("ISC")

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

import os, time, getopt, sys
import rpki.resource_set, rpki.up_down, rpki.left_right, rpki.x509, rpki.sql
import rpki.http, rpki.config, rpki.exceptions, rpki.relaxng, rpki.log
import rpki.rpki_engine

class main(object):
  """
  Main program for rpkid.  This class probably ought to be merged with
  rpki.rpki_engine.rpkid_context, but that can wait, for today the
  task is to move all the real code out of the scripts, this is the
  minimal necessary change to do that.
  """

  def __init__(self):

    os.environ["TZ"] = "UTC"
    time.tzset()

    self.cfg_file = "rpkid.conf"
    self.profile = None

    opts, argv = getopt.getopt(sys.argv[1:], "c:dhp:?", ["config=", "debug", "help", "profile="])
    for o, a in opts:
      if o in ("-h", "--help", "-?"):
        print __doc__
        sys.exit(0)
      elif o in ("-d", "--debug"):
        rpki.log.use_syslog = False
      elif o in ("-c", "--config"):
        self.cfg_file = a
      elif o in ("-p", "--profile"):
        self.profile = a
    if argv:
      raise rpki.exceptions.CommandParseFailure, "Unexpected arguments %s" % argv

    rpki.log.init("rpkid")

    if self.profile:
      import cProfile
      cProfile.run("self.main()", self.profile)
    else:
      self.main()

  def main(self):

    self.cfg = rpki.config.parser(self.cfg_file, "rpkid")

    startup_msg = self.cfg.get("startup-message", "")
    if startup_msg:
      rpki.log.info(startup_msg)

    if self.profile:
      rpki.log.info("Running in profile mode with output to %s" % self.profile)

    self.cfg.set_global_flags()

    gctx = rpki.rpki_engine.rpkid_context(self.cfg)

    gctx.start_cron()

    rpki.http.server(
      host     = gctx.http_server_host,
      port     = gctx.http_server_port,
      handlers = (("/left-right", gctx.left_right_handler),
                  ("/up-down/",   gctx.up_down_handler),
                  ("/cronjob",    gctx.cronjob_handler)))
