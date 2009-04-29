"""
RPKI engine daemon.  This is still very much a work in progress.

Usage: python rpkid.py [ { -c | --config } configfile ]
                       [ { -h | --help } ]
                       [ { -p | --profile } outputfile ]

Default configuration file is rpkid.conf, override with --config option.

$Id$

Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")

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
import rpki.https, rpki.config, rpki.exceptions, rpki.relaxng, rpki.log
import rpki.rpki_engine

os.environ["TZ"] = "UTC"
time.tzset()

rpki.log.init("rpkid")

cfg_file = "rpkid.conf"
profile = None

opts, argv = getopt.getopt(sys.argv[1:], "c:hp:?", ["config=", "help", "profile="])
for o, a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  elif o in ("-c", "--config"):
    cfg_file = a
  elif o in ("-p", "--profile"):
    profile = a
if argv:
  raise RuntimeError, "Unexpected arguments %s" % argv

def main():

  cfg = rpki.config.parser(cfg_file, "rpkid")

  startup_msg = cfg.get("startup-message", "")
  if startup_msg:
    rpki.log.info(startup_msg)

  if profile:
    rpki.log.info("Running in profile mode with output to %s" % profile)

  gctx = rpki.rpki_engine.rpkid_context(cfg)

  rpki.https.server(host                       = gctx.https_server_host,
                    port                       = gctx.https_server_port,
                    server_key                 = gctx.rpkid_key,
                    server_cert                = gctx.rpkid_cert,
                    dynamic_https_trust_anchor = gctx.build_https_ta_cache,
                    handlers                   = (("/left-right", gctx.left_right_handler),
                                                  ("/up-down/",   gctx.up_down_handler),
                                                  ("/cronjob",    gctx.cronjob_handler)))

if profile:
  import cProfile
  cProfile.run("main()", profile)
else:
  main()
