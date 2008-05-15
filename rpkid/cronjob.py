# $Id$

# Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
Tool to trigger "cron" runs in rpkid.

Usage: python cronjob.py [ { -c | --config } configfile ]
                         [ { -d | --debug  } ]
                         [ { -h | --help   } ]

Default configuration file is cronjob.conf, override with --config option.
"""

import rpki.config, rpki.https, getopt, sys

cfg_file = "cronjob.conf"
debug = False

opts,argv = getopt.getopt(sys.argv[1:], "c:h?", ["config=", "help"])
for o,a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  elif o in ("-c", "--config"):
    cfg_file = a
  elif o in ("-d", "--debug"):
    debug = True
if argv:
  print __doc__
  raise RuntimeError, "Unexpected arguments %s" % argv

cfg = rpki.config.parser(cfg_file, "cronjob")

if debug:
  rpki.log.init("cronjob")
  rpki.log.set_trace(True)

irbe_key   = rpki.x509.RSA( Auto_file = cfg.get("irbe-key"))
irbe_cert  = rpki.x509.X509(Auto_file = cfg.get("irbe-cert"))
bpki_ta    = rpki.x509.X509(Auto_file = cfg.get("bpki-ta"))
rpkid_cert = rpki.x509.X509(Auto_file = cfg.get("rpkid-cert"))

print rpki.https.client(client_key   = irbe_key,
                        client_cert  = irbe_cert,
                        server_ta    = (bpki_ta, rpkid_cert),
                        url          = cfg.get("https-url"),
                        msg          = "Please run cron now.")
