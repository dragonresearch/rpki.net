# $Id$

"""
Tool to trigger "cron" runs in rpkid.

Usage: python cronjob.py [ { -c | --config } configfile ]
                         [ { -h | --help } ]

Default configuration file is cronjob.conf, override with --config option.
"""

import rpki.config, rpki.https, getopt, sys

cfg_file = "cronjob.conf"

opts,argv = getopt.getopt(sys.argv[1:], "c:h?", ["config=", "help"])
for o,a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  elif o in ("-c", "--config"):
    cfg_file = a
if argv:
  print __doc__
  raise RuntimeError, "Unexpected arguments %s" % argv

cfg = rpki.config.parser(cfg_file, "cronjob")

print rpki.https.client(privateKey      = rpki.x509.RSA(Auto_file = cfg.get("https-key")),
                        certChain       = rpki.x509.X509_chain(Auto_files = cfg.multiget("https-cert")),
                        x509TrustList   = rpki.x509.X509_chain(Auto_files = cfg.multiget("https-ta")),
                        url             = cfg.get("https-url"),
                        msg             = "Please run cron now.")
