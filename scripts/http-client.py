# $Id$

"""
Usage: python http-client [ { -c | --config } configfile ]
                          [ { -h | --help } ]
                          [ { -m | --msg } message ]

Default configuration file is http-demo.conf, override with --config option.
"""

import rpki.config, rpki.https, getopt

msg = "This is a test.  This is only a test.  Had this been real you would now be really confused.\n"

cfg_file = "http-demo.conf"

opts,argv = getopt.getopt(sys.argv[1:], "c:hm:?", ["config=", "help", "msg="])
for o,a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  elif o in ("-m", "--msg"):
    msg = a
  elif o in ("-c", "--config"):
    cfg_file = a
if argv:
  print __doc__
  raise RuntimeError, "Unexpected arguments %s" % argv

cfg = rpki.config.parser(cfg_file)
section = "client"

print rpki.https.client(privateKey      = rpki.x509.RSA(Auto_file = cfg.get( section, "https-key")),
                        certChain       = rpki.x509.X509_chain(Auto_files = cfg.multiget(section, "https-cert")),
                        x509TrustList   = rpki.x509.X509_chain(Auto_files = cfg.multiget(section, "https-ta")),
                        url             = cfg.get(section, "https-url"),
                        msg             = msg)
