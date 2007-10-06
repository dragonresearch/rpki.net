# $Id$

import rpki.config, rpki.https

msg = "This is a test.  This is only a test.  Had this been real you would now be really confused.\n"

cfg = rpki.config.parser("http-demo.conf")
section = "client"

print rpki.https.client(privateKey      = rpki.x509.RSA(Auto_file = cfg.get( section, "https-key")),
                        certChain       = rpki.x509.X509_chain(Auto_files = cfg.multiget(section, "https-cert")),
                        x509TrustList   = rpki.x509.X509_chain(Auto_files = cfg.multiget(section, "https-ta")),
                        url             = cfg.get(section, "https-url"),
                        msg             = msg)
