# $Id$

import rpki.https, tlslite.api, rpki.config

cfg = rpki.config.parser("http-demo.conf")
section = "server"

privateKey = rpki.x509.RSA(PEM_file = cfg.get(section, "https-key"))

certChain = rpki.x509.X509_chain()
certChain.load_from_PEM(cfg.multiget(section, "https-cert"))

def handler(query, path):
  return 200, "Path:    %s\nQuery:   %s" % (path, query)

rpki.https.server(privateKey=privateKey, certChain=certChain, handlers=handler)
