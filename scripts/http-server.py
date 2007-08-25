# $Id$

import rpki.https, tlslite.api, rpki.config

certInfo = rpki.https.CertInfo(rpki.config.parser("http-demo.conf"), "server")

def handler(query, path):
  return 200, "Path:    %s\nQuery:   %s" % (path, query)

rpki.https.server(certInfo=certInfo, handlers={"/" : handler})
