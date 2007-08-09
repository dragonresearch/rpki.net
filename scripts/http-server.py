# $Id$

import rpki.https, tlslite.api

certInfo = rpki.https.CertInfo("Carol")

def handler(query, path):
  return 200, "Path:    %s\nQuery:   %s" % (path, query)

rpki.https.server(certInfo=certInfo, handlers={"/" : handler})
