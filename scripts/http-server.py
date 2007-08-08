# $Id$

import rpki.https, tlslite.api

certInfo = rpki.https.CertInfo("Carol")

def handler(self, query):
  return 200, "I got:\n" + query

rpki.https.server(certInfo=certInfo, handler=handler)
