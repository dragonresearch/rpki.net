# $Id$

import rpki.https, tlslite.api

if False:
  certInfo = rpki.https.CertInfo("Carol")
else:
  certInfo = rpki.https.CertInfo()

  certChain = []
  for file in ("biz-certs/Carol-EE.cer", "biz-certs/Carol-CA.cer"):
    f = open(file, "r")
    x509 = tlslite.api.X509()
    x509.parse(f.read())
    f.close()
    certChain.append(x509)
  certInfo.certChain = tlslite.api.X509CertChain(certChain)

  f = open("biz-certs/Carol-EE.key", "r")
  certInfo.privateKey = tlslite.api.parsePEMKey(f.read(), private=True)
  f.close()

def handler(self, query):
  return 200, "I got:\n" + query

rpki.https.server(certInfo=certInfo, handler=handler)
