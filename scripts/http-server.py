# $Id$

import rpki.https, tlslite.api

certInfo = rpki.https.CertInfo("Carol")

# Ok, here's the problem: the certChain is order-sensitive.
# We have to put the EE cert before the CA cert or things break.
#
# For the moment we can kludge this but in the general case we're
# going to have to sort certs somehow.  This is the second time this
# problem has come up (CMS had the same issue).

if True:
  certChain = []
  for file in ("biz-certs/Carol-EE.cer", "biz-certs/Carol-CA.cer"):
    f = open(file, "r")
    x509 = tlslite.api.X509()
    x509.parse(f.read())
    f.close()
    certChain.append(x509)
  certInfo.certChain = tlslite.api.X509CertChain(certChain)

def handler(self, query):
  return 200, "I got:\n" + query

rpki.https.server(certInfo=certInfo, handler=handler)
