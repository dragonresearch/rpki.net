# $Id$

import rpki.x509, POW.pkix, base64, sys

def g(x):
  return base64.b64encode(x).replace("+", "-").replace("/", "_")

def h(x):
  return ":".join(("%02X" % ord(i) for i in x))

for file in sys.argv[1:]:
  cert = rpki.x509.X509(Auto_file = file)
  ski = cert.get_SKI()
  print g(ski), h(ski), file
