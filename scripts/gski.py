# $Id$

import rpki.x509, sys

for file in sys.argv[1:]:
  cert = rpki.x509.X509(Auto_file = file)
  print cert.gSKI(), cert.hSKI(), file
