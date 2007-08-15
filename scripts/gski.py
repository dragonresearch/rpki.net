# $Id$

import rpki.x509, POW.pkix, base64, getopt, sys

opts, args = getopt.getopt(sys.argv[1:], "", ["pem", "der"])

use_pem = False

for o, a in opts:
  if o == "--pem": use_pem = True
  if o == "--der": use_pem = False

for file in args:
  if use_pem:
    cert = rpki.x509.X509(PEM_file=file)
  else:
    cert = rpki.x509.X509(DER_file=file)
  ski = base64.b64encode([x for x in cert.get_POWpkix().getExtensions() if x[0] == (2, 5, 29, 14)][0][2]).replace("+", "-").replace("/", "_")
  print ski, file
