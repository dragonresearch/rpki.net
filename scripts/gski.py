# $Id$

import POW, POW.pkix, base64, getopt, sys

opts, args = getopt.getopt(sys.argv[1:], "", ["pem", "der"])

use_pem = False

for o, a in opts:
  if o == "--pem": use_pem = True
  if o == "--der": use_pem = False

for file in args:
  f = open(file, "r")
  der = f.read()
  f.close()
  if use_pem:
    der = POW.pemRead(POW.X509_CERTIFICATE, der).derWrite()
  cert = POW.pkix.Certificate()
  cert.fromString(der)
  ski = base64.b64encode([x for x in cert.getExtensions() if x[0] == (2, 5, 29, 14)][0][2]).replace("+", "-").replace("/", "_")
  print ski, file
