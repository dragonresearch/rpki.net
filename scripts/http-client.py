# $Id$

import httplib, tlslite.api

certChain = []
for file in ("biz-certs/Dave-EE.cer", "biz-certs/Dave-CA.cer"):
  f = open(file, "r")
  x509 = tlslite.api.X509()
  x509.parse(f.read())
  f.close()
  certChain.append(x509)
certChain = tlslite.api.X509CertChain(certChain)

f = open("biz-certs/Dave-EE.key", "r")
privateKey = tlslite.api.parsePEMKey(f.read(), private=True)
f.close()

x509TrustList = []
for file in ("biz-certs/Alice-Root.cer", "biz-certs/Bob-Root.cer", "biz-certs/Carol-Root.cer"):
  f = open(file, "r")
  x509 = tlslite.api.X509()
  x509.parse(f.read())
  f.close()
  x509TrustList.append(x509)

https = tlslite.api.HTTPTLSConnection(host="localhost", port=4433, certChain=certChain, privateKey=privateKey, x509TrustList=x509TrustList)

https.connect()
https.request("POST", "/", "This is a test.  This is only a test.  Had this been real you would now be really confused.\n", {"Content-Type":"application/wombat"})
response = https.getresponse()

for h in response.getheaders():
  print "%s: %s" % h
print
if response.status == httplib.OK:
  print "OK"
else:
  print "Ouch"
print
print response.read()
