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

# There doesn't seem to be any existing OpenSSL-based python HTTPS
# client which bothers to check the server's certificate.  tlslite
# does check, but only when it's using cryptlib...which doesn't
# compile on FreeBSD this week due to a completely unrelated symbol
# collision with another FreeBSD package (don't ask).
#
# The mechanism that requires cryptlib is the x509TrustList parameter to
# tlslite.api.HTTPTLSConnection(), which looks just about perfect other
# than requiring cryptlib.   Not sure how much work it would be to get
# this to work with M2Crypto (would help if M2Crypto were documented).
#
# For the moment, just punt on the issue, as this is test code.  In
# production this would be a problem.

http = tlslite.api.HTTPTLSConnection(host="localhost", port=8080, certChain=certChain, privateKey=privateKey)

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
