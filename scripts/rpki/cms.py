# $Id$

"""
CMS routines.  For the moment these just call the OpenSSL CLI tool,
which is slow and requires disk I/O and likes PEM format.  Fix later.
"""

import os, POW

# openssl smime -sign -nodetach -outform DER -signer biz-certs/Alice-EE.cer -certfile biz-certs/Alice-CA.cer -inkey biz-certs/Alice-EE.key -in PLAN -out PLAN.der

def encode(xml, key, cert_files):

  # This is a little tricky, the OpenSSL CLI really wants us to tell
  # it which cert is the signer and which ones are not.  We don't know
  # a priori, so we have to figure it out.  Simple algorithm: assuming
  # this is a well-formed chain, we're looking for the one cert in
  # this collection that's not the issuer of any other cert in this
  # collection.

  def readPEM(filename):
    f = open(filename, "r")
    pem = f.read()
    f.close()
    return POW.pemRead(POW.X509_CERTIFICATE, pem)

  certs = [readPEM(x) for x in cert_files]
  issuers = [x.getIssuer() for x in certs]
  issuers = [x for x in certs if x.getSubject() in issuers]
  signers = [x for x in certs if x not in issuers]
  assert len(signers) == 1

  signer_filename = "cms.tmp.signer.pem"
  certfile_filename = "cms.tmp.certfile.pem"

  f = open(signer_filename, "w")
  f.write(signers[0].pemWrite())
  f.close()

  f = open(certfile_filename, "w")
  for cert in issuers:
    f.write(cert.pemWrite())
  f.close()

  i,o = os.popen2(["openssl", "smime", "-sign", "-nodetach", "-outform", "DER", "-signer", signer_filename, "-certfile", certfile_filename, "-inkey", key])
  i.write(xml)
  i.close()
  cms = o.read()
  o.close()

  os.unlink(signer_filename)
  os.unlink(certfile_filename)

  return cms

# openssl smime -verify -inform DER -in PLAN.der -CAfile biz-certs/Alice-Root.cer 

def decode(cms, ta):
  i,o,e = os.popen3(["openssl", "smime", "-verify", "-inform", "DER", "-CAfile", ta])
  i.write(cms)
  i.close()
  xml = o.read()
  o.close()
  status = e.read()
  e.close()
  assert status == "Verification successful\n", "CMS verification failed: %s" % status
  return xml
