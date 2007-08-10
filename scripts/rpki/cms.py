# $Id$

"""
CMS routines.  For the moment these just call the OpenSSL CLI tool,
which is slow and requires disk I/O and likes PEM format.  Fix later.
"""

import os, rpki.x509

# openssl smime -sign -nodetach -outform DER -signer biz-certs/Alice-EE.cer -certfile biz-certs/Alice-CA.cer -inkey biz-certs/Alice-EE.key -in PLAN -out PLAN.der

def encode(xml, key, cert_files):

  certs = rpki.x509.X509_chain()
  certs.load_from_PEM(cert_files)
  certs.chainsort()

  signer_filename = "cms.tmp.signer.pem"
  certfile_filename = "cms.tmp.certfile.pem"
  
  f = open(signer_filename, "w")
  f.write(certs[0].get_PEM())
  f.close()

  f = open(certfile_filename, "w")
  for cert in certs[1:]:
    f.write(cert.get_PEM())
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
