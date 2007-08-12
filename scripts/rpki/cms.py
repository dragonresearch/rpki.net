# $Id$

"""CMS routines.

For the moment these just call the OpenSSL CLI tool, which is slow,
requires disk I/O, and likes PEM format.  Fix this later.
"""

import os, rpki.x509

# openssl smime -sign -nodetach -outform DER -signer biz-certs/Alice-EE.cer -certfile biz-certs/Alice-CA.cer -inkey biz-certs/Alice-EE.key -in PLAN -out PLAN.der

def encode(xml, key, cert_files):
  """Encode a chunk of XML as CMS signed with a specified key and bag of certificates.

  We have to sort the certificates into the correct order before the
  OpenSSL CLI tool will accept them.  rpki.x509 handles that for us.
  """

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
  """Decode and check the signature of a chunk of CMS.

  Returns the signed text (XML, until proven otherwise) on success.
  if OpenSSL CLI tool reports anything other than successful
  verification, we raise an exception.
  """  

  i,o,e = os.popen3(["openssl", "smime", "-verify", "-inform", "DER", "-CAfile", ta])
  i.write(cms)
  i.close()
  xml = o.read()
  o.close()
  status = e.read()
  e.close()
  if status == "Verification successful\n":
    return xml
  else:
    raise RuntimeError, "CMS verification failed: %s" % status
