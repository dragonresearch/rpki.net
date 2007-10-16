# $Id$

"""CMS routines.

For the moment these just call the OpenSSL CLI tool, which is slow,
requires disk I/O, and likes PEM format.  Fix this later.
"""

import os, rpki.x509, rpki.exceptions, lxml.etree

# openssl smime -sign -nodetach -outform DER -signer biz-certs/Alice-EE.cer
# -certfile biz-certs/Alice-CA.cer -inkey biz-certs/Alice-EE.key -in PLAN -out PLAN.der

def sign(plaintext, keypair, certs):
  """Sign plaintext as CMS with specified key and bag of certificates.

  We have to sort the certificates into the correct order before the
  OpenSSL CLI tool will accept them.  rpki.x509 handles that for us.
  """

  certs.chainsort()

  signer_filename = "cms.tmp.signer.pem"
  certfile_filename = "cms.tmp.certfile.pem"
  plaintext_filename = "cms.tmp.plaintext"
  
  f = open(signer_filename, "w")
  f.write(certs[0].get_PEM())
  f.close()

  f = open(certfile_filename, "w")
  for cert in certs[1:]:
    f.write(cert.get_PEM())
  f.close()

  f = open(plaintext_filename, "w")
  f.write(plaintext)
  f.close()

  i,o = os.popen2(("openssl", "smime", "-sign", "-nodetach", "-outform", "DER", "-binary",
                   "-signer", signer_filename,
                   "-certfile", certfile_filename, "-inkey", "/dev/stdin", "-in", plaintext_filename))
  i.write(keypair.get_PEM())
  i.close()
  cms = o.read()
  o.close()

  os.unlink(signer_filename)
  os.unlink(certfile_filename)
  os.unlink(plaintext_filename)

  return cms

# openssl smime -verify -inform DER -in PLAN.der -CAfile biz-certs/Alice-Root.cer 

def verify(cms, ta):
  """Verify the signature of a chunk of CMS.

  Returns the plaintext on success.  If OpenSSL CLI tool reports
  anything other than successful verification, we raise an exception.
  """  

  ta_filename = "cms.tmp.ta.pem"

  f = open(ta_filename, "w")
  f.write(ta.get_PEM())
  f.close()

  i,o,e = os.popen3(("openssl", "smime", "-verify", "-inform", "DER", "-binary", "-CAfile", ta_filename))
  i.write(cms)
  i.close()
  plaintext = o.read()
  o.close()
  status = e.read()
  e.close()

  os.unlink(ta_filename)

  if status == "Verification successful\n":
    return plaintext
  else:
    raise rpki.exceptions.CMSVerificationFailed, "CMS verification failed with status %s" % status


def xml_verify(elt, ta):
  """Composite routine to verify CMS-wrapped XML."""
  return lxml.etree.fromstring(verify(elt, ta))

def xml_sign(elt, key, certs):
  """Composite routine to sign CMS-wrapped XML."""
  return sign(lxml.etree.tostring(elt, pretty_print=True, encoding="us-ascii", xml_declaration=True),
              key, certs)
