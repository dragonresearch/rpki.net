# $Id$

# Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""CMS routines.

For the moment these just call the OpenSSL CLI tool, which is slow,
requires disk I/O, and likes PEM format.  Fix this later.
"""

import os, rpki.x509, rpki.exceptions, lxml.etree, rpki.log

debug = 1

# openssl smime -sign -nodetach -outform DER -signer biz-certs/Alice-EE.cer
#                -certfile biz-certs/Alice-CA.cer -inkey biz-certs/Alice-EE.key 
#                -in THING -out THING.der

def sign(plaintext, keypair, certs):
  """Sign plaintext as CMS with specified key and bag of certificates.

  We have to sort the certificates into the correct order before the
  OpenSSL CLI tool will accept them.  rpki.x509 handles that for us.
  """

  certs.chainsort()

  mypid = str(os.getpid())

  rpki.log.trace()

  signer_filename = "cms.tmp." + mypid + ".signer.pem"
  certfile_filename = "cms.tmp." + mypid + ".certfile.pem"
  plaintext_filename = "cms.tmp." + mypid + ".plaintext"
  signed_filename = "cms.tmp." + mypid + ".signed"
  key_filename = "cms.tmp." + mypid + ".key.pem"
  
  rpki.log.trace()

  f = open(signer_filename, "w")
  f.write(certs[0].get_PEM())
  f.close()

  rpki.log.trace()

  f = open(certfile_filename, "w")
  for cert in certs[1:]:
    f.write(cert.get_PEM())
  f.close()

  rpki.log.trace()

  f = open(plaintext_filename, "w")
  f.write(plaintext)
  f.close()

  rpki.log.trace()

  # This is evil, key should NOT be on disk, but OpenSSL CLI goes into
  # a spin wait sometimes and I now suspect it's an I/O problem.
  # So we whack this with chmod() to minimize the risk.

  f = open(key_filename, "w")
  f.close()
  os.chmod(key_filename, 0600)
  f = open(key_filename, "w")
  f.write(keypair.get_PEM())
  f.close()
  os.chmod(key_filename, 0600)

  cmd = ("openssl", "smime", "-sign", "-nodetach", "-outform", "DER", "-binary",
         "-inkey", key_filename,
         "-signer", signer_filename,
         "-certfile", certfile_filename,
         "-in", plaintext_filename,
         "-out", signed_filename)

  rpki.log.trace()

  pid = os.fork()

  if pid == 0:
    rpki.log.trace()
    os.execvp(cmd[0], cmd)
    raise rpki.exceptions.SubprocessError, "os.execvp() returned, which should never happen"

  rpki.log.trace()

  assert pid != 0

  retpid, status = os.waitpid(pid, 0)

  rpki.log.trace()

  if status != 0:
    raise rpki.exceptions.SubprocessError, "CMS signing command returned status 0x%x" % status

  rpki.log.trace()

  f = open(signed_filename, "r")
  cms = f.read()
  f.close()

  rpki.log.trace()

  for f in (key_filename, signer_filename, certfile_filename, plaintext_filename, signed_filename):
    os.unlink(f)

  rpki.log.trace()

  if debug >= 2:
    print
    print "Signed CMS:"
    dumpasn1(cms)

  return cms

# openssl smime -verify -inform DER -in THING.der -CAfile biz-certs/Alice-Root.cer

def verify(cms, ta):
  """Verify the signature of a chunk of CMS.

  Returns the plaintext on success.  If OpenSSL CLI tool reports
  anything other than successful verification, we raise an exception.
  """  

  if debug >= 2:
    print
    print "Verifying CMS:"
    dumpasn1(cms)

  mypid = str(os.getpid())

  ta_filename = "cms.tmp." + mypid + ".ta.pem"

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
    if debug >= 1:
      print "CMS verification failed, dumping inputs:"
      print
      print "TA:"
      dumpasn1(ta.get_DER())
      print
      print "CMS:"
      dumpasn1(cms)
    raise rpki.exceptions.CMSVerificationFailed, "CMS verification failed with status %s" % status


def xml_verify(cms, ta):
  """Composite routine to verify CMS-wrapped XML."""
  val = lxml.etree.fromstring(verify(cms, ta))
  return val

def xml_sign(elt, key, certs, encoding = "us-ascii"):
  """Composite routine to sign CMS-wrapped XML."""
  val = sign(lxml.etree.tostring(elt, pretty_print = True, encoding = encoding, xml_declaration = True),
             key, certs)
  return val

def dumpasn1(thing):
  """Prettyprint an ASN.1 DER object using cryptlib dumpasn1 tool.
  Use a temporary file rather than popen4() because dumpasn1 uses
  seek() when decoding ASN.1 content nested in OCTET STRING values.
  """
  fn = "dumpasn1.tmp"
  try:
    f = open(fn, "w")
    f.write(thing)
    f.close()
    f = os.popen("dumpasn1 2>&1 -a " + fn)
    print "\n".join(x for x in f.read().splitlines() if x.startswith(" "))
    f.close()
  finally:
    os.unlink(fn)
