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

These used to use the OpenSSL CLI too, which was slow.  I've since
added minimal PKCS #7 / CMS capability to POW, so we now use that
instead.  I should write a pretty DER_object wrapper around the POW
code and include it in x509.py, but I haven't gotten to that yet.
"""

import os, rpki.x509, rpki.exceptions, lxml.etree, rpki.log, POW

debug = 1

# openssl smime -sign -nodetach -outform DER -signer biz-certs/Alice-EE.cer
#                -certfile biz-certs/Alice-CA.cer -inkey biz-certs/Alice-EE.key 
#                -in THING -out THING.der

def sign(plaintext, keypair, certs):
  """Sign plaintext as CMS with specified key and bag of certificates.

  We have to sort the certificates into the correct order before the
  OpenSSL CLI tool will accept them.  rpki.x509 handles that for us.
  """

  p7 = POW.PKCS7()
  p7.sign(certs[0].get_POW(), keypair.get_POW(), [x.get_POW() for x in certs[1:]], plaintext)
  cms = p7.derWrite()

  if debug >= 2:
    print
    print "Signed CMS:"
    dumpasn1(cms)

  return cms

# openssl smime -verify -inform DER -in THING.der -CAfile biz-certs/Alice-Root.cer

def verify(cms, ta):
  """Verify the signature of a chunk of CMS.

  Returns the plaintext on success, otherwise raise an exception.
  """  

  if debug >= 2:
    print
    print "Verifying CMS:"
    dumpasn1(cms)

  p7 = POW.derRead(POW.PKCS7_MESSAGE, cms)

  store = POW.X509Store()
  store.addTrust(ta.get_POW())

  try:
    return p7.verify(store)

  except:
    if debug >= 1:
      print "CMS verification failed, dumping inputs:"
      print
      print "TA:"
      dumpasn1(ta.get_DER())
      print
      print "CMS:"
      dumpasn1(cms)
    raise rpki.exceptions.CMSVerificationFailed, "CMS verification failed"

# openssl smime -verify -noverify -inform DER -in THING.der

def extract(cms):
  """Extract the content of a signed CMS message WITHOUT verifying the
  signature.   Don't try this at home, kids.
  """

  return POW.derRead(POW.PKCS7_MESSAGE, cms).extract()

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
