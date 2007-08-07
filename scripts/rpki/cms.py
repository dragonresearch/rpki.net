# $Id$

"""
CMS routines.  For the moment these just call the OpenSSL CLI tool,
which is slow and which really prefers PEM format to DER.  Fix later.
"""

import os

# Also see the -certfile option (PEM bag of certs to be included in the message)

def encode(xml, key, cer):
  i,o = os.popen2("openssl", "smime", "-sign", "-nodetach", "-outform", "PEM", "-signer", cer, "-inkey", key)
  i.write(xml)
  i.close()
  cms = o.read()
  o.close()
  return cms

# We should be able to use -CAfile instead of -CApath here as we
# should be expecting a particular trust anchor.

def decode(cms, dir):
  i,o = os.popen2("openssl", "smime", "-verify", "-inform", "PEM", "-CApath", dir)
  i.write(cms)
  i.close()
  xml = o.read()
  o.close()
  return xml
