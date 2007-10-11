# $Id$

"""Old code to generate PKCS #10 certification requests.

This has been replaced by direct support for PKCS #10 in my hacked
version of the POW package.  This module will go away eventually, I'm
just keeping it around in case I discover some horrible bug in the new
code that would make me want to fall back to this.
"""

raise NotImplementedError, "You shouldn't be using this module anymore, see rpki.x509.PKCS10"

import POW, rpki.x509, os, rpki.exceptions, binascii

req_fmt = '''
[ req ]
distinguished_name = req_dn
default_md = sha256
prompt = no

[ req_dn ]
CN = %s
'''

def make_request(keypair):
  """Generate a PKCS #10 request."""

  digest = POW.Digest(POW.SHA1_DIGEST)
  digest.update(keypair.get_POW().derWrite(POW.RSA_PUBLIC_KEY))
  commonName = "0x" + binascii.hexlify(digest.digest())

  try:
    config_filename = "req.tmp.conf"
    f = open(config_filename, "w")
    f.write(req_fmt % commonName)
    f.close()

    i,o = os.popen2(["openssl", "req", "-config", config_filename,  "-new", "-key", "/dev/stdin", "-outform", "DER"])
    i.write(keypair.get_PEM())
    i.close()
    pkcs10 = rpki.x509.PKCS10(DER = o.read())
    o.close()

  finally:
    os.unlink(config_filename)

  return pkcs10
