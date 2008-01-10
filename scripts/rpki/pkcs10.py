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

    i,o = os.popen2(["openssl", "req", "-config", config_filename,  "-new",
                     "-key", "/dev/stdin", "-outform", "DER"])
    i.write(keypair.get_PEM())
    i.close()
    pkcs10 = rpki.x509.PKCS10(DER = o.read())
    o.close()

  finally:
    os.unlink(config_filename)

  return pkcs10
