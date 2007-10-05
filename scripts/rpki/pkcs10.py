# $Id$

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
