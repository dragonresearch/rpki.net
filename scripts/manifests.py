# $Id$

import rpki.x509, rpki.manifest, time, POW, POW.pkix, glob, os

def one_cert(filename):
  c = rpki.x509.X509(Auto_file = filename)
  d = POW.Digest(POW.SHA256_DIGEST)
  d.update(c.get_DER())
  return filename.rpartition("/")[2], d.digest()

now = time.time()

certs = glob.glob("resource-cert-samples/*.cer")

mani = rpki.manifest.Manifest()
mani.set((0,                                   # version
          17,                                  # manifestNumber
          POW.pkix.time2gen(now),              # thisUpdate
          POW.pkix.time2gen(now + 24*60*60),   # nextUpdate
          (2, 16, 840, 1, 101, 3, 4, 2, 1),    # id-sha256
          [one_cert(i) for i in certs]))

f = os.popen("dumpasn1 -a - 2>/dev/null", "w")
f.write(mani.toString())
f.close()
