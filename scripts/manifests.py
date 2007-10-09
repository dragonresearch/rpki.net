# $Id$

import rpki.x509, rpki.manifest, time, POW, POW.pkix, glob, os

now = time.time()

certs = glob.glob("resource-cert-samples/*.cer")

def one_cert(filename):
  c = rpki.x509.X509(Auto_file = filename)
  d = POW.Digest(POW.SHA256_DIGEST)
  d.update(c.get_DER())
  return filename.rpartition("/")[2], d.digest()

mani1 = rpki.manifest.Manifest()
mani1.set((0,                                   # version
           17,                                  # manifestNumber
           POW.pkix.time2gen(now),              # thisUpdate
           POW.pkix.time2gen(now + 24*60*60),   # nextUpdate
           (2, 16, 840, 1, 101, 3, 4, 2, 1),    # id-sha256
           [one_cert(i) for i in certs]))

m = rpki.x509.SignedManifest()
m.build(serial = 17,
        nextUpdate = now + 24 * 60 * 60,
        names_and_objs = [(fn, rpki.x509.X509(Auto_file = fn)) for fn in certs])
mani2 = m.get_content()

assert mani1.toString() == mani2.toString()

i,o = os.popen4(("dumpasn1", "-a", "-"))
i.write(mani2.toString())
i.close()
print "\n".join(x for x in o.read().splitlines() if x.startswith(" "))
o.close()
