# $Id$

import rpki.x509, rpki.manifest, time, POW, POW.pkix, glob

def onefile(name):
  f = open(name)
  d = POW.Digest(POW.SHA256_DIGEST)
  d.update(f.read())
  f.close()
  return name.rpartition("/")[2], d.digest()

now = time.time()

mani = rpki.manifest.Manifest()
mani.set((0,                                   # version
          17,                                  # manifestNumber
          POW.pkix.time2utc(now),              # thisUpdate
          POW.pkix.time2utc(now + 24*60*60),   # nextUpdate
          (2, 16, 840, 1, 101, 3, 4, 2, 1),    # id-sha256
          [onefile(i) for i in glob.glob("resource-cert-samples/*.cer")]))

print mani.get()

if False:
  f = open("manifests.out.der", "w")
  f.write(mani.toString())
  f.close()
