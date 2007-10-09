# $Id$

import rpki.x509, rpki.manifest, time, glob, os

m = rpki.x509.SignedManifest()
m.build(serial = 17,
        nextUpdate = time.time() + 24 * 60 * 60,
        names_and_objs = [(fn, rpki.x509.X509(Auto_file = fn))
                          for fn in glob.glob("resource-cert-samples/*.cer")])

i,o = os.popen4(("dumpasn1", "-a", "-"))
i.write(m.get_content().toString())
i.close()
print "\n".join(x for x in o.read().splitlines() if x.startswith(" "))
o.close()
