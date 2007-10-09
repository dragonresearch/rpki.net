# $Id$

import rpki.x509, rpki.manifest, time, glob, os

def dumpasn1(thing):
  i,o = os.popen4(("dumpasn1", "-a", "-"))
  i.write(thing)
  i.close()
  print "\n".join(x for x in o.read().splitlines() if x.startswith(" "))
  o.close()

m = rpki.x509.SignedManifest()
m.build(serial = 17,
        nextUpdate = time.time() + 24 * 60 * 60,
        names_and_objs = [(fn, rpki.x509.X509(Auto_file = fn))
                          for fn in glob.glob("resource-cert-samples/*.cer")])

#dumpasn1(m.get_content().toString())

m.sign(keypair = rpki.x509.RSA(Auto_file = "biz-certs/Alice-EE.key"),
       certs   = rpki.x509.X509_chain(Auto_files = ("biz-certs/Alice-EE.cer", "biz-certs/Alice-CA.cer")))

print m.get_PEM()
dumpasn1(m.get_DER())
