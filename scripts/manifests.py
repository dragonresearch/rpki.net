# $Id$

import rpki.x509, rpki.manifest, time, glob, os

show_content_1                  = True
show_signed_manifest_PEM        = True
show_signed_manifest_asn1dump   = True
show_content_2                  = True
show_content_3                  = True

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

if show_content_1:
  dumpasn1(m.get_content().toString())

m.sign(keypair = rpki.x509.RSA(Auto_file = "biz-certs/Alice-EE.key"),
       certs   = rpki.x509.X509_chain(Auto_files = ("biz-certs/Alice-EE.cer", "biz-certs/Alice-CA.cer")))

if show_signed_manifest_PEM:
  print m.get_PEM()

if show_signed_manifest_asn1dump:
  dumpasn1(m.get_DER())

n = rpki.x509.SignedManifest(DER = m.get_DER())

n.verify(ta = rpki.x509.X509(Auto_file = "biz-certs/Alice-Root.cer"))

if show_content_2:
  dumpasn1(n.get_content().toString())

assert m.get_content().toString() == n.get_content().toString()
assert m.get_content().get()      == n.get_content().get()

print
print n.get_content().get()
