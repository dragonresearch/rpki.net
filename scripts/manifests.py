# $Id$

import rpki.x509, rpki.manifest, time, glob, os

show_content_1                  = False
show_signed_manifest_PEM        = False
show_signed_manifest_asn1dump   = True
show_content_2                  = False
show_content_3                  = False
dump_signed_manifest_DER        = False
dump_manifest_content_DER       = False

def dumpasn1(thing):
  # Save to file rather than using popen4() because dumpasn1 uses
  # seek() when decoding ASN.1 content nested in OCTET STRING values.
  try:
    fn = "dumpasn1.tmp"
    f = open(fn, "w")
    f.write(thing)
    f.close()
    f = os.popen("dumpasn1 2>&1 -a " + fn)
    print "\n".join(x for x in f.read().splitlines() if x.startswith(" "))
    f.close()
  finally:
    os.unlink(fn)

m = rpki.x509.SignedManifest()
m.build(serial = 17,
        nextUpdate = rpki.datetime.datetime.utcnow() + rpki.datetime.timedelta(days = 1),
        names_and_objs = [(fn, rpki.x509.X509(Auto_file = fn))
                          for fn in glob.glob("resource-cert-samples/*.cer")])

if show_content_1:
  dumpasn1(m.get_content().toString())

m.sign(keypair = rpki.x509.RSA(Auto_file = "biz-certs/Alice-EE.key"),
       certs   = rpki.x509.X509_chain(Auto_files = ("biz-certs/Alice-EE.cer", "biz-certs/Alice-CA.cer")))

if show_signed_manifest_PEM:
  print m.get_PEM()

if dump_manifest_content_DER:
  f = open("manifest-content.der", "wb")
  f.write(m.get_content().toString())
  f.close()

if dump_signed_manifest_DER:
  f = open("signed-manifest.der", "wb")
  f.write(m.get_DER())
  f.close()

if show_signed_manifest_asn1dump:
  dumpasn1(m.get_DER())

n = rpki.x509.SignedManifest(DER = m.get_DER())

n.verify(ta = rpki.x509.X509(Auto_file = "biz-certs/Alice-Root.cer"))

if show_content_2:
  dumpasn1(n.get_content().toString())

assert m.get_content().toString() == n.get_content().toString()
assert m.get_content().get()      == n.get_content().get()

if show_content_3:
  print
  print n.get_content().get()
