# $Id$

import POW.pkix, rpki.x509, glob, rpki.resource_set

parse_extensions        = True
show_attributes         = False
show_algorithm          = False
do_verify               = True
show_signature          = False
show_publickey          = False

def hexify(thing):
  return ":".join(["%02X" % ord(i) for i in thing])

for name in glob.glob("resource-cert-samples/*.req") + glob.glob("biz-certs/*.req"):
  pkcs10 = rpki.x509.PKCS10_Request(Auto_file = name).get_POWpkix()

  print "[", name, "]"

  if show_algorithm:
    print pkcs10.signatureAlgorithm
    print
    print pkcs10.signatureAlgorithm.get()
    print

  if show_signature:
    print pkcs10.signatureValue, hexify(pkcs10.signatureValue.get())
    print

  if show_publickey:
    print pkcs10.certificationRequestInfo.subjectPublicKeyInfo
    print pkcs10.certificationRequestInfo.subjectPublicKeyInfo.get()
    print hexify(pkcs10.certificationRequestInfo.subjectPublicKeyInfo.toString())
    print

  if show_attributes:
    print pkcs10.certificationRequestInfo.attributes.oid, pkcs10.certificationRequestInfo.attributes.oid.get()
    print
    print pkcs10.certificationRequestInfo.attributes.val, pkcs10.certificationRequestInfo.attributes.val.get()
    print
    print pkcs10.certificationRequestInfo.attributes.val.choice, pkcs10.certificationRequestInfo.attributes.val.choices
    print
    print pkcs10.certificationRequestInfo.attributes.val.choices[pkcs10.certificationRequestInfo.attributes.val.choice]
    print
    print len(pkcs10.certificationRequestInfo.attributes.val.choices[pkcs10.certificationRequestInfo.attributes.val.choice])
    print
    if len(pkcs10.certificationRequestInfo.attributes.val.choices[pkcs10.certificationRequestInfo.attributes.val.choice]) > 0:
      print pkcs10.certificationRequestInfo.attributes.val.choices[pkcs10.certificationRequestInfo.attributes.val.choice][0]
      print

  if parse_extensions:

    exts = pkcs10.getExtensions()

    as, v4, v6 = rpki.resource_set.parse_extensions(exts)
    if as: print "ASN  =", as
    if v4: print "IPv4 =", v4
    if v6: print "IPv6 =", v6

    for oid, crit, val in exts:
      if oid in ((1, 3, 6, 1, 5, 5, 7, 1, 7), (1, 3, 6, 1, 5, 5, 7, 1, 8)):
        continue
      if isinstance(val, str):
        val = hexify(val)
      print POW.pkix.oid2obj(oid), oid, "=", val

  if do_verify:
    print
    print "Signature verification: %s" % pkcs10.verify()

  print
