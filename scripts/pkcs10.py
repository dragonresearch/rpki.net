# $Id$

import POW.pkix, rpki.x509, glob, rpki.resource_set

parse_extensions        = True
list_extensions         = False
show_attributes         = False
show_algorithm          = False
do_verify               = True

for name in glob.glob("resource-cert-samples/*.req") + glob.glob("biz-certs/*.req"):
  pkcs10 = rpki.x509.PKCS10_Request(Auto_file = name).get_POWpkix()

  print "[", name, "]"

  if show_algorithm:
    print pkcs10.signatureAlgorithm
    print
    print pkcs10.signatureAlgorithm.get()
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

  if False:
    extc = pkcs10.certificationRequestInfo.attributes.val
    exts = extc.choices[extc.choice][0]
    assert exts is pkcs10.getExtensions()
  else:
    exts = pkcs10.getExtensions()

  #print len(exts), exts[0].extnValue

  if list_extensions and exts is not None:
    for x in exts:
      oid = x.extnID.get()
      name = POW.pkix.oid2obj(oid)
      crit = x.critical.get()
      value = x.extnValue.get()
      assert isinstance(value, str)
      value = ":".join(["%02X" % ord(i) for i in value])
      print [ name, oid, crit, value ]

  if parse_extensions and exts is not None:

    as, v4, v6 = rpki.resource_set.parse_extensions(exts.get())
    if as: print "ASN  =", as
    if v4: print "IPv4 =", v4
    if v6: print "IPv6 =", v6

    for oid, crit, val in exts.get():
      if oid in ((1, 3, 6, 1, 5, 5, 7, 1, 7), (1, 3, 6, 1, 5, 5, 7, 1, 8)):
        continue
      if isinstance(val, str):
        val = ":".join(["%02X" % ord(i) for i in val])
      print POW.pkix.oid2obj(oid), oid, "=", val

  if do_verify:
    print
    print "Signature verification: %s" % pkcs10.verify()

  print
