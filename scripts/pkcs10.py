# $Id$

import POW.pkix, rpki.x509, glob, rpki.resource_set

parse_extensions = True
list_extensions = True

for name in glob.glob("resource-cert-samples/*.req"):
  f = open(name, "r")
  der = rpki.x509.pem2der(f.read(), "CERTIFICATE REQUEST")
  f.close()

  pkcs10 = POW.pkix.CertificationRequest()
  pkcs10.fromString(der)
  
  print "[", name, "]"

  exts = pkcs10.certificationRequestInfo.attributes.get()[0][1][0]

  if parse_extensions:

    as, v4, v6 = rpki.resource_set.parse_extensions(exts)
    if as: print "ASN  =", as
    if v4: print "IPv4 =", v4
    if v6: print "IPv6 =", v6

    for t in exts:
      oid = t[0]
      if oid in ((1, 3, 6, 1, 5, 5, 7, 1, 7), (1, 3, 6, 1, 5, 5, 7, 1, 8)):
        continue
      val = t[2]
      if isinstance(val, str):
        val = ":".join(["%02X" % ord(i) for i in val])
      print POW.pkix.oid2obj(oid), oid, "=", val

  if list_extensions:
    extensions = pkcs10.certificationRequestInfo.attributes.sequenceOf[0].val.sequenceOf[0].sequenceOf
    for x in extensions:
      oid = x.extnID.get()
      name = POW.pkix.oid2obj(oid)
      crit = x.critical.get()
      value = x.extnValue.get()
      assert isinstance(value, str)
      value = ":".join(["%02X" % ord(i) for i in value])
      print [ name, oid, crit, value ]

  print

