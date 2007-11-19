# $Id$

import POW.pkix, glob, os
import rpki.x509, rpki.resource_set, rpki.oids

parse_test              = False
generate_test           = True

parse_extensions        = True
show_attributes         = False
show_algorithm          = False
do_verify               = True
show_signature          = False
show_publickey          = False

def hexify(thing):
  return ":".join(["%02X" % ord(i) for i in thing])

if parse_test:

  for name in glob.glob("resource-cert-samples/*.req") + glob.glob("biz-certs/*.req"):
    pkcs10 = rpki.x509.PKCS10(Auto_file = name).get_POWpkix()

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

      bag = rpki.resource_set.parse_extensions(exts)
      if bag.as: print "ASN  =", bag.as
      if bag.v4: print "IPv4 =", bag.v4
      if bag.v6: print "IPv6 =", bag.v6

      for oid, crit, val in exts:
        if oid in (rpki.oids.name2oid["sbgp-ipAddrBlock"],
                   rpki.oids.name2oid["sbgp-autonomousSysNum"]):
          continue
        if isinstance(val, str):
          val = hexify(val)
        print POW.pkix.oid2obj(oid), oid, "=", val

    if do_verify:
      print
      print "Signature verification: %s" % pkcs10.verify()

    print

if generate_test:
  keypair = rpki.x509.RSA()
  keypair.generate()
  pkcs10 = rpki.x509.PKCS10.create(keypair)
  f = os.popen("openssl req -text -config /dev/null", "w")
  f.write(pkcs10.get_PEM())
  f.close()
