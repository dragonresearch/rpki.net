# $Id$

import lxml.etree

rng = lxml.etree.RelaxNG(lxml.etree.parse("myrpki.rng"))

tree = lxml.etree.parse("myrpki.xml").getroot()

if False:
  print lxml.etree.tostring(
    tree,
    pretty_print = True,
    encoding = "us-ascii",
    xml_declaration = True)

rng.assertValid(tree)

if False:
  for x in tree.getiterator():
    print x
  # print x.get("handle")
    for k, v in x.items():
      if v:
        print " ", k, v
    if x.text:
      print " ", x.text

def tag(t):
  return "{http://www.hactrn.net/uris/rpki/myrpki/}" + t

print "My handle:", tree.get("handle")

print "Children:"
for x in tree.getiterator(tag("child")):
  print x.get("handle"), x
  for k, v in x.items():
    if v:
      print " ", k, v

print "ROA requests:"
for x in tree.getiterator(tag("roa_request")):
  print x
  for k, v in x.items():
    if v:
      print " ", k, v

ca = tree.findtext(tag("bpki_ca_certificate"))
if ca:
  print "CA certificate:", ca

ee = tree.findtext(tag("bpki_ee_certificate"))
if ee:
  print "EE certificate:", ee
