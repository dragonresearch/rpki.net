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

for x in tree.getiterator():
  print x
# print x.get("handle")
  for k, v in x.items():
    if v:
      print " ", k, v
  if x.text:
    print " ", x.text
