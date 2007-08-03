# $Id$

"""
Command line program to simulate behavior of the IR back-end.
"""

import glob, rpki.left_right, xml.sax, lxml.etree, lxml.sax, POW, POW.pkix, getopt

rng = lxml.etree.RelaxNG(lxml.etree.parse("left-right-schema.rng"))

files = glob.glob("left-right-protocol-samples/*.xml")
files.sort()
for f in files:
  print "\n<!--", f, "-->"
  handler = rpki.left_right.sax_handler()
  elt_in = lxml.etree.parse(f).getroot()
  rng.assertValid(elt_in)
  lxml.sax.saxify(elt_in, handler)
  elt_out = handler.result.toXML()
  rng.assertValid(elt_out)
  print lxml.etree.tostring(elt_out, pretty_print=True, encoding="us-ascii", xml_declaration=True)
