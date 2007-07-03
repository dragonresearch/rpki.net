#!/usr/local/bin/python
# $Id$

import glob, rpki.up_down, rpki.relaxng, xml.sax

files = glob.glob("up-down-protocol-samples/*.xml")
files.sort()
for f in files:
  handler = rpki.up_down.sax_handler()
  fh = open(f, "r")
  x = fh.read()
  fh.close()
  xml.sax.parseString(x, handler)
  obj = handler.obj
  print "<!-- " + str(obj) + " -->\n"
  x = obj.msgToXML()
  print x
  rpki.relaxng.relaxng(x, "up-down-medium-schema.rng")
