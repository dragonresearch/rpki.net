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
  x = str(handler.obj)
  print x
  rpki.relaxng.relaxng(x, "up-down-medium-schema.rng")
