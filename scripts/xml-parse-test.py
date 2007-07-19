# $Id$

import glob, rpki.up_down, rpki.left_right, rpki.relaxng, xml.sax

if True:
  files = glob.glob("up-down-protocol-samples/*.xml")
  files.sort()
  for f in files:
    print "<!--", f, "-->"
    handler = rpki.up_down.sax_handler()
    fh = open(f, "r")
    x = fh.read()
    fh.close()
    xml.sax.parseString(x, handler)
    x = str(handler.result)
    print x
    rpki.relaxng.relaxng(x, "up-down-medium-schema.rng")

if True:
  files = glob.glob("left-right-protocol-samples/*.xml")
  files.sort()
  for f in files:
    print "<!--", f, "-->"
    handler = rpki.left_right.sax_handler()
    fh = open(f, "r")
    x = fh.read()
    fh.close()
    xml.sax.parseString(x, handler)
    x = str(handler.result)
    print x
    rpki.relaxng.relaxng(x, "left-right-schema.rng")
