# $Id$

import os

def relaxng(xml, rng):
  i, o = os.popen4(("xmllint", "--noout", "--relaxng", rng, "-"))
  i.write(xml)
  i.close()
  v = o.read()
  o.close()
  if v != "- validates\n":
    raise RuntimeError, "RelaxNG validation failure:\n" + v
