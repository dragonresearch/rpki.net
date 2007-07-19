# $Id$

import os

def relaxng(xml, rng):
  """
  Validate a chunk of xml against a RelaxNG schema.
  """

  # We could use either xmllint or jing here, but xmllint is easier.
  # How to invoke jing, just in case:
  #
  # java -jar /usr/local/share/java/classes/jing.jar schema.rng foo.xml
  #
  # If error messages from xmllint are incomprehensible, try jing too.

  i, o = os.popen4(("xmllint", "--noout", "--relaxng", rng, "-"))
  i.write(xml)
  i.close()
  v = o.read()
  o.close()
  if v != "- validates\n":
    raise RuntimeError, "RelaxNG validation failure:\n" + v
