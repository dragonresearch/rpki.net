# $Id$

import os, libxml2, sys

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

  if False:

    i, o = os.popen4(("xmllint", "--noout", "--relaxng", rng, "-"))
    i.write(xml)
    i.close()
    v = o.read()
    o.close()
    if v != "- validates\n":
      raise RuntimeError, "RelaxNG validation failure:\n" + v

  else:

    # First cut at internal RelaxNG validation.  Not entirely
    # satisfactory, see /usr/ports/devel/py-lxml/pkg-descr for a
    # possible alternate approach.  Error reporting in libxml2 module
    # apparently uses a callback which I'm not yet setting.

    fh = open(rng, "r")
    schema = fh.read()
    fh.close()
    rngp = libxml2.relaxNGNewMemParserCtxt(schema, len(schema))
    rngs = rngp.relaxNGParse()
    ctxt = rngs.relaxNGNewValidCtxt()

    doc = libxml2.parseDoc(xml)
    ret = doc.relaxNGValidateDoc(ctxt)
    if ret != 0:
      raise RuntimeError, "RelaxNG validation error %d" % ret

    doc.freeDoc()
    del rngp
    del rngs
    del ctxt
    libxml2.relaxNGCleanupTypes()

    # Memory debug specific
    libxml2.cleanupParser()
    if libxml2.debugMemory(1) != 0:
      print "Memory leak %d bytes" % (libxml2.debugMemory(1))
      libxml2.dumpMemory()
      raise RuntimeError, "RelaxNG memory leak"
