# $Id$

import libxml2

def relaxng(xml, rng):
  """
  Validate a chunk of XML against a RelaxNG schema.
  """

  # Most of this is lifted from a libxml2 example.  Using py-lxml
  # might be a better approach, but this works for now.
  #
  # This is probably very inefficient, as we make no attempt to
  # retain validation contexts between calls.  It's still much
  # faster than calling xmllint or jing as an external program.
  #
  # Beware of cleaning up the following code.  libxml2 is not well
  # documented but there are hints that much of the following voodoo
  # is required manual memory management (see py-lxml, above)

  fh = open(rng, "r")
  schema = fh.read()
  fh.close()
  rngp = libxml2.relaxNGNewMemParserCtxt(schema, len(schema))
  rngs = rngp.relaxNGParse()
  ctxt = rngs.relaxNGNewValidCtxt()

  doc = libxml2.parseDoc(xml)
  ret = doc.relaxNGValidateDoc(ctxt)
  if ret != 0:
    raise RuntimeError, "RelaxNG validation error"

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
