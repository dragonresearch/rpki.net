# $Id$

import glob, rpki.up_down, rpki.left_right, xml.sax, lxml.etree, lxml.sax

def test(fileglob, schema, proto, encoding):
  rng = lxml.etree.RelaxNG(lxml.etree.parse(schema))
  files = glob.glob(fileglob)
  files.sort()
  for f in files:
    print "\n<!--", f, "-->"
    handler = proto.sax_handler()
    et = lxml.etree.parse(f)
    rng.assertValid(et)
    lxml.sax.saxify(et, handler)
    et = handler.result.toXML()
    print lxml.etree.tostring(et, pretty_print=True, encoding=encoding, xml_declaration=True)
    try:
      rng.assertValid(et)
    except lxml.etree.DocumentInvalid:
      print rng.error_log.last_error
      raise

test("up-down-protocol-samples/*.xml", "up-down-medium-schema.rng", rpki.up_down, encoding="utf-8")

test("left-right-protocol-samples/*.xml", "left-right-schema.rng", rpki.left_right, encoding="us-ascii")
