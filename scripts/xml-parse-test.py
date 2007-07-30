# $Id$

import glob, rpki.up_down, rpki.left_right, xml.sax, lxml.etree, lxml.sax

def test(fileglob, schema, proto):
  rng = lxml.etree.RelaxNG(lxml.etree.parse(schema))
  files = glob.glob(fileglob)
  files.sort()
  for f in files:
    print "\n<!--", f, "-->"
    handler = proto.sax_handler()
    et = lxml.etree.parse(f)
    rng.assertValid(et)
    lxml.sax.saxify(et, handler)
    et = lxml.etree.fromstring(str(handler.result))
    print lxml.etree.tostring(et)
    rng.assertValid(et)

test("up-down-protocol-samples/*.xml", "up-down-medium-schema.rng", rpki.up_down)

test("left-right-protocol-samples/*.xml", "left-right-schema.rng", rpki.left_right)
