# $Id$

import glob, rpki.up_down, rpki.left_right, xml.sax, lxml.etree, lxml.sax, pprint, POW, POW.pkix

def test(fileglob, schema, sax_handler, encoding, tester=None):

  rng = lxml.etree.RelaxNG(lxml.etree.parse(schema))
  def validate(x):
    try:
      rng.assertValid(x)
    except lxml.etree.DocumentInvalid:
      print rng.error_log.last_error
      raise

  files = glob.glob(fileglob)
  files.sort()
  for f in files:
    print "\n<!--", f, "-->"
    handler = sax_handler()
    elt_in = lxml.etree.parse(f).getroot()
    validate(elt_in)
    lxml.sax.saxify(elt_in, handler)
    elt_out = handler.result.toXML()
    validate(elt_out)
    if (tester):
      tester(elt_in, elt_out, handler.result)
    print lxml.etree.tostring(elt_out, pretty_print=True, encoding=encoding, xml_declaration=True)

def pprint_cert(cert):
  print POW.derRead(POW.X509_CERTIFICATE, cert.toString()).pprint()

def ud_tester(elt_in, elt_out, msg):
  assert isinstance(msg, rpki.up_down.message_pdu)
  if isinstance(msg.payload, rpki.up_down.list_response_pdu):
    for c in msg.payload.classes:
      for i in range(len(c.certs)):
        print "[Certificate #%d]" % i
        pprint_cert(c.certs[i].cert)
      print "[Issuer]"
      pprint_cert(c.issuer)

  nsmap = { "x" : "http://www.apnic.net/specs/rescerts/up-down/" }
  for c in elt_in.xpath("//x:issuer | //x:certificate", nsmap):
    print c.tag, c.text

def lr_tester(elt_in, elt_out, msg):
  assert isinstance(msg, rpki.left_right.msg)

test(fileglob="up-down-protocol-samples/*.xml",
     schema="up-down-medium-schema.rng",
     sax_handler=rpki.up_down.sax_handler,
     encoding="utf-8",
     tester=ud_tester)

test(fileglob="left-right-protocol-samples/*.xml",
     schema="left-right-schema.rng",
     sax_handler=rpki.left_right.sax_handler,
     encoding="us-ascii",
     tester=lr_tester)
