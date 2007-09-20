# $Id$

import glob, rpki.up_down, rpki.left_right, rpki.relaxng, xml.sax, lxml.etree, lxml.sax, POW, POW.pkix

verbose = False

def test(fileglob, rng, sax_handler, encoding, tester=None):
  files = glob.glob(fileglob)
  files.sort()
  for f in files:
    print "\n<!--", f, "-->"
    handler = sax_handler()
    elt_in = lxml.etree.parse(f).getroot()
    rng.assertValid(elt_in)
    lxml.sax.saxify(elt_in, handler)
    elt_out = handler.result.toXML()
    rng.assertValid(elt_out)
    if (tester):
      tester(elt_in, elt_out, handler.result)
    print lxml.etree.tostring(elt_out, pretty_print=True, encoding=encoding, xml_declaration=True)

def pprint_cert(cert):
  print POW.derRead(POW.X509_CERTIFICATE, cert.toString()).pprint()

def ud_tester(elt_in, elt_out, msg):
  assert isinstance(msg, rpki.up_down.message_pdu)
  if verbose:
    if isinstance(msg.payload, rpki.up_down.list_response_pdu):
      for c in msg.payload.classes:
        for i in range(len(c.certs)):
          print "[Certificate #%d]" % i
          pprint_cert(c.certs[i].cert)
        print "[Issuer]"
        pprint_cert(c.issuer)

def lr_tester(elt_in, elt_out, msg):
  assert isinstance(msg, rpki.left_right.msg)
  if verbose:
    for bsc in [x for x in msg if isinstance(x, rpki.left_right.bsc_elt)]:
      for cert in bsc.signing_cert:
        pprint_cert(cert)

test(fileglob="up-down-protocol-samples/*.xml",
     rng=rpki.relaxng.up_down,
     sax_handler=rpki.up_down.sax_handler,
     encoding="utf-8",
     tester=ud_tester)

test(fileglob="left-right-protocol-samples/*.xml",
     rng=rpki.relaxng.left_right,
     sax_handler=rpki.left_right.sax_handler,
     encoding="us-ascii",
     tester=lr_tester)
