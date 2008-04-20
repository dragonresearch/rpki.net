# $Id$

# Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

import glob, xml.sax, lxml.etree, lxml.sax, POW, POW.pkix
import rpki.up_down, rpki.left_right, rpki.relaxng

verbose = True

def test(fileglob, rng, sax_handler, encoding, tester = None):
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
    print lxml.etree.tostring(elt_out, pretty_print = True, encoding = encoding, xml_declaration = True)

def pprint_cert(cert):
  print cert.get_POW().pprint()

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

test(fileglob = "up-down-protocol-samples/*.xml",
     rng = rpki.relaxng.up_down,
     sax_handler = rpki.up_down.sax_handler,
     encoding = "utf-8",
     tester = ud_tester)

test(fileglob = "left-right-protocol-samples/*.xml",
     rng = rpki.relaxng.left_right,
     sax_handler = rpki.left_right.sax_handler,
     encoding = "us-ascii",
     tester = lr_tester)
