"""
$Id$

Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import glob, lxml.etree, lxml.sax
import rpki.up_down, rpki.left_right, rpki.publication, rpki.relaxng

verbose = False

def test(fileglob, rng, sax_handler, encoding, tester = None):
  files = glob.glob(fileglob)
  files.sort()
  for f in files:
    print "<!--", f, "-->"
    handler = sax_handler()
    elt_in = lxml.etree.parse(f).getroot()
    if verbose:
      print "<!-- Input -->"
      print lxml.etree.tostring(elt_in, pretty_print = True, encoding = encoding, xml_declaration = True)
    rng.assertValid(elt_in)
    lxml.sax.saxify(elt_in, handler)
    elt_out = handler.result.toXML()
    if verbose:
      print "<!-- Output -->"
      print lxml.etree.tostring(elt_out, pretty_print = True, encoding = encoding, xml_declaration = True)
    rng.assertValid(elt_out)
    if (tester):
      tester(elt_in, elt_out, handler.result)
    if verbose:
      print

def pprint(pairs):
  if verbose:
    for thing, name in pairs:
      if thing is not None:
        print "[%s]" % name
        print thing.get_POW().pprint()

def ud_tester(elt_in, elt_out, msg):
  assert isinstance(msg, rpki.up_down.message_pdu)
  if isinstance(msg.payload, rpki.up_down.list_response_pdu):
    for c in msg.payload.classes:
      pprint([(c.certs[i].cert, ("%s certificate #%d" % (c.class_name, i))) for i in xrange(len(c.certs))] + [(c.issuer, ("%s issuer" % c.class_name))])

def lr_tester(elt_in, elt_out, msg):
  assert isinstance(msg, rpki.left_right.msg)
  for obj in msg:
    if isinstance(obj, rpki.left_right.self_elt):
      pprint(((obj.bpki_cert,         "BPKI cert"),
              (obj.bpki_glue,         "BPKI glue")))
    if isinstance(obj, rpki.left_right.bsc_elt):
      pprint(((obj.signing_cert,      "Signing certificate"),
              (obj.signing_cert_crl,  "Signing certificate CRL")))
      #       (obj.pkcs10_request,    "PKCS #10 request")
    if isinstance(obj, (rpki.left_right.parent_elt, rpki.left_right.repository_elt)):
      pprint(((obj.bpki_cms_cert,     "CMS certificate"),
              (obj.bpki_cms_glue,     "CMS glue"),
              (obj.bpki_https_cert,   "HTTPS certificate"),
              (obj.bpki_https_glue,   "HTTPS glue")))
    if isinstance(obj, rpki.left_right.child_elt):
      pprint(((obj.bpki_cert,         "Certificate"),
              (obj.bpki_glue,         "Glue")))

def pp_tester(elt_in, elt_out, msg):
  assert isinstance(msg, rpki.publication.msg)
  for obj in msg:
    if isinstance(obj, rpki.publication.client_elt):
      pprint(((obj.bpki_cert,         "BPKI cert"),
              (obj.bpki_glue,         "BPKI glue")))
    if isinstance(obj, rpki.publication.certificate_elt):
      pprint(((obj.payload,         "RPKI cert"),))
    if isinstance(obj, rpki.publication.crl_elt):
      pprint(((obj.payload,         "RPKI CRL"),))
    if isinstance(obj, rpki.publication.manifest_elt):
      pprint(((obj.payload,          "RPKI manifest"),))
    if isinstance(obj, rpki.publication.roa_elt):
      pprint(((obj.payload,          "ROA"),))

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

test(fileglob = "publication-protocol-samples/*.xml",
     rng = rpki.relaxng.publication,
     sax_handler = rpki.publication.sax_handler,
     encoding = "us-ascii",
     tester = pp_tester)
