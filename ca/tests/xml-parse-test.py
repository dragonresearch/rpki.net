# $Id$
#
# Copyright (C) 2010  Internet Systems Consortium ("ISC")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.
#
# Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
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

import glob
import lxml.etree
import rpki.up_down
import rpki.left_right
import rpki.publication
import rpki.publication_control
import rpki.relaxng

verbose = False

def test(fileglob, rng, parser, encoding, tester = None):
    files = glob.glob(fileglob)
    files.sort()
    for f in files:
        print "<!--", f, "-->"
        elt_in = lxml.etree.parse(f).getroot()
        if verbose:
            print "<!-- Input -->"
            print lxml.etree.tostring(elt_in, pretty_print = True, encoding = encoding, xml_declaration = True)
        rng.assertValid(elt_in)
        parsed  = parser.fromXML(elt_in)
        elt_out = parsed.toXML()
        if verbose:
            print "<!-- Output -->"
            print lxml.etree.tostring(elt_out, pretty_print = True, encoding = encoding, xml_declaration = True)
        rng.assertValid(elt_out)
        if tester:
            tester(elt_in, elt_out, parsed)
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
        if isinstance(obj, rpki.left_right.parent_elt):
            pprint(((obj.bpki_cert,         "BPKI certificate"),
                    (obj.bpki_glue,         "BPKI glue")))
        if isinstance(obj, (rpki.left_right.child_elt, rpki.left_right.repository_elt)):
            pprint(((obj.bpki_cert,         "BPKI certificate"),
                    (obj.bpki_glue,         "BPKI glue")))

def pp_tester(elt_in, elt_out, msg):
    assert isinstance(msg, rpki.publication.msg)
    for obj in msg:
        if isinstance(obj, rpki.publication.publish_elt):
            pprint(((obj.payload,          "Publish object"),))
        if isinstance(obj, rpki.publication.withdraw_elt):
            pprint(((None,                 "Withdraw object"),))

def pc_tester(elt_in, elt_out, msg):
    assert isinstance(msg, rpki.publication_control.msg)
    for obj in msg:
        if isinstance(obj, rpki.publication_control.client_elt):
            pprint(((obj.bpki_cert,         "BPKI cert"),
                    (obj.bpki_glue,         "BPKI glue")))

test(fileglob = "up-down-protocol-samples/*.xml",
     rng = rpki.relaxng.up_down,
     parser = rpki.up_down.msg,
     encoding = "utf-8",
     tester = ud_tester)

test(fileglob = "left-right-protocol-samples/*.xml",
     rng = rpki.relaxng.left_right,
     parser = rpki.left_right.msg,
     encoding = "us-ascii",
     tester = lr_tester)

test(fileglob = "publication-protocol-samples/*.xml",
     rng = rpki.relaxng.publication,
     parser = rpki.publication.msg,
     encoding = "us-ascii",
     tester = pp_tester)

test(fileglob = "publication-control-protocol-samples/*.xml",
     rng = rpki.relaxng.publication_control,
     parser = rpki.publication_control.msg,
     encoding = "us-ascii",
     tester = pc_tester)
