"""
Test parser and display tool for myrpki.xml files.

$Id$

Copyright (C) 2009--2012  Internet Systems Consortium ("ISC")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import lxml.etree, rpki.resource_set, base64, subprocess

relaxng = lxml.etree.RelaxNG(file = "myrpki.rng")

tree = lxml.etree.parse("myrpki.xml").getroot()

if False:
  print lxml.etree.tostring(tree, pretty_print = True, encoding = "us-ascii", xml_declaration = True)

relaxng.assertValid(tree)

def showitems(y):
  if False:
    for k, v in y.items():
      if v:
        print " ", k, v

def tag(t):
  return "{http://www.hactrn.net/uris/rpki/myrpki/}" + t

print "My handle:", tree.get("handle")

print "Children:"
for x in tree.getiterator(tag("child")):
  print " ", x
  print "  Handle:", x.get("handle")
  print "  ASNS:  ", rpki.resource_set.resource_set_as(x.get("asns"))
  print "  IPv4:  ", rpki.resource_set.resource_set_ipv4(x.get("v4"))
  print "  Valid: ", x.get("valid_until")
  showitems(x)
print

print "ROA requests:"
for x in tree.getiterator(tag("roa_request")):
  print " ", x
  print "  ASN: ", x.get("asn")
  print "  IPv4:", rpki.resource_set.roa_prefix_set_ipv4(x.get("v4"))
  print "  IPv6:", rpki.resource_set.roa_prefix_set_ipv6(x.get("v6"))
  showitems(x)
print

def showpem(label, b64, kind):
  cmd = ("openssl", kind, "-noout", "-text", "-inform", "DER")
  if kind == "x509":
    cmd += ("-certopt", "no_pubkey,no_sigdump")
  p = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE)
  text = p.communicate(input = base64.b64decode(b64))[0]
  if p.returncode != 0:
    raise subprocess.CalledProcessError(returncode = p.returncode, cmd = cmd)
  print label, text

for x in tree.getiterator(tag("child")):
  cert = x.findtext(tag("bpki_certificate"))
  if cert:
    showpem("Child", cert, "x509")

for x in tree.getiterator(tag("parent")):
  print "Parent URI:", x.get("service_uri")
  cert = x.findtext(tag("bpki_certificate"))
  if cert:
    showpem("Parent", cert, "x509")

ca = tree.findtext(tag("bpki_ca_certificate"))
if ca:
  showpem("CA", ca, "x509")

bsc = tree.findtext(tag("bpki_bsc_certificate"))
if bsc:
  showpem("BSC EE", bsc, "x509")

repo = tree.findtext(tag("bpki_repository_certificate"))
if repo:
  showpem("Repository", repo, "x509")

req = tree.findtext(tag("bpki_bsc_pkcs10"))
if req:
  showpem("BSC EE", req, "req")

crl = tree.findtext(tag("bpki_crl"))
if crl:
  showpem("CA", crl, "crl")
