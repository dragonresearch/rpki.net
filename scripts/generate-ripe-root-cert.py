"""
Parse IANA XML data and write out just what we need to generate a root
cert for Pseudo-RIPE.

$Id$

Copyright (C) 2010  Internet Systems Consortium ("ISC")

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

import sys, lxml.etree, rpki.myrpki

def ns(tag):
  return "{http://www.iana.org/assignments}" + tag

tag_registry    = ns("registry")
tag_description = ns("description")
tag_designation = ns("designation")
tag_record      = ns("record")
tag_number      = ns("number")
tag_prefix      = ns("prefix")

asn_xml  = lxml.etree.parse("as-numbers.xml").getroot()
ipv4_xml = lxml.etree.parse("ipv4-address-space.xml").getroot()
ipv6_xml = lxml.etree.parse("ipv6-unicast-address-assignments.xml").getroot()

asns     = rpki.myrpki.csv_writer("asns.csv")
prefixes = rpki.myrpki.csv_writer("prefixes.csv")

for record in asn_xml.getiterator(tag_record):
  if record.findtext(tag_description) == "Assigned by RIPE NCC":
    asns.writerow(("RIPE", record.findtext(tag_number)))
    
for record in ipv4_xml.getiterator(tag_record):
  if record.findtext(tag_designation) in ("RIPE NCC", "Administered by RIPE NCC"):
    prefix = record.findtext(tag_prefix)
    p, l = prefix.split("/")
    assert l == "8", "Violated /8 assumption: %r" % prefix
    prefixes.writerow(("RIPE", "%d.0.0.0/8" % int(p)))
    
for record in ipv6_xml.getiterator(tag_record):
  if record.findtext(tag_description) == "RIPE NCC":
    prefixes.writerow(("RIPE", record.findtext(tag_prefix)))

asns.close()
prefixes.close()
