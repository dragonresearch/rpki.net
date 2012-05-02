"""
Parse IANA XML data.

$Id$

Copyright (C) 2010-2012  Internet Systems Consortium ("ISC")

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

import sys
import lxml.etree
from rpki.csv_utils import csv_writer

def iterate_xml(filename, tag):
  return lxml.etree.parse(filename).getroot().getiterator(tag)

def ns(tag):
  return "{http://www.iana.org/assignments}" + tag

tag_description = ns("description")
tag_designation = ns("designation")
tag_record      = ns("record")
tag_number      = ns("number")
tag_prefix      = ns("prefix")

handles = {}

for rir in ("AfriNIC", "APNIC", "ARIN", "LACNIC", "RIPE NCC"):
  handles[rir] = handles["Assigned by %s" % rir] = handles["Administered by %s" % rir] = rir.split()[0].upper()

asns     = csv_writer("asns.csv")
prefixes = csv_writer("prefixes.csv")

for record in iterate_xml("as-numbers.xml", tag_record):
  description = record.findtext(tag_description)
  if description in handles:
    asns.writerow((handles[description], record.findtext(tag_number)))
    
for record in iterate_xml("ipv4-address-space.xml", tag_record):
  designation = record.findtext(tag_designation)
  if designation in handles:
    prefix = record.findtext(tag_prefix)
    p, l = prefix.split("/")
    assert l == "8", "Violated /8 assumption: %r" % prefix
    prefixes.writerow((handles[designation], "%d.0.0.0/8" % int(p)))
    
for record in iterate_xml("ipv6-unicast-address-assignments.xml", tag_record):
  description = record.findtext(tag_description)
  if record.findtext(tag_description) in handles:
    prefixes.writerow((handles[description], record.findtext(tag_prefix)))

asns.close()
prefixes.close()
