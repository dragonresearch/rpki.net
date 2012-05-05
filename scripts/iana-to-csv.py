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
from rpki.csv_utils import csv_reader, csv_writer
from rpki.resource_set import resource_bag

def iterate_xml(filename, tag):
  return lxml.etree.parse(filename).getroot().getiterator(tag)

def ns(tag):
  return "{http://www.iana.org/assignments}" + tag

tag_description = ns("description")
tag_designation = ns("designation")
tag_record      = ns("record")
tag_number      = ns("number")
tag_prefix      = ns("prefix")
tag_status      = ns("status")

handles = {}
rirs = { "legacy" : resource_bag() }

for rir in ("AfriNIC", "APNIC", "ARIN", "LACNIC", "RIPE NCC"):
  handle = rir.split()[0].lower()
  handles[rir] = handles["Assigned by %s" % rir] = handles["Administered by %s" % rir] = handle
  rirs[handle] = resource_bag()

asns     = csv_writer("asns.csv")
prefixes = csv_writer("prefixes.csv")

for record in iterate_xml("as-numbers.xml", tag_record):
  description = record.findtext(tag_description)
  if description in handles:
    asns.writerow((handles[description], record.findtext(tag_number)))
    
for record in iterate_xml("ipv4-address-space.xml", tag_record):
  designation = record.findtext(tag_designation)
  if record.findtext(tag_status) != "RESERVED":
    prefix, prefixlen = [int(i) for i in record.findtext(tag_prefix).split("/")]
    if prefixlen != 8:
      raise ValueError("%s violated /8 assumption" % record.findtext(tag_prefix))
    rirs[handles.get(designation, "legacy")] |= resource_bag.from_str("%d.0.0.0/8" % prefix)

for record in iterate_xml("ipv6-unicast-address-assignments.xml", tag_record):
  description = record.findtext(tag_description)
  if record.findtext(tag_description) in handles:
    rirs[handles[description]] |= resource_bag.from_str(record.findtext(tag_prefix))

erx = list(csv_reader("erx.csv"))
assert all(r in rirs for r, p in erx)

erx_overrides = resource_bag.from_str(",".join(p for r, p in erx), allow_overlap = True)

for rir in rirs:
  if rir != "legacy":
    rirs[rir] -= erx_overrides
    rirs[rir] |= resource_bag.from_str(",".join(p for r, p in erx if r == rir), allow_overlap = True)

for rir, bag in rirs.iteritems():
  for p in bag.v4:
    prefixes.writerow((rir, p))
  for p in bag.v6:
    prefixes.writerow((rir, p))

asns.close()
prefixes.close()
