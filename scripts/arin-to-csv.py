"""
Parse a WHOIS research dump and write out (just) the RPKI-relevant
fields in myrpki-format CSV syntax.

NB: The input data for this script comes from ARIN under an agreement
that allows research use but forbids redistribution, so if you think
you need a copy of the data, please talk to ARIN about it, not us.

Input format used to be RPSL WHOIS dump, but ARIN recently went Java,
so we have to parse a 3.5GB XML "document".  Credit to Liza Daly for
explaining the incantations needed to convince lxml to do this nicely,
see: http://www.ibm.com/developerworks/xml/library/x-hiperfparse/

$Id$

Copyright (C) 2009-2012  Internet Systems Consortium ("ISC")

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

import sys, lxml.etree

from rpki.csv_utils import csv_writer

def ns(tag):
  return "{http://www.arin.net/bulkwhois/core/v1}" + tag

tag_asn		  = ns("asn")
tag_net           = ns("net")
tag_org           = ns("org")
tag_poc           = ns("poc")
tag_orgHandle     = ns("orgHandle")
tag_netBlock      = ns("netBlock")
tag_type          = ns("type")
tag_startAddress  = ns("startAddress")
tag_endAddress    = ns("endAddress")
tag_startAsNumber = ns("startAsNumber")
tag_endAsNumber   = ns("endAsNumber")

def find(node, tag):
  return node.findtext(tag).strip()

def do_asn(node):
  asns.writerow((find(node, tag_orgHandle),
                 "%s-%s" % (find(node, tag_startAsNumber),
                            find(node, tag_endAsNumber))))

erx_table = {
  "AF" : "afrinic",
  "AP" : "apnic",
  "AR" : "arin",
  "AV" : "arin",
  "FX" : "afrinic",
  "LN" : "lacnic",
  "LX" : "lacnic",
  "PV" : "apnic",
  "PX" : "apnic",
  "RN" : "ripe",
  "RV" : "ripe",
  "RX" : "ripe" }

def do_net(node):
  handle = find(node, tag_orgHandle)
  for netblock in node.iter(tag_netBlock):
    tag = find(netblock, tag_type)
    startAddress = find(netblock, tag_startAddress)
    endAddress = find(netblock, tag_endAddress)
    if not startAddress.endswith(".000") and not startAddress.endswith(":0000"):
      continue
    if not endAddress.endswith(".255") and not endAddress.endswith(":FFFF"):
      continue
    if tag in ("DS", "DA", "IU"):
      prefixes.writerow((handle, "%s-%s" % (startAddress, endAddress)))
    elif tag in erx_table:
      erx.writerow((erx_table[tag], "%s-%s" % (startAddress, endAddress)))

dispatch = { tag_asn : do_asn, tag_net : do_net }

asns     = csv_writer("asns.csv")
prefixes = csv_writer("prefixes.csv")
erx      = csv_writer("erx.csv")

root = None

for event, node in lxml.etree.iterparse(sys.stdin):

  if root is None:
    root = node
    while root.getparent() is not None:
      root = root.getparent()

  if node.getparent() is root:

    if node.tag in dispatch:
      dispatch[node.tag](node)

    node.clear()
    while node.getprevious() is not None:
      del node.getparent()[0]

asns.close()
prefixes.close()
erx.close()
