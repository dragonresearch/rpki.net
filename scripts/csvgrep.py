"""
Utility to simplify finding handles in one of the pseudo-RIR databases.

Usage: python csvgrep.py datum [datum ...]

where each datum is an ASN, IP address, or IP prefix.

ASNs are recognized by being pure integers; IP addreses are recognized
by having dots (IPv4) or colons (IPv6).

After eating all of the command line arguments, we search asns.csv for
any ASNs given, and prefixes.csv for any prefixes given.

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

import sys, rpki.resource_set, rpki.myrpki

asn  = rpki.resource_set.resource_set_as()
ipv4 = rpki.resource_set.resource_set_ipv4()
ipv6 = rpki.resource_set.resource_set_ipv6()

for datum in sys.argv[1:]:
  if datum.replace("-", "").isdigit():
    t = asn
  else:
    t = ipv6 if ":" in datum else ipv4
    if "-" not in datum and "/" not in datum:
      datum = datum + "-" + datum
  t.append(t.parse_str(datum))

#print "Looking for: ASNs %s IPv4 %s IPv6 %s" % (asn, ipv4, ipv6)

def matches(resource_set, datum):
  return resource_set.intersection(resource_set.__class__(datum))

if asn:
  for h, a in rpki.myrpki.csv_reader("asns.csv", columns = 2):
    if matches(asn, a):
      print h, a

if ipv4 or ipv6:
  for h, a in rpki.myrpki.csv_reader("prefixes.csv", columns = 2):
    t = ipv6 if ":" in a else ipv4
    if t and matches(t, a):
      print h, a
