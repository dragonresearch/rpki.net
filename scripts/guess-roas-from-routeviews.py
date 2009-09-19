"""
$Id$

Pull RFC 3779 resources from a cert, attempt to mine routeviews (via
DNS, using the dnspython toolkit) for what the ROAs might look like
for the addresses found in the cert.

This doesn't handle IPv6 yet, because I didn't know about the
dns.reversename module when I wrote this.  I'll fix that.

NB: this is wild-assed guessing at best.  Even if the routeviews data
were signed, which it is not, you have no particular reason to believe
it.  Do not use output of this script production.  Sanity check.
Beware of dog.  If you issue ROAs using this script and your wallpaper
peels, your cat explodes, or your children turn blue, it's your own
fault for using this script.  You have been warned.

Copyright (C) 2009  Internet Systems Consortium ("ISC")

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

import sys, dns.resolver, rpki.x509
from rpki.ipaddrs import v4addr
from rpki.resource_set import roa_prefix_ipv4, resource_set_ipv4, resource_range_ipv4

roas = []

for filename in sys.argv[1:]:
  resources = rpki.x509.X509(Auto_file = filename).get_3779resources().v4

  while resources:
    labels = str(resources[0].min).split(".")
    labels.reverse()

    try:
      for answer in dns.resolver.query(".".join(labels) + ".asn.routeviews.org", "txt"):
        asn, prefix, prefixlen = answer.strings
        roa_prefix = roa_prefix_ipv4(v4addr(prefix), long(prefixlen))
        roa = "%s\t%s\t%s" % (roa_prefix, long(asn), filename)
        if roa not in roas:
          roas.append(roa)
        resources = resources.difference(resource_set_ipv4([roa_prefix.to_resource_range()]))

    except dns.resolver.NXDOMAIN:
      resources = resources.difference(resource_set_ipv4([resource_range_ipv4(resources[0].min, v4addr(resources[0].min + 256))]))

roas.sort()

for roa in roas:
  print roa
