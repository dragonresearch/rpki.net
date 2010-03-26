"""
Generate config for a test RPKI root certificate for resources
specified in asns.csv and prefixes.csv.

This script is separate from arin-to-csv.py so that we can convert on
the fly rather than having to pull the entire database into memory.

$Id: arin-rootcert.py 3132 2010-03-23 20:33:08Z sra $

Copyright (C) 2009-2010  Internet Systems Consortium ("ISC")

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

import csv, myrpki, sys, rpki.resource_set, rpki.ipaddrs

holder = "ripe"

if len(sys.argv) == 2:
  holder = sys.argv[1]
elif len(sys.argv) > 1:
  raise RuntimeError, "Usage: %s [holder]" % sys.argv[0]

print '''\
[req]
default_bits                    = 2048
default_md                      = sha256
distinguished_name              = req_dn
prompt                          = no
encrypt_key                     = no

[req_dn]
CN                              = Pseudo-%(HOLDER)s testbed root RPKI certificate

[x509v3_extensions]
basicConstraints                = critical,CA:true
subjectKeyIdentifier            = hash
keyUsage                        = critical,keyCertSign,cRLSign
subjectInfoAccess               = 1.3.6.1.5.5.7.48.5;URI:rsync://%(holder)s.rpki.net/rpki/%(holder)s/,1.3.6.1.5.5.7.48.10;URI:rsync://%(holder)s.rpki.net/rpki/%(holder)s/root.mnf
certificatePolicies             = critical,1.3.6.1.5.5.7.14.2
sbgp-autonomousSysNum           = critical,@rfc3779_asns
sbgp-ipAddrBlock                = critical,@rfc3997_addrs

[rfc3779_asns]
''' % { "holder" : holder.lower(),
        "HOLDER" : holder.upper() }

for i, asn in enumerate(asn for handle, asn in myrpki.csv_open("asns.csv")):
  print "AS.%d = %s" % (i, asn)

print '''\

[rfc3997_addrs]

'''

v4 = []
v6 = []

for handle, prefix in myrpki.csv_open("prefixes.csv"):
  if ":" in prefix:
    p, l = prefix.split("/")
    v6.append(rpki.resource_set.resource_range_ipv6.make_prefix(rpki.ipaddrs.v6addr(p), int(l)))
  else:
    a, b = prefix.split("-")
    v4.append(rpki.resource_set.resource_range_ipv4(rpki.ipaddrs.v4addr(a), rpki.ipaddrs.v4addr(b)))

v4.sort()
v6.sort()

for v in (v4, v6):
  for i in xrange(len(v) - 2, -1, -1):
    if v[i].max + 1 >= v[i+1].min:
      v[i].max = v[i+1].max
      del v[i+1]

for i, prefix in enumerate(v4):
  print "IPv4.%d = %s" % (i, prefix)

for i, prefix in enumerate(v6):
  print "IPv6.%d = %s" % (i, prefix)
