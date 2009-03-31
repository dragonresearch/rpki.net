"""
Router origin-authentication update job.  Work in progress.

This should be run under cron, after rcynic finishes.  It chews over
the data rcynic collected and generates output suitable as input for a
companion server program (not yet written) which serves the resulting
data to the routers.

$Id$

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

import sys, os, struct, rpki.x509, rpki.ipaddrs

rcynic_dir = "../rcynic/rcynic-data/authenticated"

class prefix(object):

  @classmethod
  def from_asn1(cls, asn, t):
    x = 0L
    for y in t[0]:
      x = (x << 1) | y
    for y in xrange(cls.addr_type.bits - len(t[0])):
      x = (x << 1)
    self = cls()
    self.asn = asn
    self.prefix = cls.addr_type(x)
    self.prefixlen = len(t[0])
    self.max_prefixlen = self.prefixlen if t[1] is None else t[1]
    self.pdu = self.to_pdu()
    return self

  def __str__(self):
    return "%s/%s-%s[%s]" % (self.prefix, self.prefixlen, self.max_prefixlen, self.asn)

  def __cmp__(self, other):
    return cmp(self.pdu, other.pdu)

  def to_pdu(self, announce = 1, color = 0):
    return (struct.pack("!BBHBBBB", 0, self.pdu_type, color, announce, self.prefixlen, self.max_prefixlen, 0) +
            self.prefix.to_bytes() +
            struct.pack("!L", self.asn))

class v4prefix(prefix):
  addr_type = rpki.ipaddrs.v4addr
  pdu_type = 4

class v6prefix(prefix):
  addr_type = rpki.ipaddrs.v6addr
  pdu_type = 6

prefix.map = { "\x00\x01" : v4prefix,
               "\x00\x02" : v6prefix }

prefixes = []

for root, dirs, files in os.walk(rcynic_dir):
  for f in files:
    if f.endswith(".roa"):
      roa = rpki.x509.ROA(DER_file = os.path.join(root, f)).extract().get()
      assert roa[0] == 0, "ROA version is %d, expected 0" % roa[0]
      asn = roa[1]
      for afi, addrs in roa[2]:
        for addr in addrs:
          prefixes.append(prefix.map[afi].from_asn1(asn, addr))

prefixes.sort()

for i in xrange(len(prefixes) - 2, -1, -1):
  if prefixes[i] == prefixes[i + 1]:
    del prefixes[i + 1]

for p in prefixes:
  print "%-40s %s" % (p, ":".join(("%02X" % ord(i) for i in p.to_pdu())))
