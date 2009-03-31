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

import sys, os, struct, time, rpki.x509, rpki.ipaddrs, rpki.sundial

os.environ["TZ"] = "UTC"
time.tzset()

class prefix(object):
  """Object representing one prefix.  This corresponds closely to one
  PDU in the rpki-router protocol, so closely that we use lexical
  ordering of the wire format of the PDU as the ordering for this
  class.
  """

  version = 0                           # Protocol version
  source = 0                            # Source (0 == RPKI)

  _pdu = None                           # Cached when first generated
  
  header_struct = struct.Struct("!BBHBBBB")
  serial_struct = struct.Struct("!L")

  @classmethod
  def from_asn1(cls, asn, t):
    """Read a prefix from a ROA in the tuple format used by our ASN.1 decoder."""
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
    self.color = 0
    self.announce = 1
    self.check()
    return self

  def __str__(self):
    return "%s/%s-%s[%s]" % (self.prefix, self.prefixlen, self.max_prefixlen, self.asn)

  def __cmp__(self, other):
    return cmp(self.to_pdu(), other.to_pdu())

  def check(self):
    """Check attributes to make sure they're within range."""
    assert self.announce in (0, 1)
    assert self.prefixlen >= 0 and self.prefixlen <= self.addr_type.bits
    assert self.max_prefixlen >= self.prefixlen and self.max_prefixlen <= self.addr_type.bits

  def to_pdu(self, announce = None):
    """Generate the wire format PDU for this prefix."""
    if announce is not None:
      assert announce in (0, 1)
    elif self._pdu is not None:
      return self._pdu
    pdu =  (self.header_struct.pack(self.version, self.pdu_type, self.color,
                                    announce if announce is not None else self.announce,
                                    self.prefixlen, self.max_prefixlen, self.source) +
            self.prefix.to_bytes() +
            self.serial_struct.pack(self.asn))
    if announce is None:
      assert self._pdu is None
      self._pdu = pdu
    return pdu

  @classmethod
  def from_pdu_file(cls, f):
    """Read one wire format PDU from a file.  This is intended to be
    used in an iterator, so it raises StopIteration on end of file.
    """
    b = f.read(8)
    if b == "":
      raise StopIteration
    version, pdu_type, color, announce, prefixlen, max_prefixlen, source = cls.header_struct.unpack(b)
    assert version == self.version, "PDU version is %d, expected %d" % (version, self.version)
    assert source == self.source
    self = cls.pdu_map[pdu_type]()
    self.prefixlen = prefixlen
    self.max_prefixlen = max_prefixlen
    self.color = color
    self.announce = announce
    self.prefix = self.addr_type.from_bytes(f.read(self.addr_type.bits / 8))
    self.asn = cls.serial_struct.unpack(f.read(4))
    self.check()
    return self

class v4prefix(prefix):
  """IPv4 flavor of a prefix."""
  addr_type = rpki.ipaddrs.v4addr
  pdu_type = 4

class v6prefix(prefix):
  """IPv6 flavor of a prefix."""
  addr_type = rpki.ipaddrs.v6addr
  pdu_type = 6

prefix.afi_map = { "\x00\x01" : v4prefix, "\x00\x02" : v6prefix }
prefix.pdu_map = { 4 : v4prefix, 6 : v6prefix }

class prefix_set(list):
  """Object representing a set of prefixes, that is, one versioned and
  (theoretically) consistant set of prefixes extracted from rcynic's
  output.
  """

  @classmethod
  def from_rcynic(cls, rcynic_dir):
    """Parse ROAS fetched (and validated!) by rcynic to create a new
    prefix_set.
    """
    self = cls()
    self.timestamp = rpki.sundial.now()
    self.serial = self.timestamp.totimestamp()
    for root, dirs, files in os.walk(rcynic_dir):
      for f in files:
        if f.endswith(".roa"):
          roa = rpki.x509.ROA(DER_file = os.path.join(root, f)).extract().get()
          assert roa[0] == 0, "ROA version is %d, expected 0" % roa[0]
          asn = roa[1]
          for afi, addrs in roa[2]:
            for addr in addrs:
              self.append(prefix.afi_map[afi].from_asn1(asn, addr))
    self.sort()
    for i in xrange(len(self) - 2, -1, -1):
      if self[i] == self[i + 1]:
        del self[i + 1]
    return self

prefixes = prefix_set.from_rcynic("../rcynic/rcynic-data/authenticated")

for p in prefixes:
  print "%-40s %s" % (p, ":".join(("%02X" % ord(i) for i in p.to_pdu())))
