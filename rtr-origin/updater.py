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

class pdu(object):
  """Object representing a generic PDU in the rpki-router protocol.
  Real PDUs are subclasses of this class.
  """

  version = 0                           # Protocol version

  _pdu = None                           # Cached when first generated

  header_struct = struct.Struct("!BB")

  def __cmp__(self, other):
    return cmp(self.to_pdu(), other.to_pdu())

  def check(self):
    """Check attributes to make sure they're within range."""
    pass

  @classmethod
  def from_pdu_file(cls, f):
    """Read one wire format PDU from a file.  This is intended to be
    used in an iterator, so it raises StopIteration on end of file.
    """
    assert cls._pdu is None
    b = f.read(cls.header_struct.size)
    if b == "":
      raise StopIteration
    version, pdu_type = cls.header_struct.unpack(b)
    assert version == cls.version, "PDU version is %d, expected %d" % (version, cls.version)
    self = cls.pdu_map[pdu_type].from_pdu_file_helper(f, b)
    self.check()
    return self

class pdu_with_serial(pdu):
  """Base class for PDUs consisting of just a serial number."""

  header_struct = struct.Struct("!BBHL")

  def __str__(self):
    return "#%s" % self.serial

  def to_pdu(self):
    """Generate the wire format PDU for this prefix."""
    if self._pdu is None:
      self._pdu = self.header_struct.pack(self.version, self.pdu_type, 0, self.serial)
    return self._pdu

  @classmethod
  def from_pdu_file_helper(cls, f, b):
    """Read one wire format prefix PDU from a file."""
    self = cls()
    b += f.read(cls.header_struct.size - len(b))
    version, pdu_type, zero, self.serial = cls.header_struct.unpack(b)
    assert zero == 0
    assert b == self.to_pdu()
    return self

class pdu_empty(pdu):
  """Base class for emtpy PDUs."""

  header_struct = struct.Struct("!BBH")

  def to_pdu(self):
    """Generate the wire format PDU for this prefix."""
    if self._pdu is None:
      self._pdu = self.header_struct.pack(self.version, self.pdu_type, 0)
    return self._pdu

  @classmethod
  def from_pdu_file_helper(cls, f, b):
    """Read one wire format prefix PDU from a file."""
    self = cls()
    b += f.read(cls.header_struct.size - len(b))
    version, pdu_type, zero = cls.header_struct.unpack(b)
    assert zero == 0
    assert b == self.to_pdu()
    return self

class serial_notify(pdu_with_serial):
  """Serial Notify PDU."""
  pdu_type = 0

class serial_query(pdu_with_serial):
  """Serial Query PDU."""
  pdu_type = 1

class reset_query(pdu_empty):
  """Reset Query PDU."""
  pdu_type = 2

class cache_response(pdu_empty):
  """Cache Response PDU."""
  pdu_type = 3

class end_of_data(pdu_with_serial):
  """End of Data PDU."""
  pdu_type = 7

class cache_reset(pdu_empty):
  """Cache reset PDU."""
  pdu_type = 8

class prefix(pdu):
  """Object representing one prefix.  This corresponds closely to one
  PDU in the rpki-router protocol, so closely that we use lexical
  ordering of the wire format of the PDU as the ordering for this
  class.
  """

  source = 0                            # Source (0 == RPKI)

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
    plm = "%s/%s-%s" % (self.prefix, self.prefixlen, self.max_prefixlen)
    return "%s %8s  %-32s %s" % ("+" if self.announce else "-", self.asn, plm, ":".join(("%02X" % ord(b) for b in self.to_pdu())))

  def pprint(self):
    print "# Class:       ", self.__class__.__name__
    print "# ASN:         ", self.asn
    print "# Prefix:      ", self.prefix
    print "# Prefixlen:   ", self.prefixlen
    print "# MaxPrefixlen:", self.max_prefixlen
    print "# Color:       ", self.color
    print "# Announce:    ", self.announce

  def check(self):
    """Check attributes to make sure they're within range."""
    assert self.announce in (0, 1)
    assert self.prefixlen >= 0 and self.prefixlen <= self.addr_type.bits
    assert self.max_prefixlen >= self.prefixlen and self.max_prefixlen <= self.addr_type.bits
    assert len(self.to_pdu()) == 12 + self.addr_type.bits / 8, "Expected %d byte PDU, got %d" % (12 + self.addr_type.bits / 8, len(self.to_pdu()))

  def to_pdu(self, announce = None):
    """Generate the wire format PDU for this prefix."""
    if announce is not None:
      assert announce in (0, 1)
    elif self._pdu is not None:
      return self._pdu
    pdu = (self.header_struct.pack(self.version, self.pdu_type, self.color,
                                   announce if announce is not None else self.announce,
                                   self.prefixlen, self.max_prefixlen, self.source) +
           self.prefix.to_bytes() +
           self.serial_struct.pack(self.asn))
    if announce is None:
      assert self._pdu is None
      self._pdu = pdu
    return pdu

  @classmethod
  def from_pdu_file_helper(cls, f, b):
    """Read one wire format prefix PDU from a file."""
    self = cls()
    b += f.read(cls.header_struct.size - len(b))
    p = b
    version, pdu_type, self.color, self.announce, self.prefixlen, self.max_prefixlen, source = cls.header_struct.unpack(b)
    assert source == cls.source
    b = f.read(self.addr_type.bits / 8)
    p += b
    self.prefix = self.addr_type.from_bytes(b)
    b = f.read(cls.serial_struct.size)
    p += b
    self.asn = cls.serial_struct.unpack(b)[0]
    assert p == self.to_pdu()
    return self

class ipv4_prefix(prefix):
  """IPv4 flavor of a prefix."""
  pdu_type = 4
  addr_type = rpki.ipaddrs.v4addr

class ipv6_prefix(prefix):
  """IPv6 flavor of a prefix."""
  pdu_type = 6
  addr_type = rpki.ipaddrs.v6addr

class error_report(pdu):
  """Error Report PDU.  This is kind of painful to parse, an explicit
  count for the encapsulated PDU would simplify this considerably.
  """

  pdu_type = 10

  header_struct = struct.Struct("!BBH")
  errlen_struct = struct.Struct("!B")

  errmsg = ""

  def __str__(self):
    return "#%s: %s" % (self.errno, self.errmsg)

  def to_pdu(self):
    """Generate the wire format PDU for this prefix."""
    if self._pdu is None:
      assert isinstance(self.errno, int)
      assert isinstance(self.errpdu, pdu)
      assert not isinstance(self.errpdu, error_report)
      self._pdu = (self.header_struct.pack(self.version, self.pdu_type, self.errno) +
                   self.errpdu.to_pdu() +
                   self.errlen_struct.pack(len(self.errmsg)) +
                   self.errmsg)
    return self._pdu

  @classmethod
  def from_pdu_file_helper(cls, f, b):
    """Read one wire format prefix PDU from a file."""
    self = cls()
    b += f.read(cls.header_struct.size - len(b))
    version, pdu_type, self.errno = cls.header_struct.unpack(b)
    self.errpdu = pdu.from_pdu_file(f)
    b = f.read(cls.errlen_struct.size)
    n = cls.errlen_struct.unpack(b)
    if n:
      self.errmsg = f.read(n)
    return self

prefix.afi_map = { "\x00\x01" : ipv4_prefix, "\x00\x02" : ipv6_prefix }

pdu.pdu_map = dict((p.pdu_type, p) for p in (ipv4_prefix, ipv6_prefix, serial_notify, serial_query, reset_query, cache_response, end_of_data, cache_reset, error_report))

class pdufile(file):
  """File subclass with PDU iterator."""

  def __iter__(self):
    return self

  def next(self):
    return pdu.from_pdu_file(self)

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

  def to_file(self, filename):
    """Low-level method to write prefix_set to a file."""
    f = pdufile(filename, "wb")
    for p in self:
      f.write(p.to_pdu())
    f.close()

  @classmethod
  def from_file(cls, filename):
    """Low-level method to read prefix_set from a file."""
    self = cls()
    f = pdufile(filename, "rb")
    for p in f:
      self.append(p)
    f.close()
    return self

  def diff_to_file(self, other, outputfile):
    """Compare this prefix_set with an older one and write a file
    consisting of the changes.  Since we store prefix_sets in sorted
    order, computing the difference is a trivial linear comparison.
    """
    f = pdufile(outputfile, "wb")
    old = other[:]
    new = self[:]
    while old and new:
      if old[0] < new[0]:
        f.write(old.pop(0).to_pdu(announce = 0))
      elif old[0] > new[0]:
        f.write(new.pop(0).to_pdu(announce = 1))
      else:
        del old[0]
        del new[0]
    while old:
      f.write(old.pop(0).to_pdu(announce = 0))
    while new:
      f.write(new.pop(0).to_pdu(announce = 1))
    f.close()

def test1():
  prefixes = prefix_set.from_rcynic("../rcynic/rcynic-data/authenticated")
  for p in prefixes:
    print p
  prefixes.to_file("fnord")
  fnord = prefix_set.from_file("fnord")
  for p in fnord:
    print p
  os.unlink("fnord")
  print prefixes == fnord

def test2():
  p1 = prefix_set.from_rcynic("../rcynic/rcynic-data/authenticated")
  p2 = prefix_set.from_rcynic("../rpkid/testbed.dir/rcynic-data/authenticated")
  p2.diff_to_file(p1, "fnord")
  fnord = prefix_set.from_file("fnord")
  print "# Old:"
  for p in p1: print p
  print "# New:"
  for p in p2: print p
  print "# Diff:"
  for p in fnord: print p
  os.unlink("fnord")

if __name__ == "__main__":
  test2()
