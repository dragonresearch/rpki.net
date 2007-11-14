# $Id$

"""Classes dealing with sets of resources.

The basic mechanics of a resource set are the same for any of the
resources we handle (ASNs, IPv4 addresses, or IPv6 addresses), so we
can provide the same operations on any of them, even though the
underlying details vary.

We also provide some basic set operations (union, intersection, etc).
"""

import re
import rpki.ipaddrs, rpki.oids

inherit_token = "<inherit>"

class resource_range(object):
  """Generic resource range type.

  Assumes underlying type is some kind of integer.  You probably don't
  want to use this type directly.
  """

  def __init__(self, min, max):
    """Initialize and sanity check a resource_range."""
    assert min <= max, "Mis-ordered range: %s before %s" % (str(min), str(max))
    self.min = min
    self.max = max

  def __cmp__(self, other):
    """Compare two resource_range objects."""
    c = self.min - other.min
    if c == 0: c = self.max - other.max
    if c < 0:  c = -1
    if c > 0:  c =  1
    return c

class resource_range_as(resource_range):
  """Range of Autonomous System Numbers.

  Denotes a single ASN by a range whose min and max values are identical.
  """

  datum_type = long

  def __str__(self):
    """Convert a resource_range_as to string format."""
    if self.min == self.max:
      return str(self.min)
    else:
      return str(self.min) + "-" + str(self.max)

  def to_tuple(self):
    """Convert a resource_range_as to tuple format for ASN.1 encoding."""
    if self.min == self.max:
      return ("id", self.min)
    else:
      return ("range", (self.min, self.max))

class resource_range_ip(resource_range):
  """Range of (generic) IP addresses.

  Prefixes are converted to ranges on input, and ranges that can be
  represented as prefixes are written as prefixes on output.
  """

  def _prefixlen(self):
    """Determine whether a resource_range_ip can be expressed as a prefix."""
    mask = self.min ^ self.max
    prefixlen = self.datum_type.bits
    while mask & 1:
      prefixlen -= 1
      mask >>= 1
    if mask:
      return -1
    else:
      return prefixlen

  def __str__(self):
    """Convert a resource_range_ip to string format."""
    prefixlen = self._prefixlen()
    if prefixlen < 0:
      return str(self.min) + "-" + str(self.max)
    else:
      return str(self.min) + "/" + str(prefixlen)

  def to_tuple(self):
    """Convert a resource_range_ip to tuple format for ASN.1 encoding."""
    prefixlen = self._prefixlen()
    if prefixlen < 0:
      return ("addressRange", (_long2bs(self.min, self.datum_type.bits, strip = 0),
                               _long2bs(self.max, self.datum_type.bits, strip = 1)))
    else:
      return ("addressPrefix", _long2bs(self.min, self.datum_type.bits, prefixlen = prefixlen))

class resource_range_ipv4(resource_range_ip):
  """Range of IPv4 addresses."""

  datum_type = rpki.ipaddrs.v4addr

class resource_range_ipv6(resource_range_ip):
  """Range of IPv6 addresses."""

  datum_type = rpki.ipaddrs.v6addr

def _rsplit(rset, that):
  """Split a resource range into two resource ranges."""
  this = rset.pop(0)
  cell_type = type(this.min)
  assert type(this) is type(that) and type(this.max) is cell_type and \
         type(that.min) is cell_type and type(that.max) is cell_type
  if this.min < that.min:
    rset.insert(0, type(this)(this.min, cell_type(that.min - 1)))
    rset.insert(1, type(this)(that.min, this.max))
  else:
    assert this.max > that.max
    rset.insert(0, type(this)(this.min, that.max))
    rset.insert(1, type(this)(cell_type(that.max + 1), this.max))

class resource_set(list):
  """Generic resource set.

  List type containing resource ranges.  You probably don't want to
  use this type directly.
  """

  inherit = False

  def __init__(self, ini = None):
    """Initialize a resource_set."""
    if isinstance(ini, long):
      ini = str(ini)
    if ini == inherit_token:
      self.inherit = True
    elif isinstance(ini, str) and len(ini):
      self.extend(map(self.parse_str, ini.split(",")))
    elif isinstance(ini, tuple):
      self.parse_tuple(ini)
    elif isinstance(ini, list):
      self.extend(ini)
    else:
      assert ini is None or ini == ""
    assert not self.inherit or not self
    self.sort()
    if __debug__:
      for i in range(0, len(self) - 1):
        assert self[i].max < self[i+1].min, "Resource overlap: %s %s" % (self[i], self[i+1])

  def __str__(self):
    """Convert a resource_set to string format."""
    if self.inherit:
      return inherit_token
    else:
      return ",".join(map(str, self))

  def _comm(self, other):
    """Like comm(1), sort of.

    Returns a tuple of three resource sets: resources only in self,
    resources only in other, and resources in both.  Used (not very
    efficiently) as the basis for most set operations on resource
    sets.
    """
    assert not self.inherit
    assert type(self) is type(other), "Type mismatch %s %s" % (repr(type(self)), repr(type(other)))
    set1 = self[:]
    set2 = other[:]
    only1, only2, both = [], [], []
    while set1 or set2:
      if set1 and (not set2 or set1[0].max < set2[0].min):
        only1.append(set1.pop(0))
      elif set2 and (not set1 or set2[0].max < set1[0].min):
        only2.append(set2.pop(0))
      elif set1[0].min < set2[0].min:
        _rsplit(set1, set2[0])
      elif set2[0].min < set1[0].min:
        _rsplit(set2, set1[0])
      elif set1[0].max < set2[0].max:
        _rsplit(set2, set1[0])
      elif set2[0].max < set1[0].max:
        _rsplit(set1, set2[0])
      else:
        assert set1[0].min == set2[0].min and set1[0].max == set2[0].max
        both.append(set1.pop(0))
        set2.pop(0)
    return type(self)(only1), type(self)(only2), type(self)(both)

  def union(self, other):
    """Set union for resource sets."""
    assert not self.inherit
    assert type(self) is type(other)
    set1 = self[:]
    set2 = other[:]
    result = []
    while set1 or set2:
      if set1 and (not set2 or set1[0].max < set2[0].min):
        result.append(set1.pop(0))
      elif set2 and (not set1 or set2[0].max < set1[0].min):
        result.append(set2.pop(0))
      else:
        this = set1.pop(0)
        that = set2.pop(0)
        assert type(this) is type(that)
        if this.min < that.min: min = this.min
        else:                   min = that.min
        if this.max > that.max: max = this.max
        else:                   max = that.max
        result.append(type(this)(min, max))
    return type(self)(result)

  def intersection(self, other):
    """Set intersection for resource sets."""
    return self._comm(other)[2]

  def difference(self, other):
    """Set difference for resource sets."""
    return self._comm(other)[0]

  def symmetric_difference(self, other):
    """Set symmetric difference (XOR) for resource sets."""
    com = self._comm(other)
    return com[0].union(com[1])

  def contains(self, item):
    """Set membership test for resource sets."""
    assert not self.inherit
    for i in self:
      if isinstance(item, type(i)) and i.min <= item.min and i.max >= item.max:
        return True
      elif isinstance(item, type(i.min)) and i.min <= item and i.max >= item:
        return True
      else:
        assert isinstance(item, (type(i), type(i.min)))
    return False

  def issubset(self, other):
    """Test whether self is a subset (possibly improper) of other."""
    for i in self:
      if not other.contains(i):
        return False
    return True

  def issuperset(self, other):
    """Test whether self is a superset (possibly improper) of other."""
    return other.issubset(self)

  @classmethod
  def from_sql(cls, cursor, query):
    """Create resource set from an SQL query.

    cursor is a DB API 2.0 cursor object.

    query is an SQL query that returns a sequence of (min, max) pairs.
    """

    cursor.execute(query)
    return cls(ini = [cls.range_type(cls.range_type.datum_type(b),
                                     cls.range_type.datum_type(e))
                      for (b,e) in cursor.fetchall()])

class resource_set_as(resource_set):
  """ASN resource set."""

  range_type = resource_range_as

  def parse_str(self, x):
    """Parse AS resource sets from text (eg, XML attributes)."""
    r = re.match("^([0-9]+)-([0-9]+)$", x)
    if r:
      return resource_range_as(long(r.group(1)), long(r.group(2)))
    else:
      return resource_range_as(long(x), long(x))

  def parse_tuple(self, x):
    """Parse AS resource sets from intermediate form generated by ASN.1 decoder."""
    if x[0] == "asIdsOrRanges":
      for aor in x[1]:
        if aor[0] == "range":
          min = aor[1][0]
          max = aor[1][1]
        else:
          min = aor[1]
          max = min
        self.append(resource_range_as(min, max))
    else:
      assert x[0] == "inherit"
      self.inherit = True

  def to_tuple(self):
    """Encode AS resource set into intermediate form used by ASN.1 encoder."""
    if self:
      return ("asIdsOrRanges", tuple(a.to_tuple() for a in self))
    elif self.inherit:
      return ("inherit", "")
    else:
      return None

class resource_set_ip(resource_set):
  """(Generic) IP address resource set.

  You probably don't want to use this type directly.
  """

  def parse_str(self, x):
    """Parse IP address resource sets from text (eg, XML attributes)."""
    r = re.match("^([0-9:.a-fA-F]+)-([0-9:.a-fA-F]+)$", x)
    if r:
      return self.range_type(self.range_type.datum_type(r.group(1)), self.range_type.datum_type(r.group(2)))
    r = re.match("^([0-9:.a-fA-F]+)/([0-9]+)$", x)
    if r:
      min = self.range_type.datum_type(r.group(1))
      prefixlen = int(r.group(2))
      mask = (1 << (self.range_type.datum_type.bits - prefixlen)) - 1
      assert (min & mask) == 0, "Resource not in canonical form: %s" % (x)
      max = self.range_type.datum_type(min | mask)
      return self.range_type(min, max)
    raise RuntimeError, 'Bad IP resource "%s"' % (x)

  def parse_tuple(self, x):
    """Parse IP address resource sets from intermediate form generated by ASN.1 decoder."""
    if x[0] == "addressesOrRanges":
      for aor in x[1]:
        if aor[0] == "addressRange":
          min = _bs2long(aor[1][0]) << (self.range_type.datum_type.bits - len(aor[1][0]))
          max = _bs2long(aor[1][1]) << (self.range_type.datum_type.bits - len(aor[1][1]))
          mask = (1L << (self.range_type.datum_type.bits - len(aor[1][1]))) - 1
        else:
          min = _bs2long(aor[1]) << (self.range_type.datum_type.bits - len(aor[1]))
          mask = (1L << (self.range_type.datum_type.bits - len(aor[1]))) - 1
          assert (min & mask) == 0, "Resource not in canonical form: %s" % (str(x))
        max = min | mask
        self.append(self.range_type(self.range_type.datum_type(min), self.range_type.datum_type(max)))
    else:
      assert x[0] == "inherit"
      self.inherit = True

  def to_tuple(self):
    """Encode IP resource set into intermediate form used by ASN.1 encoder."""
    if self:
      return (self.afi, ("addressesOrRanges", tuple(a.to_tuple() for a in self)))
    elif self.inherit:
      return (self.afi, ("inherit", ""))
    else:
      return None

class resource_set_ipv4(resource_set_ip):
  """IPv4 address resource set."""

  range_type = resource_range_ipv4
  afi = "\x00\x01"

class resource_set_ipv6(resource_set_ip):
  """IPv6 address resource set."""

  range_type = resource_range_ipv6
  afi = "\x00\x02"

def _bs2long(bs):
  """Convert a bitstring (tuple representation) into a long."""
  return reduce(lambda x, y: (x << 1) | y, bs, 0L)

def _long2bs(number, addrlen, prefixlen = None, strip = None):
  """Convert a long into a tuple bitstring.  This is a bit complicated
  because it supports the fiendishly compact encoding used in RFC 3779.
  """
  assert prefixlen is None or strip is None
  bs = []
  while number:
    bs.append(int(number & 1))
    number >>= 1
  if addrlen > len(bs):
    bs.extend((0 for i in xrange(addrlen - len(bs))))
  bs.reverse()
  if prefixlen is not None:
    return tuple(bs[0:prefixlen])
  if strip is not None:
    while bs and bs[-1] == strip:
      bs.pop()
  return tuple(bs)

class resource_bag(object):
  """Container to simplify passing around the usual triple of AS,
  IPv4, and IPv6 resource sets.
  """

  def __init__(self, as = None, v4 = None, v6 = None, valid_until = None):
    self.as = as or resource_set_as()
    self.v4 = v4 or resource_set_ipv4()
    self.v6 = v6 or resource_set_ipv6()
    self.valid_until = valid_until

  def oversized(self, other):
    """True iff self is oversized with respect to other."""
    return not self.as.issubset(other.as) or \
           not self.v4.issubset(other.v4) or \
           not self.v6.issubset(other.v6)

  def undersized(self, other):
    """True iff self is undersized with respect to other."""
    return not other.as.issubset(self.as) or \
           not other.v4.issubset(self.v4) or \
           not other.v6.issubset(self.v6)

  @classmethod
  def from_asn1_tuples(cls, exts):
    """Build a resource_bag from intermediate form returned by ASN.1 decoder."""
    as = None
    v4 = None
    v6 = None
    for x in exts:
      if x[0] == rpki.oids.name2oid["sbgp-autonomousSysNum"]: # 
        assert x[2][1] is None, "RDI not implemented: %s" % (str(x))
        assert as is None
        as = resource_set_as(x[2][0])
      if x[0] == rpki.oids.name2oid["sbgp-ipAddrBlock"]:
        for fam in x[2]:
          if fam[0] == resource_set_ipv4.afi:
            assert v4 is None
            v4 = resource_set_ipv4(fam[1])
          if fam[0] == resource_set_ipv6.afi:
            assert v6 is None
            v6 = resource_set_ipv6(fam[1])
    return cls(as, v4, v6)

  def empty(self):
    """Return True iff all resource sets in this bag are empty."""
    return not self.as and not self.v4 and not self.v6

  def __eq__(self, other):
    return self.as == other.as and self.v4 == other.v4 and self.v6 == other.v6

  def __ne__(self, other):
    return not (self == other)

  def intersection(self, other):
    """Compute intersection with another resource_bag.
    valid_until attribute (if any) inherits from self.
    """
    return self.__class__(self.as.intersection(other.as),
                          self.v4.intersection(other.v4),
                          self.v6.intersection(other.v6),
                          self.valid_until)

# Test suite for set operations.  This will probably go away eventually

if __name__ == "__main__":

  def test(t, s1, s2):
    print
    r1 = t(s1)
    r2 = t(s2)
    print "x:  ", r1
    print "y:  ", r2
    v1 = r1._comm(r2)
    v2 = r2._comm(r1)
    assert v1[0] == v2[1] and v1[1] == v2[0] and v1[2] == v2[2]
    for i in r1: assert r1.contains(i) and r1.contains(i.min) and r1.contains(i.max)
    for i in r2: assert r2.contains(i) and r2.contains(i.min) and r2.contains(i.max)
    for i in v1[0]: assert r1.contains(i) and not r2.contains(i)
    for i in v1[1]: assert not r1.contains(i) and r2.contains(i)
    for i in v1[2]: assert r1.contains(i) and r2.contains(i)
    v1 = r1.union(r2)
    v2 = r2.union(r1)
    assert v1 == v2
    print "x|y:", v1
    v1 = r1.difference(r2)
    v2 = r2.difference(r1)
    print "x-y:", v1
    print "y-x:", v2
    v1 = r1.symmetric_difference(r2)
    v2 = r2.symmetric_difference(r1)
    assert v1 == v2
    print "x^y:", v1
    v1 = r1.intersection(r2)
    v2 = r2.intersection(r1)
    assert v1 == v2
    print "x&y:", v1

  print "Testing set operations on resource sets"
  test(resource_set_as, "1,2,3,4,5,6,11,12,13,14,15", "1,2,3,4,5,6,111,121,131,141,151")
  test(resource_set_ipv4, "10.0.0.44/32,10.6.0.2/32", "10.3.0.0/24,10.0.0.77/32")
  test(resource_set_ipv4, "10.0.0.44/32,10.6.0.2/32", "10.0.0.0/24")
  test(resource_set_ipv4, "10.0.0.0/24", "10.3.0.0/24,10.0.0.77/32")
