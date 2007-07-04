# $Id$

import re, ipaddrs

class resource_range(object):
  """
  Generic resource range type.  Assumes underlying type is some kind of integer.
  You probably don't want to use this type directly.
  """

  def __init__(self, min, max):
    assert min <= max, "Mis-ordered range: %s before %s" % (str(min), str(max))
    self.min = min
    self.max = max

  def __cmp__(self, other):
    c = self.min - other.min
    if c == 0:
      c = self.max - other.max
    return c

class resource_range_as(resource_range):
  """
  Range of Autonomous System Numbers.
  Denote a single ASN by a range whose min and max values are identical.
  """

  def __str__(self):
    if self.min == self.max:
      return str(self.min)
    else:
      return str(self.min) + "-" + str(self.max)

class resource_range_ip(resource_range):
  """
  Range of (generic) IP addresses.  Prefixes are converted to ranges
  on input, and ranges that can be represented as prefixes are written
  as prefixes on output.
  """

  def __str__(self):
    mask = self.min ^ self.max
    prefixlen = self.min.bits
    while mask & 1:
      prefixlen -= 1
      mask >>= 1
    if mask:
      return str(self.min) + "-" + str(self.max)
    else:
      return str(self.min) + "/" + str(prefixlen)

class resource_range_ipv4(resource_range_ip):
  """
  Range of IPv4 addresses.
  """
  pass

class resource_range_ipv6(resource_range_ip):
  """
  Range of IPv6 addresses.
  """
  pass

class resource_set(list):
  """
  Generic resource set.  List type containing resource ranges.
  You probably don't want to use this type directly.
  """

  def __init__(self, s):
    if s:
      self.extend(map(self.parse, s.split(",")))
      self.sort()
      if __debug__:
        for i in range(0, len(self) - 1):
          assert self[i].max < self[i + 1].min, 'Resource overlap "%s"' % (s)

  def __str__(self):
    return ",".join(map(str, self))

class resource_set_as(resource_set):
  """
  ASN resource set.
  """

  def parse(self, x):
    r = re.match("^([0-9]+)-([0-9]+)$", x)
    if r:
      return resource_range_as(long(r.group(1)), long(r.group(2)))
    else:
      return resource_range_as(long(x), long(x))

class resource_set_ip(resource_set):
  """
  (Generic) IP address resource set.
  You probably don't want to use this type directly.
  """

  def parse(self, x):
    r = re.match("^([0-9:.a-fA-F]+)-([0-9:.a-fA-F]+)$", x)
    if r:
      return self.range_type(self.addr_type(r.group(1)), self.addr_type(r.group(2)))
    r = re.match("^([0-9:.a-fA-F]+)/([0-9]+)$", x)
    if r:
      min = self.addr_type(r.group(1))
      prefixlen = int(r.group(2))
      mask = (1 << (self.addr_type.bits - prefixlen)) - 1
      assert (min & mask) == 0, "Resource not in canonical form: %s" % (x)
      max = min | mask
      return self.range_type(min, max)
    raise RuntimeError, 'Bad IP resource "%s"' % (x)

class resource_set_ipv4(resource_set_ip):
  """
  IPv4 address resource set.
  """

  addr_type = ipaddrs.v4addr
  range_type = resource_range_ipv4

class resource_set_ipv6(resource_set_ip):
  """
  IPv6 address resource set.
  """

  addr_type = ipaddrs.v6addr
  range_type = resource_range_ipv6
