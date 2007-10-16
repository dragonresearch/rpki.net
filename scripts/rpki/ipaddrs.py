# $Id$

"""Classes to represent IP addresses.

Given some of the other operations we need to perform on them, it's
most convenient to represent IP addresses as Python "long" values.
The classes in this module just wrap suitable read/write syntax around
the underlying "long" type.

These classes also supply a "bits" attribute for use by other code
built on these classes; for the most part, IPv6 addresses really are
just IPv4 addresses with more bits, so we supply the number of bits
once, here, thus avoiding a lot of duplicate code elsewhere.
"""

import socket, struct

class v4addr(long):
  """IPv4 address.

  Derived from long, but supports IPv4 print syntax.
  """

  bits = 32
  
  def __new__(cls, x):
    """Construct a v4addr object."""
    if isinstance(x, str):
      y = struct.unpack("!I", socket.inet_pton(socket.AF_INET, x))
      x = y[0]
    return long.__new__(cls, x)

  def __str__(self):
    """Convert a v4addr object to string format."""
    return socket.inet_ntop(socket.AF_INET, struct.pack("!I", long(self)))

class v6addr(long):
  """IPv6 address.

  Derived from long, but supports IPv6 print syntax.
  """

  bits = 128

  def __new__(cls, x):
    """Construct a v6addr object."""
    if isinstance(x, str):
      y = struct.unpack("!QQ", socket.inet_pton(socket.AF_INET6, x))
      x = (y[0] << 64) | y[1]
    return long.__new__(cls, x)

  def __str__(self):
    """Convert a v6addr object to string format."""
    return socket.inet_ntop(socket.AF_INET6,
                            struct.pack("!QQ", long(self) >> 64, long(self) & 0xFFFFFFFFFFFFFFFF))
