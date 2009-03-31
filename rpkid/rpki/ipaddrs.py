"""Classes to represent IP addresses.

Given some of the other operations we need to perform on them, it's
most convenient to represent IP addresses as Python "long" values.
The classes in this module just wrap suitable read/write syntax around
the underlying "long" type.

These classes also supply a "bits" attribute for use by other code
built on these classes; for the most part, IPv6 addresses really are
just IPv4 addresses with more bits, so we supply the number of bits
once, here, thus avoiding a lot of duplicate code elsewhere.

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


Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
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
      return cls.from_bytes(socket.inet_pton(socket.AF_INET, ".".join(str(int(i)) for i in x.split("."))))
    else:
      return long.__new__(cls, x)

  def to_bytes(self):
    """Convert a v4addr object to a raw byte string."""
    return struct.pack("!I", long(self))

  @classmethod
  def from_bytes(cls, x):
    """Convert from a raw byte string to a v4addr object."""
    return cls(struct.unpack("!I", x)[0])

  def __str__(self):
    """Convert a v4addr object to string format."""
    return socket.inet_ntop(socket.AF_INET, self.to_bytes())

class v6addr(long):
  """IPv6 address.

  Derived from long, but supports IPv6 print syntax.
  """

  bits = 128

  def __new__(cls, x):
    """Construct a v6addr object."""
    if isinstance(x, str):
      return cls.from_bytes(socket.inet_pton(socket.AF_INET6, x))
    else:
      return long.__new__(cls, x)

  def to_bytes(self):
    """Convert a v6addr object to a raw byte string."""
    return struct.pack("!QQ", long(self) >> 64, long(self) & 0xFFFFFFFFFFFFFFFF)

  @classmethod
  def from_bytes(cls, x):
    """Convert from a raw byte string to a v6addr object."""
    x = struct.unpack("!QQ", x)
    return cls((x[0] << 64) | x[1])

  def __str__(self):
    """Convert a v6addr object to string format."""
    return socket.inet_ntop(socket.AF_INET6, self.to_bytes())
