"""
Classes to represent IP addresses.

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

import socket
import ctypes

# Scary hack to let us use methods from the Python/C API

PyLong_AsByteArray = ctypes.pythonapi._PyLong_AsByteArray
PyLong_AsByteArray.argtypes = [ctypes.py_object,
                               ctypes.c_char_p,
                               ctypes.c_size_t,
                               ctypes.c_int,
                               ctypes.c_int]

PyLong_FromByteArray = ctypes.pythonapi._PyLong_FromByteArray
PyLong_FromByteArray.restype = ctypes.py_object
PyLong_FromByteArray.argtypes = [ctypes.c_char_p,
                                 ctypes.c_size_t,
                                 ctypes.c_int,
                                 ctypes.c_int]

class addr(long):
  """
  IP address.  This is a virtual class.
  Derived from long, but supports IP print syntax.
  Derived classes must define .bits and .af values
  and may override .normalize_string().
  """

  def __new__(cls, x):
    if isinstance(x, unicode):
      x = x.encode("ascii")
    if isinstance(x, str):
      return cls.from_bytes(socket.inet_pton(cls.af, cls.normalize_string(x)))
    else:
      return long.__new__(cls, x)

  @staticmethod
  def normalize_string(s):
    return s

  def to_bytes(self):
    b = ctypes.create_string_buffer(self.bits / 8)
    PyLong_AsByteArray(self, b, len(b), 0, 1)
    return b.raw

  @classmethod
  def from_bytes(cls, x):
    return cls(PyLong_FromByteArray(x, len(x), 0, 1))

  def __str__(self):
    b = self.to_bytes()
    return socket.inet_ntop(self.af, b)

class v4addr(addr):
  bits = 32
  af = socket.AF_INET
  
  @staticmethod
  def normalize_string(s):
    return ".".join(str(int(i)) for i in s.split("."))

class v6addr(addr):
  bits = 128
  af = socket.AF_INET6

def parse(s):
  """
  Parse a string as either an IPv4 or IPv6 address, and return object of appropriate class.
  """
  if isinstance(s, unicode):
    s = s.encode("ascii")
  return v6addr(s) if ":" in s else v4addr(s)

if __name__ == "__main__":
  def test(x):
    y = parse(x)
    print x, "=>", y

  test("10.0.0.44")
  test("010.000.000.044")
  test("::1")
  test("::")
