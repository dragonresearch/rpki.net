# $Id$

import socket, struct

class v4addr(long):
  bits = 32

  def __new__(cls, x):
    if isinstance(x, str):
      y = struct.unpack("!I", socket.inet_pton(socket.AF_INET, x))
      x = y[0]
    return long.__new__(cls, x)

  def __str__(self):
    return socket.inet_ntop(socket.AF_INET, struct.pack("!I", long(self)))

class v6addr(long):
  bits = 128

  def __new__(cls, x):
    if isinstance(x, str):
      y = struct.unpack("!QQ", socket.inet_pton(socket.AF_INET6, x))
      x = (y[0] << 64) | y[1]
    return long.__new__(cls, x)

  def __str__(self):
    return socket.inet_ntop(socket.AF_INET6, struct.pack("!QQ", long(self) >> 64, long(self) & 0xFFFFFFFFFFFFFFFF))
