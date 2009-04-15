"""
Testbed for figuring out how to write asynchronous HTTPS code.

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

import sys, os, time, socket, fcntl, asyncore, asynchat, getopt, email, traceback

class http_server(asynchat.async_chat):
  """This started out as the asynchat example from the Python manual."""

  def __init__(self, conn):
    asynchat.async_chat.__init__(self, conn = conn)
    self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    self.ibuffer = []
    self.set_terminator("\r\n\r\n")

  def reading_headers(self):
    return isinstance(self.get_terminator(), str)

  def reading_body(self):
    return isinstance(self.get_terminator(), int)

  def collect_incoming_data(self, data):
    """Buffer the data"""
    self.ibuffer.append(data)

  def get_ibuffer(self):
    val = "".join(self.ibuffer)
    self.ibuffer = []
    return val

  def found_terminator(self):
    if self.reading_headers():
      return self.handle_headers()
    if self.reading_body():
      return self.handle_body()
    raise RuntimeError

  def handle_headers(self):
    headers = self.get_ibuffer().split("\r\n")
    request = headers.pop(0).split()
    if len(request) == 3:
      cmd, path, version = request
      assert version[:5] == "HTTP/"
      version = tuple(int(i) for i in version[5:].split("."))
    elif len(request) == 2:
      cmd, path = request
      version = (0, 9)
    else:
      raise RuntimeError
    cmd = cmd.upper()
    for i in xrange(len(headers) - 2, -1, -1):
      if headers[i + 1][0].isspace():
        headers[i] += headers[i + 1]
        del headers[i + 1]
    headers = [h.split(":", 1) for h in headers]
    headers = dict((k.lower(), v) for (k,v) in headers)
    print
    print "Command: ", cmd
    print "Path:    ", path
    print "Version:", version
    print
    print "Headers:", repr(headers)
    self.push_line("HTTP/1.0 200 Yo!")
    self.push_line("Content-Type: text/plain")
    self.push_line()
    self.push_line("Hi, Mom!")
    self.close_when_done()
    #asyncore.close_all()

  def push_line(self, line = ""):
    self.push(line + "\r\n")

  def handle_error(self):
    print traceback.format_exc()
    asyncore.close_all()

class http_listener(asyncore.dispatcher):

  def __init__(self):
    asyncore.dispatcher.__init__(self)
    self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
    self.bind(("", 8000))
    self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    self.listen(5)

  def handle_accept(self):
    server = http_server(self.accept()[0])

  def handle_error(self):
    print traceback.format_exc()
    asyncore.close_all()

listener = http_listener()

asyncore.loop()
