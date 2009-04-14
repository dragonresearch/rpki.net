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
    self.ibuffer = []
    self.set_terminator("\r\n\r\n")

  def reading_headers(self):
    return isinstance(self.get_terminator(), str)

  def reading_body(self):
    return isinstance(self.get_terminator(), int)

  def collect_incoming_data(self, data):
    """Buffer the data"""
    print "Got:", data
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

  def handle_accept(self):
    print "handle_accept()"
    self.accept()

  def handle_headers(self):
    request, headers = self.get_ibuffer().split("\r\n", 1)
    request = request.split()
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
    print headers
    headers = email.Parser().parsestr(headers, True)
    print
    print "Command: ", cmd
    print "Path:    ", path
    print "Version:", version
    print
    print "Headers:", repr(headers)

  def handle_error(self):
    print traceback.format_exc()
    asyncore.close_all()


class http_listener(asyncore.dispatcher):

  def __init__(self):
    asyncore.dispatcher.__init__(self)
    self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
    self.bind(("", 8000))
    self.listen(5)

  def handle_accept(self):
    print "handle_accept()"
    newsock = self.accept()
    server = http_server(newsock[0])

  def handle_error(self):
    print traceback.format_exc()
    asyncore.close_all()

listener = http_listener()

asyncore.loop()
