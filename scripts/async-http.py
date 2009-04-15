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

# Command that may be useful for testing server side of this:
#
#    lynx -post_data -mime_header -source http://127.0.0.1:8000/


import sys, os, time, socket, fcntl, asyncore, asynchat, getopt, email, traceback

class http_message(object):

  def __init__(self, headers):
    headers = headers.split("\r\n")
    self.parse_first_line(*headers.pop(0).split(None, 2))
    for i in xrange(len(headers) - 2, -1, -1):
      if headers[i + 1][0].isspace():
        headers[i] += headers[i + 1]
        del headers[i + 1]
    headers = [h.split(":", 1) for h in headers]
    self.headers = dict((k.lower(), v) for (k,v) in headers)

  def __str__(self):
    s =  "Version: %d.%d\n" % self.version
    s += "Type:    %s\n" % self.__class__.__name__
    s += "Command: %s\n" % getattr(self, "cmd", "")
    s += "Path:    %s\n" % getattr(self, "path", "")
    s += "Code:    %s\n" % getattr(self, "code", "")
    s += "Msg:     %s\n" % getattr(self, "msg", "")
    for k,v in self.headers.iteritems():
      s += " %s: %s\n" % (k, v)
    return s

class http_request(http_message):

  def parse_first_line(self, cmd, path, version = None):
    self.cmd = cmd.upper()
    self.path = path
    if version is None:
      self.version = (0, 9)
    elif version[:5] == "HTTP/":
      self.version = tuple(int(i) for i in version[5:].split("."))
    else:
      raise RuntimeError

class http_response(http_message):

  def parse_first_line(self, version, code, msg):
    if version[:5] == "HTTP/":
      self.version = tuple(int(i) for i in version[5:].split("."))
    else:
      raise RuntimeError
    self.code = int(code)
    self.msg = msg

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
    msg = http_request(self.get_ibuffer())
    print msg
    self.reply(msg)

  def reply(self, msg):
    self.push("HTTP/1.0 200 Yo!\r\nContent-Type: text/plain\r\n\r\n")
    self.push(str(msg).replace("\n", "\r\n"))
    self.close_when_done()

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
    self.listen(5)

  def handle_accept(self):
    server = http_server(self.accept()[0])

  def handle_error(self):
    print traceback.format_exc()
    asyncore.close_all()

listener = http_listener()

asyncore.loop()
