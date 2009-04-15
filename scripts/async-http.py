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

  @classmethod
  def parse_from_wire(cls, headers):
    self = cls()
    headers = headers.split("\r\n")
    self.parse_first_line(*headers.pop(0).split(None, 2))
    for i in xrange(len(headers) - 2, -1, -1):
      if headers[i + 1][0].isspace():
        headers[i] += headers[i + 1]
        del headers[i + 1]
    headers = [h.split(":", 1) for h in headers]
    self.headers = dict((k.lower(), v) for (k,v) in headers)
    return self

  def format(self):
    s = self.format_first_line()
    if self.body is not None:
      assert isinstance(self.body, str)
      self.headers["content-length"] = len(self.body)
    for kv in self.headers.iteritems():
      s += "%s: %s\r\n" % kv
    s += "\r\n"
    if self.body is not None:
      s += self.body
    return s

  def __str__(self):
    return self.format()

  def parse_version(self, version):
    if version[:5] != "HTTP/":
      raise RuntimeError, "Couldn't parse version %s" % version
    self.version = tuple(int(i) for i in version[5:].split("."))

class http_request(http_message):

  def __init__(self, cmd = None, path = None, version = (1,0), body = None, headers = None):
    if cmd is not None and cmd.upper() != "POST" and body is not None:
      raise RuntimeError
    self.cmd = cmd
    self.path = path
    self.version = version
    self.body = body
    self.headers = {} if headers is None else headers

  def parse_first_line(self, cmd, path, version):
    self.parse_version(version)
    self.cmd = cmd.upper()
    self.path = path

  def format_first_line(self):
    return "%s %s HTTP/%d.%d\r\n" % (self.cmd, self.path, self.version[0], self.version[1])

class http_response(http_message):

  def __init__(self, code = None, msg = None, version = (1,0), body = None, headers = None):
    self.code = code
    self.msg = msg
    self.version = version
    self.body = body
    self.headers = {} if headers is None else headers

  def parse_first_line(self, version, code, msg):
    self.parse_version(version)
    self.code = int(code)
    self.msg = msg

  def format_first_line(self):
    return "HTTP/%d.%d %s %s\r\n" % (self.version[0], self.version[1], self.code, self.msg)

class http_stream(asynchat.async_chat):

  def __init__(self, conn = None):
    asynchat.async_chat.__init__(self, conn = conn)
    self.buffer = []
    self.restart()

  def restart(self):
    assert not self.buffer
    self.set_terminator("\r\n\r\n")

  def reading_headers(self):
    return isinstance(self.get_terminator(), str)

  def reading_body(self):
    return isinstance(self.get_terminator(), int)

  def collect_incoming_data(self, data):
    """Buffer the data"""
    self.buffer.append(data)

  def get_buffer(self):
    val = "".join(self.buffer)
    self.buffer = []
    return val

  def found_terminator(self):
    if self.reading_headers():
      return self.handle_headers()
    if self.reading_body():
      return self.handle_body()
    raise RuntimeError

  def handle_body(self):
    self.msg.body = self.get_buffer()
    assert len(self.msg.body) == int(self.msg.headers["content-length"])
    self.handle_message()

  def handle_error(self):
    print traceback.format_exc()
    asyncore.close_all()

class http_server(http_stream):

  def handle_headers(self):
    self.msg = http_request.parse_from_wire(self.get_buffer())
    if self.msg.cmd == "POST":
      self.set_terminator(int(self.msg.headers["content-length"]))
    else:
      self.handle_message()

  def handle_message(self):
    print self.msg
    self.push(http_response(code = 200, msg = "OK", body = self.msg.format(), headers = { "content-type" : "text/plain" }).format())
    if False:
      self.close_when_done()
    else:
      self.restart()

  def handle_close(self):
    asyncore.close_all()

class http_client(http_stream):

  def handle_headers(self):
    self.msg = http_response.parse_from_wire(self.get_buffer())
    self.set_terminator(int(self.msg.headers["content-length"]))

  def handle_message(self):
    print self.msg
    self.next_msg()

  def handle_connect(self):
    self.next_msg()

  @classmethod
  def queue_messages(cls, msgs):
    self = cls()
    self.msgs = msgs
    self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
    self.connect(("", 8000))
    
  def next_msg(self):
    if self.msgs:
      self.push(self.msgs.pop(0).format())
      self.restart()
    else:
      self.close_when_done()

class http_listener(asyncore.dispatcher):

  def __init__(self):
    asyncore.dispatcher.__init__(self)
    self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
    self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    self.bind(("", 8000))
    self.listen(5)

  def handle_accept(self):
    server = http_server(self.accept()[0])

  def handle_error(self):
    print traceback.format_exc()
    asyncore.close_all()

assert len(sys.argv) in (1, 2)

if len(sys.argv) == 1:

  listener = http_listener()

else:

  # This doesn't comply with HTTP, we're not signalling reusable
  # connections properly.  For the moment this is just a test to see
  # whether the parser can survive multiple mssages.

  client = http_client.queue_messages([
    http_request(cmd = sys.argv[1], path = "/", body = "Hi, Mom!\r\n", headers = { "content-type" : "text/plain" }),
    http_request(cmd = sys.argv[1], path = "/", body = "Hi, Dad!\r\n", headers = { "content-type" : "text/plain" }),
    http_request(cmd = sys.argv[1], path = "/", body = "Hi, Bro!\r\n", headers = { "content-type" : "text/plain" }),
    http_request(cmd = sys.argv[1], path = "/", body = "Hi, Sis!\r\n", headers = { "content-type" : "text/plain" }),
    ])

asyncore.loop()
