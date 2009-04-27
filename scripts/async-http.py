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


import sys, os, time, socket, asyncore, asynchat, traceback, urlparse

class http_message(object):

  software_name = "WombatWare test HTTP code"

  def __init__(self, version = None, body = None, headers = None):
    self.version = version
    self.body = body
    self.headers = headers
    self.normalize_headers()

  def normalize_headers(self, headers = None):
    if headers is None:
      headers = () if self.headers is None else self.headers.items()
      translate_underscore = True
    else:
      translate_underscore = False
    result = {}
    for k,v in headers:
      if translate_underscore:
        k = k.replace("_", "-")
      k = "-".join(s.capitalize() for s in k.split("-"))
      v = v.strip()
      if k in result:
        result[k] += ", " + v
      else:
        result[k] = v
    self.headers = result

  @classmethod
  def parse_from_wire(cls, headers):
    self = cls()
    headers = headers.split("\r\n")
    self.parse_first_line(*headers.pop(0).split(None, 2))
    for i in xrange(len(headers) - 2, -1, -1):
      if headers[i + 1][0].isspace():
        headers[i] += headers[i + 1]
        del headers[i + 1]
    self.normalize_headers([h.split(":", 1) for h in headers])
    return self

  def format(self):
    s = self.format_first_line()
    if self.body is not None:
      assert isinstance(self.body, str)
      self.headers["Content-Length"] = len(self.body)
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

  def persistent(self):
    c = self.headers.get("Connection")
    if self.version == (1,1):
      return c is None or "close" not in c.lower()
    elif self.version == (1,0):
      return c is not None and "keep-alive" in c.lower()
    else:
      raise RuntimeError, "Version is neither 1.0 nor 1.1"

class http_request(http_message):

  def __init__(self, cmd = None, path = None, version = (1,0), body = None, **headers):
    if cmd is not None and cmd != "POST" and body is not None:
      raise RuntimeError
    http_message.__init__(self, version = version, body = body, headers = headers)
    self.cmd = cmd
    self.path = path

  def parse_first_line(self, cmd, path, version):
    self.parse_version(version)
    self.cmd = cmd
    self.path = path

  def format_first_line(self):
    self.headers.setdefault("User-Agent", self.software_name)
    return "%s %s HTTP/%d.%d\r\n" % (self.cmd, self.path, self.version[0], self.version[1])

class http_response(http_message):

  def __init__(self, code = None, reason = None, version = (1,0), body = None, **headers):
    http_message.__init__(self, version = version, body = body, headers = headers)
    self.code = code
    self.reason = reason

  def parse_first_line(self, version, code, reason):
    self.parse_version(version)
    self.code = int(code)
    self.reason = reason

  def format_first_line(self):
    self.headers.setdefault("Date", time.strftime("%a, %d %b %Y %T GMT"))
    self.headers.setdefault("Server", self.software_name)
    return "HTTP/%d.%d %s %s\r\n" % (self.version[0], self.version[1], self.code, self.reason)

class http_stream(asynchat.async_chat):

  def __init__(self, conn = None):
    asynchat.async_chat.__init__(self, conn = conn)
    self.buffer = []
    self.restart()

  def restart(self):
    assert not self.buffer
    self.set_terminator("\r\n\r\n")

  def collect_incoming_data(self, data):
    """Buffer the data"""
    self.buffer.append(data)

  def get_buffer(self):
    val = "".join(self.buffer)
    self.buffer = []
    return val

  def found_terminator(self):
    if isinstance(self.get_terminator(), str):
      return self.handle_headers()
    else:
      return self.handle_body()

  def handle_body(self):
    self.msg.body = self.get_buffer()
    #assert len(self.msg.body) == int(self.msg.headers["Content-Length"])
    self.handle_message()

  def handle_error(self):
    print "[Error]"
    print traceback.format_exc()
    asyncore.close_all()

class http_server(http_stream):

  def handle_headers(self):
    print "[Got headers]"
    self.msg = http_request.parse_from_wire(self.get_buffer())
    if self.msg.cmd == "POST":
      print "[Waiting for POST body]"
      self.set_terminator(int(self.msg.headers["Content-Length"]))
    else:
      self.handle_message()

  def handle_message(self):
    print "[Got message]"
    print "[Connection %s persistent]" % ("is" if self.msg.persistent() else "isn't")
    print self.msg
    self.push(http_response(code = 200, reason = "OK", body = self.msg.format(),
                            Connection = "Keep-Alive" if self.msg.persistent() else "Close",
                            Content_Type = "text/plain").format())
    if self.msg.persistent():
      print "[Listening for next message]"
      self.restart()
    else:
      print "[Closing]"
      self.close_when_done()

  def handle_close(self):
    print "[Closing all connections]"
    asyncore.close_all()

class http_listener(asyncore.dispatcher):

  def __init__(self, port):
    asyncore.dispatcher.__init__(self)
    self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
    self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    self.bind(("", port))
    self.listen(5)
    print "[Listening on port %s]" % port

  def handle_accept(self):
    print "[Accepting connection]"
    server = http_server(self.accept()[0])

  def handle_error(self):
    print "[Error]"
    print traceback.format_exc()
    asyncore.close_all()

class http_client(http_stream):

  def __init__(self, orator, hostport, msg = None):
    http_stream.__init__(self)
    self.orator = orator
    self.message_queue = []
    if msg is not None:
      self.queue_message(msg)
    self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
    self.connect(hostport)

  def handle_headers(self):
    self.msg = http_response.parse_from_wire(self.get_buffer())
    if "Content-Length" in self.msg.headers:
      self.set_terminator(int(self.msg.headers["Content-Length"]))
    else:
      self.set_terminator(None)

  def handle_message(self):
    print "[Got message]"
    print "[Connection %s persistent]" % ("is" if self.msg.persistent() else "isn't")
    print self.msg
    self.next_msg()

  def handle_connect(self):
    print "[Connected]"
    self.next_msg()

  def queue_message(self, msg):
    print "[Adding message to queue]"
    self.message_queue.append(msg)

  def next_msg(self):
    if self.message_queue:
      try:
        if not self.msg.persistent():
          raise RuntimeError, "Attempting to send subsequent message to non-persistent connection"
      except AttributeError:
        pass
      print "[Pulling next message from queue]"
      self.push(self.message_queue.pop(0).format())
      self.restart()
    else:
      print "[No messages left in queue]"
      self.close_when_done()

  def handle_close(self):
    if self.get_terminator() is None:
      self.found_terminator()

class http_orator(dict):

  def query(self, url, body = None):

    u = urlparse.urlparse(url)

    assert u.scheme == "http"
    assert u.username is None
    assert u.password is None
    assert u.params   == ""
    assert u.query    == ""
    assert u.fragment == ""

    request = http_request(cmd = "POST", path = u.path, body = body, Content_Type = "text/plain", Connection = "Keep-Alive")
    hostport = (u.hostname or "localhost", u.port or 80)

    if hostport not in self:
      print "[Creating new connection]"
      self[hostport] = http_client(self, hostport, request)
    else:
      print "[Reusing existing connection]"
      self[hostport].queue_message(request)

if len(sys.argv) == 1:

  listener = http_listener(port = 8000)

else:

  # This doesn't comply with HTTP, as we're not signalling reusable
  # connections properly.  For the moment this is just a test to see
  # whether the parser can survive multiple messages.

  orator = http_orator()
  for url in sys.argv[1:]:
    orator.query(url = url, body = "Hi, I'm trying to talk to URL %s" % url)

asyncore.loop()
