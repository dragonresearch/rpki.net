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
#
# Testing the client side of this is more entertaining, both because
# we need to be liberal in what we accept and also because servers do
# wildly different things depending both on HTTP version number and
# options signaled by the client and also on internal details in the
# server context (such as whether the content is static or generated
# by CGI).  It's useful to test against static content, but also to
# test against CGI-generated output, eg, the following trivial script:
#
#    print "Content-Type: text/plain; charset=US-ASCII\r"
#    print "\r"
#    for i in xrange(100):
#      print "%08d" % i, "." * 120, "\r"
#
# At least with Apache 2.0, result of running this differs
# significantly depending on whether client signals HTTP 1.0 or 1.1;
# the latter produces chunked output.

import sys, os, time, socket, asyncore, asynchat, traceback, urlparse
import rpki.async

debug = True

want_persistent_client = False
want_persistent_server = False

class http_message(object):

  software_name = "BalmyBandicoot HTTP test code"

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
      return False

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
    if debug: print "[%s: Error in HTTP stream handler]" % repr(self)
    print traceback.format_exc()
    asyncore.close_all()

class http_server(http_stream):

  def __init__(self, conn = None):
    http_stream.__init__(self, conn)
    self.expect_close = not want_persistent_server

  def handle_headers(self):
    if debug: print "[%s: Got headers]" % repr(self)
    self.msg = http_request.parse_from_wire(self.get_buffer())
    if self.msg.cmd == "POST":
      if debug: print "[%s: Waiting for POST body]" % repr(self)
      self.set_terminator(int(self.msg.headers["Content-Length"]))
    else:
      self.handle_message()

  def handle_message(self):
    if not self.msg.persistent():
      self.expect_close = True
    print "Query:"
    print self.msg
    print
    msg = http_response(code = 200, reason = "OK", body = self.msg.format(),
                        Connection = "Close" if self.expect_close else "Keep-Alive",
                        Cache_Control = "no-cache,no-store",
                        Content_Type = "text/plain")
    print "Reply:"
    print msg
    print
    self.push(msg.format())
    if self.expect_close:
      if debug: print "[%s: Closing]" % repr(self)
      self.close_when_done()
    else:      
      if debug: print "[%s: Listening for next message]" % repr(self)
      self.restart()

class http_listener(asyncore.dispatcher):

  def __init__(self, port):
    asyncore.dispatcher.__init__(self)
    self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
    self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    self.bind(("", port))
    self.listen(5)
    if debug: print "[%s: Listening on port %s]" % (repr(self), port)

  def handle_accept(self):
    if debug: print "[%s: Accepting connection]" % repr(self)
    server = http_server(self.accept()[0])

  def handle_error(self):
    if debug: print "[%s: Error in HTTP listener]" % repr(self)
    print traceback.format_exc()
    asyncore.close_all()

# Might need to know whether outbound data is fully sent, as part of
# this state thing.  If so, calling .writable() ought to do the trick,
# so long as it has no side effects (need to check asynchat.py for
# that).
#
# I don't think there's anything we can do about crossed-in-mail
# problem where we finish sending query just as server sends us
# an unsolicited message.  One would like to think that the HTTP
# specification rules this out, but no bets.

class http_client(http_stream):

  def __init__(self, narrator, hostport):
    if debug: print "[%s: Creating new connection]" % repr(self)
    http_stream.__init__(self)
    self.narrator = narrator
    self.hostport = hostport
    self.state = "idle"
    self.expect_close = not want_persistent_client
    self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
    self.connect(hostport)

  def handle_headers(self):
    self.msg = http_response.parse_from_wire(self.get_buffer())
    if "Content-Length" in self.msg.headers:
      self.set_terminator(int(self.msg.headers["Content-Length"]))
    else:
      self.set_terminator(None)

  def send_request(self, msg):
    print "[%s: Sending request]" % repr(self)
    assert self.state == "idle"
    assert msg is not None
    self.state = "request-sent"
    msg.headers["Connection"] = "Close" if self.expect_close else "Keep-Alive"
    self.push(msg.format())
    self.restart()

  def handle_message(self):
    if not self.msg.persistent():
      self.expect_close = True
    print "[%s: Message received, state %s]" % (repr(self), self.state)
    if self.state == "request-sent":
      print "Query:"
      print self.narrator.done_with_request(self.hostport)
      print
    elif self.state == "idle":
      print "[%s: Received unsolicited message]" % repr(self)
    elif self.state == "closing":
      assert not self.msg.body
      print "[%s: Ignoring empty response received while closing]" % repr(self)
      return
    else:
      print "[%s: Unexpected state]" % repr(self)
    print "Reply:"
    print self.msg
    print
    msg = self.narrator.next_request(self.hostport, not self.expect_close)
    if msg is not None:
      if debug: print "[%s: Got a new message to send from my queue]" % repr(self)
      self.send_request(msg)
    else:
      if debug: print "[%s: Closing]" % repr(self)
      self.state = "closing"
      self.close_when_done()

  def handle_connect(self):
    if debug: print "[%s: Connected]" % repr(self)
    msg = self.narrator.next_request(self.hostport, True)
    self.send_request(msg)

  def handle_close(self):
    if self.get_terminator() is None:
      self.found_terminator()

class http_narrator(object):

  def __init__(self):
    self.clients = {}
    self.queues  = {}

  def query(self, url, body = None):
    u = urlparse.urlparse(url)
    assert u.scheme == "http" and u.username is None and u.password is None and u.params == "" and u.query == "" and u.fragment == ""
    request = http_request(cmd = "POST", path = u.path, body = body,
                           Host = u.hostname,
                           Content_Type = "text/plain")
    hostport = (u.hostname or "localhost", u.port or 80)
    assert (hostport in self.queues) == (hostport in self.clients)
    if hostport not in self.queues:
      self.queues[hostport] = []
    self.queues[hostport].append(request)
    if hostport not in self.clients:
      self.clients[hostport] = http_client(self, hostport)
      
  # Messages have to stay in queue here in case client fails and we
  # need to retry with another client.  What a mess.

  def done_with_request(self, hostport):
    req = self.queues[hostport].pop(0)
    print "[%s: Dequeuing request %s]" % (repr(self), repr(req))
    return req

  def next_request(self, hostport, usable):
    queue = self.queues.get(hostport)
    if not queue:
      print "[%s: Queue is empty]" % repr(self)
      return None
    print "[%s: Queue: %s]" % (repr(self), repr(queue))
    if usable:
      print "[%s: Queue not empty and connection usable]" % repr(self)
      return queue[0]
    else:
      print "[%s: Queue not empty but connection not usable, spawning]" % repr(self)
      self.clients[hostport] = http_client(self, hostport)
      print "[%s: Spawned connection %s]" % (repr(self), repr(self.clients[hostport]))
      return None

if len(sys.argv) == 1:

  listener = http_listener(port = 8000)

else:

  narrator = http_narrator()
  for url in sys.argv[1:]:
    narrator.query(url = url, body = "Hi, I'm trying to talk to URL %s" % url)

rpki.async.event_loop()
