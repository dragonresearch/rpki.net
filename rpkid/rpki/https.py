"""HTTPS utilities, both client and server.

At the moment this only knows how to use the PEM certs in my
subversion repository; generalizing it would not be hard, but the more
general version should use SQL anyway.

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

import sys, os, time, socket, asyncore, asynchat, traceback, urlparse
import rpki.async, rpki.sundial, rpki.x509, rpki.exceptions, rpki.log

print "====== WARNING WARNING WARNING ======"
print "THIS VERSION OF rpki.https DOES NOT SUPPORT TLS."
print "CONNECTIONS ARE NOT SECURE."
print "THIS IS A DEVELOPMENT VERSION, TLS WILL BE ADDED LATER."
print "====== WARNING WARNING WARNING ======"

rpki_content_type = "application/x-rpki"


# ================================================================

debug = True

want_persistent_client = True
want_persistent_server = True

idle_timeout_default   = rpki.sundial.timedelta(seconds = 60)
active_timeout_default = rpki.sundial.timedelta(seconds = 15)

default_http_version = (1, 0)

class http_message(object):

  software_name = "ISC RPKI library"

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
    if self.version == (1, 1):
      return c is None or "close" not in c.lower()
    elif self.version == (1, 0):
      return c is not None and "keep-alive" in c.lower()
    else:
      return False

class http_request(http_message):

  def __init__(self, cmd = None, path = None, version = default_http_version, body = None, callback = None, errback = None, **headers):
    if cmd is not None and cmd != "POST" and body is not None:
      raise RuntimeError
    http_message.__init__(self, version = version, body = body, headers = headers)
    self.cmd = cmd
    self.path = path
    self.callback = callback
    self.errback = errback
    self.retried = False

  def retry(self):
    if self.retried:
      raise rpki.exceptions.HTTPSRetryFailure
    else:
       self.retried = True

  def parse_first_line(self, cmd, path, version):
    self.parse_version(version)
    self.cmd = cmd
    self.path = path

  def format_first_line(self):
    self.headers.setdefault("User-Agent", self.software_name)
    return "%s %s HTTP/%d.%d\r\n" % (self.cmd, self.path, self.version[0], self.version[1])

class http_response(http_message):

  def __init__(self, code = None, reason = None, version = default_http_version, body = None, **headers):
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

def logger(self, msg):
  if debug:
    rpki.log.debug("%r: %s" % (self, msg))

class http_stream(asynchat.async_chat):

  log = logger

  idle_timeout = idle_timeout_default
  active_timeout = active_timeout_default

  def __init__(self, conn = None):
    asynchat.async_chat.__init__(self, conn = conn)
    self.buffer = []
    self.timer = rpki.async.timer(self.handle_timeout)
    self.restart()

  def restart(self, idle = True):
    assert not self.buffer
    self.chunk_handler = None
    self.set_terminator("\r\n\r\n")
    timeout = self.idle_timeout if idle else self.active_timeout
    if timeout is not None:
      self.timer.set(timeout)
    else:
      self.timer.cancel()

  def update_active_timeout(self):
    if self.active_timeout is not None:
      self.timer.set(self.active_timeout)
    else:
      self.timer.cancel()

  def collect_incoming_data(self, data):
    """Buffer the data"""
    self.buffer.append(data)
    self.update_active_timeout()

  def get_buffer(self):
    val = "".join(self.buffer)
    self.buffer = []
    return val

  def found_terminator(self):
    self.update_active_timeout()
    if self.chunk_handler:
      self.chunk_handler()
    elif not isinstance(self.get_terminator(), str):
      self.handle_body()
    else:
      self.msg = self.parse_type.parse_from_wire(self.get_buffer())
      if self.msg.version == (1, 1) and "chunked" in self.msg.headers.get("Transfer-Encoding", "").lower():
        self.msg.body = []
        self.chunk_handler = self.chunk_header
        self.set_terminator("\r\n")
      elif "Content-Length" in self.msg.headers:
        self.set_terminator(int(self.msg.headers["Content-Length"]))
      else:
        self.handle_no_content_length()
      
  def chunk_header(self):
    n = int(self.get_buffer().partition(";")[0], 16)
    self.log("Chunk length %s" % n)
    if n:
      self.chunk_handler = self.chunk_body
      self.set_terminator(n)
    else:
      self.msg.body = "".join(self.msg.body)
      self.chunk_handler = self.chunk_discard_trailer

  def chunk_body(self):
    self.log("Chunk body")
    self.msg.body += self.buffer
    self.buffer = []
    self.chunk_handler = self.chunk_discard_crlf
    self.set_terminator("\r\n")

  def chunk_discard_crlf(self):
    self.log("Chunk CRLF")
    s = self.get_buffer()
    assert s == "", "Expected chunk CRLF, got '%s'" % s
    self.chunk_handler = self.chunk_header

  def chunk_discard_trailer(self):
    self.log("Chunk trailer")
    s = self.get_buffer()
    assert s == "", "Expected end of chunk trailers, got '%s'" % s
    self.chunk_handler = None
    self.handle_message()

  def handle_body(self):
    self.msg.body = self.get_buffer()
    self.handle_message()

  def handle_error(self):
    self.log("Error in HTTP stream handler")
    print traceback.format_exc()
    #asyncore.close_all()

  def handle_timeout(self):
    self.log("Timeout, closing")
    self.close()

  def handle_close(self):
    self.log("Close event in HTTP stream handler")
    asynchat.async_chat.handle_close(self)
    self.timer.cancel()

class http_server(http_stream):

  parse_type = http_request

  def __init__(self, conn, handlers):
    self.log("Starting")
    self.handlers = handlers
    http_stream.__init__(self, conn)
    self.expect_close = not want_persistent_server

  def handle_no_content_length(self):
    self.handle_message()

  def find_handler(self, path):
    """Helper method to search self.handlers."""
    for s, h in self.handlers:
      if path.startswith(s):
        return h
    return None

  def handle_message(self):
    self.log("Received request %s %s" % (self.msg.cmd, self.msg.path))
    if not self.msg.persistent():
      self.expect_close = True
    handler = self.find_handler(self.msg.path)
    error = None
    if self.msg.cmd != "POST":
      error = 501, "No handler for method %s" % self.msg.cmd
    elif self.msg.headers["Content-Type"] != rpki_content_type:
      error = 415, "No handler for Content-Type %s" % self.headers["Content-Type"]
    elif handler is None:
      error = 404, "No handler for URL %s" % self.msg.path
    if error is None:
      try:
        handler(self.msg.body, self.msg.path, self.send_reply)
      except asyncore.ExitNow:
        raise
      except Exception, edata:
        self.send_error(500, "Unhandled exception %s" % edata)
    else:
      self.send_error(*error)

  def send_error(self, code, reason):
    self.send_message(code = code, reason = reason)

  def send_reply(self, code, body):
    self.send_message(code = code, body = body)

  def send_message(self, code, reason = "OK", body = None):
    self.log("Sending response %s %s" % (code, reason))
    msg = http_response(code = code, reason = reason, body = body,
                        Content_Type = rpki_content_type,
                        Connection = "Close" if self.expect_close else "Keep-Alive")
    self.push(msg.format())
    if self.expect_close:
      self.log("Closing")
      self.timer.cancel()
      self.close_when_done()
    else:      
      self.log("Listening for next message")
      self.restart()

class http_listener(asyncore.dispatcher):

  log = logger

  def __init__(self, handlers, port = 80, host = ""):
    asyncore.dispatcher.__init__(self)
    self.handlers = handlers
    self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
    self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    self.bind((host, port))
    self.listen(5)
    self.log("Listening on (host, port) %r, handlers %r" % ((host, port), handlers))

  def handle_accept(self):
    self.log("Accepting connection")
    server = http_server(conn = self.accept()[0], handlers = self.handlers)

  def handle_error(self):
    self.log("Error in HTTP listener")
    print traceback.format_exc()
    #asyncore.close_all()

class http_client(http_stream):

  parse_type = http_response

  def __init__(self, queue, hostport):
    self.log("Creating new connection to %s" % repr(hostport))
    http_stream.__init__(self)
    self.queue = queue
    self.state = "idle"
    self.expect_close = not want_persistent_client
    self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
    self.connect(hostport)

  def handle_no_content_length(self):
    self.set_terminator(None)

  def send_request(self, msg):
    self.log("Sending request")
    assert self.state == "idle", "%r: state should be idle, is %s" % (self, self.state)
    if msg is not None:
      self.state = "request-sent"
      msg.headers["Connection"] = "Close" if self.expect_close else "Keep-Alive"
      self.push(msg.format())
      self.restart(idle = False)

  def handle_message(self):
    if not self.msg.persistent():
      self.expect_close = True
    self.log("Message received, state %s" % self.state)
    msg = None
    if self.state == "request-sent":
      msg = self.queue.done_with_request()
    elif self.state == "idle":
      self.log("Received unsolicited message")
    elif self.state == "closing":
      assert not self.msg.body
      self.log("Ignoring empty response received while closing")
      return
    else:
      raise RuntimeError, "[%r: Unexpected state]" % self
    self.state = "idle"
    if msg != None:
      try:
        if self.msg.code != 200:
          e = rpki.exceptions.HTTPRequestFailed("HTTP request failed with status %s, reason %s, response %s" % (self.msg.code, self.msg.reason, self.msg.body))
          rpki.log.debug("HTTPS client returned failure: %s" % e)
          msg.errback(e)
        else:
          self.log("Delivering HTTPS client result")
          msg.callback(self.msg.body)
      except asyncore.ExitNow:
        raise
      except Exception, data:
        self.log("Unhandled exception from callback")
        rpki.log.error(traceback.format_exc())
    msg = self.queue.next_request(not self.expect_close)
    if msg is not None and self.state is "idle":
      self.log("Got a new message to send from my queue")
      self.send_request(msg)
    elif msg is not None:
      self.log("Connection state %s, nothing left for me to do at the moment" % self.state)
    elif self.expect_close:
      self.log("Closing")
      self.state = "closing"
      self.queue.closing(self)
      self.close_when_done()
    else:
      self.log("Idling")
      self.timer.set(self.idle_timeout)

  def handle_connect(self):
    self.log("Connected")
    self.send_request(self.queue.next_request(True))

  def kickstart(self):
    self.log("Kickstart")
    assert self.state == "idle"
    self.send_request(self.queue.next_request(True))

  def handle_close(self):
    http_stream.handle_close(self)
    self.queue.closing(self)
    if self.get_terminator() is None:
      self.handle_body()

  def handle_timeout(self):
    if self.state != "idle":
      self.log("Timeout while in state %s" % self.state)
    http_stream.handle_timeout(self)
    self.queue.closing(self)

class http_queue(object):

  log = logger

  def __init__(self, hostport):
    self.log("Creating queue for %s" % repr(hostport))
    self.hostport = hostport
    self.client = None
    self.queue = []

  def request(self, *requests):
    self.log("Adding requests %r" % requests)
    need_kick = self.client is not None and not self.queue
    self.queue.extend(requests)
    if self.client is None:
      self.client = http_client(self, self.hostport)
      self.log("Spawned connection %r" % self.client)
    elif need_kick:
      self.client.kickstart()

  def done_with_request(self):
    req = self.queue.pop(0)
    self.log("Dequeuing request %r" % req)
    return req

  def next_request(self, usable):
    if not self.queue:
      self.log("Queue is empty")
      return None
    self.log("Queue: %r" % self.queue)
    if usable:
      self.log("Queue not empty and connection usable")
      return self.queue[0]
    else:
      self.log("Queue not empty but connection not usable, spawning")
      self.client = http_client(self, self.hostport)
      self.log("Spawned connection %r" % self.client)
      return None

  def closing(self, client):
    if client is self.client:
      self.log("Removing client")
      if not self.queue:
        self.log("Queue is empty")
        self.client = None
      else:
        try:
          self.queue[0].retry()
        except asyncore.ExitNow:
          raise
        except:
          self.log("Queue is not empty, but request has already been transmitted, giving up")
          self.client = None
          raise
        else:
          self.log("Queue is not empty, starting new client")
          self.client = http_client(self, self.hostport)

queues = {}

def default_client_errback(e):
  """Default errback for clients."""
  raise e

def client(msg, client_key, client_cert, server_ta, url, timeout = 300, callback = None, errback = default_client_errback):
  """Open client HTTPS connection, send a message, wait for response.

  THIS VERSION DOES NOT DO TLS.  THIS IS EXPERIMENTAL CODE.  DO NOT
  USE IN PRODUCTION UNTIL TLS SUPPORT HAS BEEN ADDED.
  """

  # This is an easy way to find synchronous calls that need conversion
  if callback is None:
    raise RuntimeError, "Synchronous call to rpki.http.client()"

  u = urlparse.urlparse(url)

  if (u.scheme not in ("", "https") or
      u.username is not None or
      u.password is not None or
      u.params   != "" or
      u.query    != "" or
      u.fragment != ""):
    raise rpki.exceptions.BadClientURL, "Unusable URL %s" % url

  rpki.log.debug("Contacting %s" % url)

  request = http_request(cmd = "POST", path = u.path, body = msg, callback = callback,
                         Host = u.hostname, Content_Type = rpki_content_type)
  hostport = (u.hostname or "localhost", u.port or 80)
  rpki.log.debug("Created request %r for %r" % (request, hostport))
  if hostport not in queues:
    queues[hostport] = http_queue(hostport)
  queues[hostport].request(request)

def server(handlers, server_key, server_cert, port = 4433, host ="", client_ta = None, dynamic_https_trust_anchor = None):
  """Run an HTTPS server and wait (forever) for connections."""

  if not isinstance(handlers, (tuple, list)):
    handlers = (("/", handlers),)

  listener = http_listener(port = port, handlers = handlers)
  rpki.async.event_loop()

