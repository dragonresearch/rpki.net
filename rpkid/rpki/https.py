"""
HTTPS utilities, both client and server.

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

import time, socket, asyncore, asynchat, urlparse, sys
import rpki.async, rpki.sundial, rpki.x509, rpki.exceptions, rpki.log
import POW

rpki_content_type = "application/x-rpki"


# ================================================================

# Chatter about TLS certificates
debug_tls_certs = False

# Verbose chatter about HTTP streams
debug = False

# Whether we want persistent HTTP streams, when peer also supports them
want_persistent_client = True
want_persistent_server = True

# Default HTTP connection timeout (set very short for initial testing)
default_timeout = rpki.sundial.timedelta(seconds = 90)

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
    for k, v in headers:
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
  tls = None
  retry_read = None
  retry_write = None

  timeout = default_timeout

  def __init__(self, conn = None):
    asynchat.async_chat.__init__(self, conn = conn)
    self.buffer = []
    self.timer = rpki.async.timer(self.handle_timeout)
    self.restart()

  def restart(self):
    assert not self.buffer
    self.chunk_handler = None
    self.set_terminator("\r\n\r\n")
    if self.timeout is not None:
      self.timer.set(self.timeout)
    else:
      self.timer.cancel()

  def update_timeout(self):
    if self.timeout is not None:
      self.timer.set(self.timeout)
    else:
      self.timer.cancel()

  def collect_incoming_data(self, data):
    """
    Buffer the data
    """
    self.buffer.append(data)
    self.update_timeout()

  def get_buffer(self):
    val = "".join(self.buffer)
    self.buffer = []
    return val

  def found_terminator(self):
    self.update_timeout()
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
    if sys.exc_info()[0] is SystemExit:
      self.log("Caught SystemExit, propagating")
      raise
    else:
      self.log("Error in HTTP stream handler")
      rpki.log.traceback()
      self.log("Closing due to error")
      self.close()

  def handle_timeout(self):
    self.log("Timeout, closing")
    self.close()

  def handle_close(self):
    self.log("Close event in HTTP stream handler")
    self.timer.cancel()

  def send(self, data):
    assert self.retry_read is None and self.retry_write is None
    return self.tls.write(data)

  def recv(self, buffer_size):
    assert self.retry_read is None and self.retry_write is None
    return self.tls.read(buffer_size)

  def readable(self):
    return self.retry_read is not None or (self.retry_write is None and asynchat.async_chat.readable(self))

  def writeable(self):
    return self.retry_write is not None or (self.retry_read is None and asynchat.async_chat.writeable(self))

  def handle_read(self):
    assert self.retry_write is None
    if self.retry_read is not None:
      thunk = self.retry_read
      self.retry_read = None
      self.log("Retrying TLS read %r" % thunk)
      thunk()
    else:
      try:
        asynchat.async_chat.handle_read(self)
      except POW.WantReadError:
        self.retry_read = self.handle_read
      except POW.WantWriteError:
        self.retry_write = self.handle_read
      except POW.ZeroReturnError:
        self.log("ZeroReturn in handle_read()")
        self.close()
      except POW.SSLUnexpectedEOFError:
        self.log("SSLUnexpectedEOF in handle_read()")
        self.close(force = True)
        
  def handle_write(self):
    assert self.retry_read is None
    if self.retry_write is not None:
      thunk = self.retry_write
      self.retry_write = None
      thunk()
      self.log("Retrying TLS write %r" % thunk)
    else:
      asynchat.async_chat.handle_write(self)

  def initate_send(self):
    assert self.retry_read is None and self.retry_write is None
    try:
      asynchat.async_chat.initiate_send(self)
    except POW.WantReadError:
      self.retry_read = self.initiate_send
    except POW.WantWriteError:
      self.retry_write = self.initiate_send
    except POW.ZeroReturnError:
      self.log("ZeroReturn in initiate_send()")
      self.close()
    except POW.SSLUnexpectedEOFError:
      self.log("SSLUnexpectedEOF in initiate_send()")
      self.close(force = True)

  def close(self, force = False):
    self.log("Close requested")
    assert self.retry_read is None and self.retry_write is None
    if self.tls is not None:
      try:
        ret = self.tls.shutdown()
        self.log("tls.shutdown() returned %s, force_shutdown %s" % (ret, force))
        if ret or force:
          self.tls = None
          asynchat.async_chat.close(self)
          self.handle_close()
      except POW.WantReadError:
        self.retry_read = self.close
      except POW.WantWriteError:
        self.retry_write = self.close

  def log_cert(self, tag, x):
    if debug_tls_certs:
      self.log("HTTPS %s cert %r issuer %s [%s] subject %s [%s]" % (tag, x, x.getIssuer(), x.hAKI(), x.getSubject(), x.hSKI()))

class http_server(http_stream):

  parse_type = http_request

  def __init__(self, conn, handlers, cert = None, key = None, ta = (), dynamic_ta = None):
    self.log("Starting")
    self.handlers = handlers
    http_stream.__init__(self, conn = conn)
    self.expect_close = not want_persistent_server

    self.log("cert %r key %r ta %r dynamic_ta %r" % (cert, key, ta, dynamic_ta))

    self.tls = POW.Ssl(POW.TLSV1_SERVER_METHOD)
    self.log_cert("server", cert)
    self.tls.useCertificate(cert.get_POW())
    self.tls.useKey(key.get_POW())
    ta = rpki.x509.X509.normalize_chain(dynamic_ta() if dynamic_ta else ta)
    if not ta:
      raise RuntimeError, "No trust anchor(s) specified, this is unlikely to work"
    for x in ta:
      self.log_cert("trusted", x)
      self.tls.addTrust(x.get_POW())
    self.tls.setVerifyMode(POW.SSL_VERIFY_PEER | POW.SSL_VERIFY_FAIL_IF_NO_PEER_CERT)

    self.tls.setFd(self.fileno())
    self.tls_accept()

  def tls_accept(self):
    try:
      self.tls.accept()
    except POW.WantReadError:
      self.retry_read = self.tls_accept
    except POW.WantWriteError:
      self.retry_write = self.tls_accept

  def handle_no_content_length(self):
    self.handle_message()

  def find_handler(self, path):
    """
    Helper method to search self.handlers.
    """
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
      except (rpki.async.ExitNow, SystemExit):
        raise
      except Exception, edata:
        rpki.log.traceback()
        self.send_error(500, "Unhandled exception %s" % edata)
    else:
      self.send_error(code = error[0], reason = error[1])

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

  def __init__(self, handlers, port = 80, host = "", cert = None, key = None, ta = None, dynamic_ta = None):
    self.log("Listener cert %r key %r ta %r dynamic_ta %r" % (cert, key, ta, dynamic_ta))
    asyncore.dispatcher.__init__(self)
    self.handlers = handlers
    self.cert = cert
    self.key = key
    self.ta = ta
    self.dynamic_ta = dynamic_ta
    try:
      self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
      self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
      self.bind((host, port))
      self.listen(5)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except:
      self.handle_error()
    self.log("Listening on %r, handlers %r" % ((host, port), handlers))

  def handle_accept(self):
    self.log("Accepting connection")
    try:
      http_server(conn = self.accept()[0], handlers = self.handlers, cert = self.cert, key = self.key, ta = self.ta, dynamic_ta = self.dynamic_ta)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except:
      self.handle_error()

  def handle_error(self):
    if sys.exc_info()[0] is SystemExit:
      self.log("Caught SystemExit, propagating")
      raise
    else:
      self.log("Error in HTTP listener")
      rpki.log.traceback()

class http_client(http_stream):

  parse_type = http_response

  def __init__(self, queue, hostport, cert = None, key = None, ta = ()):
    self.log("Creating new connection to %s" % repr(hostport))
    self.log("cert %r key %r ta %r" % (cert, key, ta))
    http_stream.__init__(self)
    self.queue = queue
    self.hostport = hostport
    self.state = "opening"
    self.expect_close = not want_persistent_client
    self.cert = cert
    self.key = key
    self.ta = rpki.x509.X509.normalize_chain(ta)

  def start(self):
    try:
      self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
      self.connect(self.hostport)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except:
      self.handle_error()

  def handle_connect(self):
    self.log("Connected")
    self.set_state("idle")

    self.tls = POW.Ssl(POW.TLSV1_CLIENT_METHOD)
    self.log_cert("client", self.cert)
    self.tls.useCertificate(self.cert.get_POW())
    self.tls.useKey(self.key.get_POW())
    if not self.ta:
      raise RuntimeError, "No trust anchor(s) specified, this is unlikely to work"
    for x in self.ta:
      self.log_cert("trusted", x)
      self.tls.addTrust(x.get_POW())
    self.tls.setVerifyMode(POW.SSL_VERIFY_PEER | POW.SSL_VERIFY_FAIL_IF_NO_PEER_CERT)

    self.tls.setFd(self.fileno())
    self.tls_connect()

  def tls_connect(self):
    try:
      self.tls.connect()
    except POW.WantReadError:
      self.retry_read = self.tls_connect
    except POW.WantWriteError:
      self.retry_write = self.tls_connect
    else:
      self.queue.send_request()

  def set_state(self, state):
    self.log("State transition %s => %s" % (self.state, state))
    self.state = state

  def handle_no_content_length(self):
    self.set_terminator(None)

  def send_request(self, msg):
    self.log("Sending request %r" % msg)
    assert self.state == "idle", "%r: state should be idle, is %s" % (self, self.state)
    self.set_state("request-sent")
    msg.headers["Connection"] = "Close" if self.expect_close else "Keep-Alive"
    self.push(msg.format())
    self.restart()

  def handle_message(self):
    self.log("Message received, state %s" % self.state)

    if not self.msg.persistent():
      self.expect_close = True

    if self.state != "request-sent":
      if self.state == "closing":
        assert not self.msg.body
        self.log("Ignoring empty response received while closing")
        return
      raise RuntimeError, "%r received message while in unexpected state %s" % (self, self.state)

    if self.expect_close:
      self.log("Closing")
      self.set_state("closing")
      self.queue.detach(self)
      self.close_when_done()
    else:
      self.log("Idling")
      self.set_state("idle")
      self.update_timeout()

    if self.msg.code == 200:
      self.queue.return_result(self.msg)
    else:
      self.queue.return_result(rpki.exceptions.HTTPRequestFailed(
        "HTTPS request failed with status %s, reason %s, response %s" % (self.msg.code, self.msg.reason, self.msg.body)))

  def handle_close(self):
    http_stream.handle_close(self)
    self.log("State %s" % self.state)
    self.queue.detach(self)
    if self.get_terminator() is None:
      self.handle_body()
    elif self.state == "request-sent":
      self.queue.return_result(rpki.exceptions.HTTPSClientAborted("HTTPS request aborted by close event"))

  def handle_timeout(self):
    if self.state != "idle":
      self.log("Timeout while in state %s" % self.state)
    http_stream.handle_timeout(self)
    self.queue.detach(self)

  def handle_error(self):
    http_stream.handle_error(self)
    self.queue.detach(self)
    etype, edata = sys.exc_info()[:2]
    if etype in (SystemExit, rpki.async.ExitNow):
      raise edata
    else:
      self.queue.return_result(edata)

class http_queue(object):

  log = logger

  def __init__(self, hostport, cert = None, key = None, ta = ()):
    self.log("Creating queue for %s" % repr(hostport))
    self.log("cert %r key %r ta %r" % (cert, key, ta))
    self.hostport = hostport
    self.client = None
    self.queue = []
    self.cert = cert
    self.key = key
    self.ta = ta

  def request(self, *requests):
    self.log("Adding requests %r" % requests)
    self.queue.extend(requests)

  def restart(self):
    if self.client is None:
      client = http_client(self, self.hostport, cert = self.cert, key = self.key, ta = self.ta)
      self.log("Attaching client %r" % client)
      self.client = client
      self.client.start()
    elif self.client.state == "idle":
      self.log("Sending request to existing client %r" % self.client)
      self.send_request()
    else:
      self.log("Client exists and is not idle")

  def send_request(self):
    if self.queue:
      self.client.send_request(self.queue[0])

  def detach(self, client):
    if client is self.client:
      self.log("Detaching client %r" % client)
      self.client = None

  def return_result(self, result):

    if not self.queue:
      self.log("No caller, this should not happen.  Dropping result %r" % result)

    req = self.queue.pop(0)
    self.log("Dequeuing request %r" % req)

    try:
      if isinstance(result, http_response):
        self.log("Returning result %r to caller" % result)
        req.callback(result.body)
      else:
        assert isinstance(result, Exception)
        self.log("Returning exception %r to caller: %s" % (result, result))
        req.errback(result)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except:
      self.log("Unhandled exception from callback")
      rpki.log.traceback()

    self.log("Queue: %r" % self.queue)

    if self.queue:
      self.restart()

client_queues = {}

def client(msg, client_key, client_cert, server_ta, url, callback, errback):
  """
  Open client HTTPS connection, send a message, set up callbacks to
  handle response.
  """

  u = urlparse.urlparse(url)

  if (u.scheme not in ("", "https") or
      u.username is not None or
      u.password is not None or
      u.params   != "" or
      u.query    != "" or
      u.fragment != ""):
    raise rpki.exceptions.BadClientURL, "Unusable URL %s" % url

  rpki.log.debug("Contacting %s" % url)

  request = http_request(
    cmd                 = "POST",
    path                = u.path,
    body                = msg,
    callback            = callback,
    errback             = errback,
    Host                = u.hostname,
    Content_Type        = rpki_content_type)

  hostport = (u.hostname or "localhost", u.port or 80)

  if debug:
    rpki.log.debug("Created request %r for %r" % (request, hostport))
  if not isinstance(server_ta, (tuple, list)):
    server_ta = (server_ta,)
  if hostport not in client_queues:
    client_queues[hostport] = http_queue(hostport, cert = client_cert, key = client_key, ta = server_ta)
  client_queues[hostport].request(request)

  # Defer connection attempt until after we've had time to process any
  # pending I/O events, in case connections have closed.

  if debug:
    rpki.log.debug("Scheduling connection startup for %r" % request)
  rpki.async.timer(client_queues[hostport].restart, errback).set(None)

def server(handlers, server_key, server_cert, port, host ="", client_ta = (), dynamic_https_trust_anchor = None):
  """
  Run an HTTPS server and wait (forever) for connections.
  """

  if not isinstance(handlers, (tuple, list)):
    handlers = (("/", handlers),)

  if not isinstance(client_ta, (tuple, list)):
    server_ta = (client_ta,)

  http_listener(port = port, handlers = handlers, cert = server_cert, key = server_key, ta = client_ta, dynamic_ta = dynamic_https_trust_anchor)
  rpki.async.event_loop()

def build_https_ta_cache(certs):
  """
  Package up a collection of certificates into a form suitable for use
  as a dynamic HTTPS trust anchor set.  Precise format of this
  collection is an internal conspiracy within the rpki.https module;
  at one point it was a POW.X509Store object, at the moment it's a
  Python set, what it will be tomorow is nobody else's business.
  """

  return set(certs)
