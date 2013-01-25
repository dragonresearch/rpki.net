"""
HTTP utilities, both client and server.

$Id$

Copyright (C) 2009-2012  Internet Systems Consortium ("ISC")

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

import time, socket, asyncore, asynchat, urlparse, sys, random
import rpki.async, rpki.sundial, rpki.x509, rpki.exceptions, rpki.log
import rpki.POW

## @var rpki_content_type
# HTTP content type used for all RPKI messages.
rpki_content_type = "application/x-rpki"

## @var debug_http
# Verbose chatter about HTTP streams.
debug_http = False

## @var want_persistent_client
# Whether we want persistent HTTP client streams, when server also supports them.
want_persistent_client = False

## @var want_persistent_server
# Whether we want persistent HTTP server streams, when client also supports them.
want_persistent_server = False

## @var default_client_timeout
# Default HTTP client connection timeout.
default_client_timeout = rpki.sundial.timedelta(minutes = 5)

## @var default_server_timeout
# Default HTTP server connection timeouts.  Given our druthers, we'd
# prefer that the client close the connection, as this avoids the
# problem of client starting to reuse connection just as server closes
# it, so this should be longer than the client timeout.
default_server_timeout = rpki.sundial.timedelta(minutes = 10)

## @var default_http_version
# Preferred HTTP version.
default_http_version = (1, 0)

## @var default_tcp_port
# Default port for clients and servers that don't specify one.
default_tcp_port = 80

## @var enable_ipv6_servers
# Whether to enable IPv6 listeners.  Enabled by default, as it should
# be harmless.  Has no effect if kernel doesn't support IPv6.
enable_ipv6_servers = True

## @var enable_ipv6_clients
# Whether to consider IPv6 addresses when making connections.
# Disabled by default, as IPv6 connectivity is still a bad joke in
# far too much of the world.
enable_ipv6_clients = False

## @var have_ipv6
# Whether the current machine claims to support IPv6.  Note that just
# because the kernel supports it doesn't mean that the machine has
# usable IPv6 connectivity.  I don't know of a simple portable way to
# probe for connectivity at runtime (the old test of "can you ping
# SRI-NIC.ARPA?" seems a bit dated...).  Don't set this, it's set
# automatically by probing using the socket() system call at runtime.
try:
  # pylint: disable=W0702,W0104
  socket.socket(socket.AF_INET6).close()
  socket.IPPROTO_IPV6
  socket.IPV6_V6ONLY
except:
  have_ipv6 = False
else:
  have_ipv6 = True

## @var use_adns

# Whether to use rpki.adns code.  This is still experimental, so it's
# not (yet) enabled by default.
use_adns = False
try:
  import rpki.adns
except ImportError:
  pass

def supported_address_families(enable_ipv6):
  """
  IP address families on which servers should listen, and to consider
  when selecting addresses for client connections.
  """
  if enable_ipv6 and have_ipv6:
    return (socket.AF_INET, socket.AF_INET6)
  else:
    return (socket.AF_INET,)

def localhost_addrinfo():
  """
  Return pseudo-getaddrinfo results for localhost.
  """
  result = [(socket.AF_INET, "127.0.0.1")]
  if enable_ipv6_clients and have_ipv6:
    result.append((socket.AF_INET6, "::1"))
  return result

class http_message(object):
  """
  Virtual class representing of one HTTP message.
  """

  software_name = "ISC RPKI library"

  def __init__(self, version = None, body = None, headers = None):
    self.version = version
    self.body = body
    self.headers = headers
    self.normalize_headers()

  def normalize_headers(self, headers = None):
    """
    Clean up (some of) the horrible messes that HTTP allows in its
    headers.
    """
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
    """
    Parse and normalize an incoming HTTP message.
    """
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
    """
    Format an outgoing HTTP message.
    """
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
    """
    Parse HTTP version, raise an exception if we can't.
    """
    if version[:5] != "HTTP/":
      raise rpki.exceptions.HTTPBadVersion, "Couldn't parse version %s" % version
    self.version = tuple(int(i) for i in version[5:].split("."))

  @property
  def persistent(self):
    """
    Figure out whether this HTTP message encourages a persistent connection.
    """
    c = self.headers.get("Connection")
    if self.version == (1, 1):
      return c is None or "close" not in c.lower()
    elif self.version == (1, 0):
      return c is not None and "keep-alive" in c.lower()
    else:
      return False

class http_request(http_message):
  """
  HTTP request message.
  """

  def __init__(self, cmd = None, path = None, version = default_http_version, body = None, callback = None, errback = None, **headers):
    assert cmd == "POST" or body is None
    http_message.__init__(self, version = version, body = body, headers = headers)
    self.cmd = cmd
    self.path = path
    self.callback = callback
    self.errback = errback
    self.retried = False

  def parse_first_line(self, cmd, path, version):
    """
    Parse first line of HTTP request message.
    """
    self.parse_version(version)
    self.cmd = cmd
    self.path = path

  def format_first_line(self):
    """
    Format first line of HTTP request message, and set up the
    User-Agent header.
    """
    self.headers.setdefault("User-Agent", self.software_name)
    return "%s %s HTTP/%d.%d\r\n" % (self.cmd, self.path, self.version[0], self.version[1])

  def __repr__(self):
    return rpki.log.log_repr(self, self.cmd, self.path)
            
class http_response(http_message):
  """
  HTTP response message.
  """

  def __init__(self, code = None, reason = None, version = default_http_version, body = None, **headers):
    http_message.__init__(self, version = version, body = body, headers = headers)
    self.code = code
    self.reason = reason

  def parse_first_line(self, version, code, reason):
    """
    Parse first line of HTTP response message.
    """
    self.parse_version(version)
    self.code = int(code)
    self.reason = reason

  def format_first_line(self):
    """
    Format first line of HTTP response message, and set up Date and
    Server headers.
    """
    self.headers.setdefault("Date", time.strftime("%a, %d %b %Y %T GMT"))
    self.headers.setdefault("Server", self.software_name)
    return "HTTP/%d.%d %s %s\r\n" % (self.version[0], self.version[1], self.code, self.reason)

  def __repr__(self):
    return rpki.log.log_repr(self, self.code, self.reason)

def log_method(self, msg, logger = rpki.log.debug):
  """
  Logging method used in several different classes.
  """
  assert isinstance(logger, rpki.log.logger)
  if debug_http or logger is not rpki.log.debug:
    logger("%r: %s" % (self, msg))

def addr_to_string(addr):
  """
  Convert socket addr tuple to printable string.  Assumes 2-element
  tuple is IPv4, 4-element tuple is IPv6, throws TypeError for
  anything else.
  """

  if len(addr) == 2:
    return "%s:%d" % (addr[0], addr[1])
  if len(addr) == 4:
    return "%s.%d" % (addr[0], addr[1])
  raise TypeError

class http_stream(asynchat.async_chat):
  """
  Virtual class representing an HTTP message stream.
  """

  log = log_method

  def __repr__(self):
    status = ["connected"] if self.connected else []
    try:
      status.append(addr_to_string(self.addr))
    except TypeError:
      pass
    return rpki.log.log_repr(self, *status)

  def __init__(self, sock = None):
    asynchat.async_chat.__init__(self, sock)
    self.buffer = []
    self.timer = rpki.async.timer(self.handle_timeout)
    self.restart()

  def restart(self):
    """
    (Re)start HTTP message parser, reset timer.
    """
    assert not self.buffer
    self.chunk_handler = None
    self.set_terminator("\r\n\r\n")
    self.update_timeout()

  def update_timeout(self):
    """
    Put this stream's timer in known good state: set it to the
    stream's timeout value if we're doing timeouts, otherwise clear
    it.
    """
    if self.timeout is not None:
      self.log("Setting timeout %s" % self.timeout)
      self.timer.set(self.timeout)
    else:
      self.log("Clearing timeout")
      self.timer.cancel()

  def collect_incoming_data(self, data):
    """
    Buffer incoming data from asynchat.
    """
    self.buffer.append(data)
    self.update_timeout()

  def get_buffer(self):
    """
    Consume data buffered from asynchat.
    """
    val = "".join(self.buffer)
    self.buffer = []
    return val

  def found_terminator(self):
    """
    Asynchat reported that it found whatever terminator we set, so
    figure out what to do next.  This can be messy, because we can be
    in any of several different states:

    @li We might be handling chunked HTTP, in which case we have to
    initialize the chunk decoder;

    @li We might have found the end of the message body, in which case
    we can (finally) process it; or

    @li We might have just gotten to the end of the message headers,
    in which case we have to parse them to figure out which of three
    separate mechanisms (chunked, content-length, TCP close) is going
    to tell us how to find the end of the message body.
    """
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
    """
    Asynchat just handed us what should be the header of one chunk of
    a chunked encoding stream.  If this chunk has a body, set the
    stream up to read it; otherwise, this is the last chunk, so start
    the process of exiting the chunk decoder.
    """
    n = int(self.get_buffer().partition(";")[0], 16)
    self.log("Chunk length %s" % n)
    if n:
      self.chunk_handler = self.chunk_body
      self.set_terminator(n)
    else:
      self.msg.body = "".join(self.msg.body)
      self.chunk_handler = self.chunk_discard_trailer

  def chunk_body(self):
    """
    Asynchat just handed us what should be the body of a chunk of the
    body of a chunked message (sic).  Save it, and prepare to move on
    to the next chunk.
    """
    self.log("Chunk body")
    self.msg.body += self.buffer
    self.buffer = []
    self.chunk_handler = self.chunk_discard_crlf
    self.set_terminator("\r\n")

  def chunk_discard_crlf(self):
    """
    Consume the CRLF that terminates a chunk, reinitialize chunk
    decoder to be ready for the next chunk.
    """
    self.log("Chunk CRLF")
    s = self.get_buffer()
    assert s == "", "%r: Expected chunk CRLF, got '%s'" % (self, s)
    self.chunk_handler = self.chunk_header

  def chunk_discard_trailer(self):
    """
    Consume chunk trailer, which should be empty, then (finally!) exit
    the chunk decoder and hand complete message off to the application.
    """
    self.log("Chunk trailer")
    s = self.get_buffer()
    assert s == "", "%r: Expected end of chunk trailers, got '%s'" % (self, s)
    self.chunk_handler = None
    self.handle_message()

  def handle_body(self):
    """
    Hand normal (not chunked) message off to the application.
    """
    self.msg.body = self.get_buffer()
    self.handle_message()

  def handle_error(self):
    """
    Asynchat (or asyncore, or somebody) raised an exception.  See
    whether it's one we should just pass along, otherwise log a stack
    trace and close the stream.
    """
    self.timer.cancel()
    etype = sys.exc_info()[0]
    if etype in (SystemExit, rpki.async.ExitNow):
      raise
    rpki.log.traceback()
    if etype is not rpki.exceptions.HTTPClientAborted:
      self.log("Closing due to error", rpki.log.warn)
      self.close()

  def handle_timeout(self):
    """
    Inactivity timer expired, close connection with prejudice.
    """
    self.log("Timeout, closing")
    self.close()

  def handle_close(self):
    """
    Wrapper around asynchat connection close handler, so that we can
    log the event, cancel timer, and so forth.
    """
    self.log("Close event in HTTP stream handler")
    self.timer.cancel()
    asynchat.async_chat.handle_close(self)

class http_server(http_stream):
  """
  HTTP server stream.
  """

  ## @var parse_type
  # Stream parser should look for incoming HTTP request messages.
  parse_type = http_request

  ## @var timeout
  # Use the default server timeout value set in the module header.
  timeout = default_server_timeout

  def __init__(self, sock, handlers):
    self.handlers = handlers
    http_stream.__init__(self, sock = sock)
    self.expect_close = not want_persistent_server
    self.log("Starting")

  def handle_no_content_length(self):
    """
    Handle an incoming message that used neither chunking nor a
    Content-Length header (that is: this message will be the last one
    in this server stream).  No special action required.
    """
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
    """
    HTTP layer managed to deliver a complete HTTP request to
    us, figure out what to do with it.  Check the command and
    Content-Type, look for a handler, and if everything looks right,
    pass the message body, path, and a reply callback to the handler.
    """
    self.log("Received request %r" % self.msg)
    if not self.msg.persistent:
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
      except Exception, e:
        rpki.log.traceback()
        self.send_error(500, reason = "Unhandled exception %s: %s" % (e.__class__.__name__, e))
    else:
      self.send_error(code = error[0], reason = error[1])

  def send_error(self, code, reason):
    """
    Send an error response to this request.
    """
    self.send_message(code = code, reason = reason)

  def send_reply(self, code, body = None, reason = "OK"):
    """
    Send a reply to this request.
    """
    self.send_message(code = code, body = body, reason = reason)

  def send_message(self, code, reason = "OK", body = None):
    """
    Queue up reply message.  If both parties agree that connection is
    persistant, and if no error occurred, restart this stream to
    listen for next message; otherwise, queue up a close event for
    this stream so it will shut down once the reply has been sent.
    """
    self.log("Sending response %s %s" % (code, reason))
    if code >= 400:
      self.expect_close = True
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
  """
  Listener for incoming HTTP connections.
  """

  log = log_method

  def __repr__(self):
    try:
      status = (addr_to_string(self.addr),)
    except TypeError:
      status = ()
    return rpki.log.log_repr(self, *status)

  def __init__(self, handlers, addrinfo):
    asyncore.dispatcher.__init__(self)
    self.handlers = handlers
    try:
      af, socktype, proto, canonname, sockaddr = addrinfo # pylint: disable=W0612
      self.create_socket(af, socktype)
      self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      try:
        self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
      except AttributeError:
        pass
      if have_ipv6 and af == socket.AF_INET6:
        self.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
      self.bind(sockaddr)
      self.listen(5)
    except Exception, e:
      self.log("Couldn't set up HTTP listener: %s" % e, rpki.log.warn)
      rpki.log.traceback()
      self.close()
    for h in handlers:
      self.log("Handling %s" % h[0])

  def handle_accept(self):
    """
    Asyncore says we have an incoming connection, spawn an http_server
    stream for it and pass along all of our handler data.
    """
    try:
      s, c = self.accept()
      self.log("Accepting connection from %s" % addr_to_string(c))
      http_server(sock = s, handlers = self.handlers)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception, e:
      self.log("Unable to accept connection: %s" % e)
      self.handle_error()

  def handle_error(self):
    """
    Asyncore signaled an error, pass it along or log it.
    """
    if sys.exc_info()[0] in (SystemExit, rpki.async.ExitNow):
      raise
    self.log("Error in HTTP listener", rpki.log.warn)
    rpki.log.traceback()

class http_client(http_stream):
  """
  HTTP client stream.
  """

  ## @var parse_type
  # Stream parser should look for incoming HTTP response messages.
  parse_type = http_response

  ## @var timeout
  # Use the default client timeout value set in the module header.
  timeout = default_client_timeout

  ## @var state
  # Application layer connection state.
  state = None

  def __init__(self, queue, hostport):
    self.log("Creating new connection to %s" % addr_to_string(hostport))
    http_stream.__init__(self)
    self.queue = queue
    self.host = hostport[0]
    self.port = hostport[1]
    self.set_state("opening")
    self.expect_close = not want_persistent_client

  def start(self):
    """
    Create socket and request a connection.
    """
    if not use_adns:
      self.log("Not using ADNS")
      self.gotaddrinfo([(socket.AF_INET, self.host)])
    elif self.host == "localhost":
      self.log("Bypassing DNS for localhost")
      self.gotaddrinfo(localhost_addrinfo())
    else:
      families = supported_address_families(enable_ipv6_clients)
      self.log("Starting ADNS lookup for %s in families %r" % (self.host, families))
      rpki.adns.getaddrinfo(self.gotaddrinfo, self.dns_error, self.host, families)

  def dns_error(self, e):
    """
    Handle DNS lookup errors.  For now, just whack the connection.
    Undoubtedly we should do something better with diagnostics here.
    """
    self.handle_error()

  def gotaddrinfo(self, addrinfo):
    """
    Got address data from DNS, create socket and request connection.
    """
    try:
      self.af, self.address = random.choice(addrinfo)
      self.log("Connecting to AF %s host %s port %s addr %s" % (self.af, self.host, self.port, self.address))
      self.create_socket(self.af, socket.SOCK_STREAM)
      self.connect((self.address, self.port))
      if self.addr is None:
        self.addr = (self.host, self.port)
      self.update_timeout()
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception:
      self.handle_error()

  def handle_connect(self):
    """
    Asyncore says socket has connected.
    """
    self.log("Socket connected")
    self.set_state("idle")
    assert self.queue.client is self
    self.queue.send_request()

  def set_state(self, state):
    """
    Set HTTP client connection state.
    """
    self.log("State transition %s => %s" % (self.state, state))
    self.state = state

  def handle_no_content_length(self):
    """
    Handle response message that used neither chunking nor a
    Content-Length header (that is: this message will be the last one
    in this server stream).  In this case we want to read until we
    reach the end of the data stream.
    """
    self.set_terminator(None)

  def send_request(self, msg):
    """
    Queue up request message and kickstart connection.
    """
    self.log("Sending request %r" % msg)
    assert self.state == "idle", "%r: state should be idle, is %s" % (self, self.state)
    self.set_state("request-sent")
    msg.headers["Connection"] = "Close" if self.expect_close else "Keep-Alive"
    self.push(msg.format())
    self.restart()

  def handle_message(self):
    """
    Handle incoming HTTP response message.  Make sure we're in a state
    where we expect to see such a message (and allow the mysterious
    empty messages that Apache sends during connection close, no idea
    what that is supposed to be about).  If everybody agrees that the
    connection should stay open, put it into an idle state; otherwise,
    arrange for the stream to shut down.
    """

    self.log("Message received, state %s" % self.state)

    if not self.msg.persistent:
      self.expect_close = True

    if self.state != "request-sent":
      if self.state == "closing":
        assert not self.msg.body
        self.log("Ignoring empty response received while closing")
        return
      raise rpki.exceptions.HTTPUnexpectedState, "%r received message while in unexpected state %s" % (self, self.state)

    if self.expect_close:
      self.log("Closing")
      self.set_state("closing")
      self.close_when_done()
    else:
      self.log("Idling")
      self.set_state("idle")
      self.update_timeout()

    if self.msg.code != 200:
      errmsg = "HTTP request failed"
      if self.msg.code is not None:
        errmsg += " with status %s" % self.msg.code
      if self.msg.reason:
        errmsg += ", reason %s" % self.msg.reason
      if self.msg.body:
        errmsg += ", response %s" % self.msg.body
      raise rpki.exceptions.HTTPRequestFailed(errmsg)
    self.queue.return_result(self, self.msg, detach = self.expect_close)

  def handle_close(self):
    """
    Asyncore signaled connection close.  If we were waiting for that
    to find the end of a response message, process the resulting
    message now; if we were waiting for the response to a request we
    sent, signal the error.
    """
    http_stream.handle_close(self)
    self.log("State %s" % self.state)
    if self.get_terminator() is None:
      self.handle_body()
    elif self.state == "request-sent":
      raise rpki.exceptions.HTTPClientAborted, "HTTP request aborted by close event"
    else:
      self.queue.detach(self)

  def handle_timeout(self):
    """
    Connection idle timer has expired.  Shut down connection in any
    case, noisily if we weren't idle.
    """
    bad = self.state not in ("idle", "closing")
    if bad:
      self.log("Timeout while in state %s" % self.state, rpki.log.warn)
    http_stream.handle_timeout(self)
    if bad:
      try:
        raise rpki.exceptions.HTTPTimeout
      except:                           # pylint: disable=W0702
        self.handle_error()
    else:
      self.queue.detach(self)

  def handle_error(self):
    """
    Asyncore says something threw an exception.  Log it, then shut
    down the connection and pass back the exception.
    """
    eclass, edata = sys.exc_info()[0:2]
    self.log("Error on HTTP client connection %s:%s %s %s" % (self.host, self.port, eclass, edata), rpki.log.warn)
    http_stream.handle_error(self)
    self.queue.return_result(self, edata, detach = True)

class http_queue(object):
  """
  Queue of pending HTTP requests for a single destination.  This class
  is very tightly coupled to http_client; http_client handles the HTTP
  stream itself, this class provides a slightly higher-level API.
  """

  log = log_method

  def __repr__(self):
    return rpki.log.log_repr(self, addr_to_string(self.hostport))

  def __init__(self, hostport):
    self.hostport = hostport
    self.client = None
    self.log("Created")
    self.queue = []

  def request(self, *requests):
    """
    Append http_request object(s) to this queue.
    """
    self.log("Adding requests %r" % requests)
    self.queue.extend(requests)

  def restart(self):
    """
    Send next request for this queue, if we can.  This may involve
    starting a new http_client stream, reusing an existing idle
    stream, or just ignoring this request if there's an active client
    stream already; in the last case, handling of the response (or
    exception, or timeout) for the query currently in progress will
    call this method when it's time to kick out the next query.
    """
    try:
      if self.client is None:
        self.client = http_client(self, self.hostport)
        self.log("Attached client %r" % self.client)
        self.client.start()
      elif self.client.state == "idle":
        self.log("Sending request to existing client %r" % self.client)
        self.send_request()
      else:
        self.log("Client %r exists in state %r" % (self.client, self.client.state))
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception, e:
      self.return_result(self.client, e, detach = True)

  def send_request(self):
    """
    Kick out the next query in this queue, if any.
    """
    if self.queue:
      self.client.send_request(self.queue[0])

  def detach(self, client_):
    """
    Detatch a client from this queue.  Silently ignores attempting to
    detach a client that is not attached to this queue, to simplify
    handling of what otherwise would be a nasty set of race
    conditions.
    """
    if client_ is self.client:
      self.log("Detaching client %r" % client_)
      self.client = None

  def return_result(self, client, result, detach = False): # pylint: disable=W0621
    """
    Client stream has returned a result, which we need to pass along
    to the original caller.  Result may be either an HTTP response
    message or an exception.  In either case, once we're done
    processing this result, kick off next message in the queue, if any.
    """

    if client is not self.client:
      self.log("Wrong client trying to return result.  THIS SHOULD NOT HAPPEN.  Dropping result %r" % result, rpki.log.warn)
      return

    if detach:
      self.detach(client)

    try:
      req = self.queue.pop(0)
      self.log("Dequeuing request %r" % req)
    except IndexError:
      self.log("No caller.  THIS SHOULD NOT HAPPEN.  Dropping result %r" % result, rpki.log.warn)
      return

    assert isinstance(result, http_response) or isinstance(result, Exception)

    if isinstance(result, http_response):
      try:
        self.log("Returning result %r to caller" % result)
        req.callback(result.body)
      except (rpki.async.ExitNow, SystemExit):
        raise
      except Exception, e:
        result = e

    if isinstance(result, Exception):
      try:
        self.log("Returning exception %r to caller: %s" % (result, result), rpki.log.warn)
        req.errback(result)
      except (rpki.async.ExitNow, SystemExit):
        raise
      except Exception:
        #
        # If we get here, we may have lost the event chain.  Not
        # obvious what we can do about it at this point, but force a
        # traceback so that it will be somewhat obvious that something
        # really bad happened.
        #
        self.log("Exception in exception callback", rpki.log.warn)
        rpki.log.traceback(True)

    self.log("Queue: %r" % self.queue)

    if self.queue:
      self.restart()

## @var client_queues
# Map of (host, port) tuples to http_queue objects.
client_queues = {}

def client(msg, url, callback, errback):
  """
  Open client HTTP connection, send a message, set up callbacks to
  handle response.
  """

  u = urlparse.urlparse(url)

  if (u.scheme not in ("", "http") or
      u.username is not None or
      u.password is not None or
      u.params   != "" or
      u.query    != "" or
      u.fragment != ""):
    raise rpki.exceptions.BadClientURL, "Unusable URL %s" % url

  if debug_http:
    rpki.log.debug("Contacting %s" % url)

  request = http_request(
    cmd                 = "POST",
    path                = u.path,
    body                = msg,
    callback            = callback,
    errback             = errback,
    Host                = u.hostname,
    Content_Type        = rpki_content_type)

  hostport = (u.hostname or "localhost", u.port or default_tcp_port)

  if debug_http:
    rpki.log.debug("Created request %r for %s" % (request, addr_to_string(hostport)))
  if hostport not in client_queues:
    client_queues[hostport] = http_queue(hostport)
  client_queues[hostport].request(request)

  # Defer connection attempt until after we've had time to process any
  # pending I/O events, in case connections have closed.

  if debug_http:
    rpki.log.debug("Scheduling connection startup for %r" % request)
  rpki.async.event_defer(client_queues[hostport].restart)

def server(handlers, port, host = ""):
  """
  Run an HTTP server and wait (forever) for connections.
  """

  if not isinstance(handlers, (tuple, list)):
    handlers = (("/", handlers),)

  # Yes, this is sick.  So is getaddrinfo() returning duplicate
  # records, which RedHat has the gall to claim is a feature.
  ai = []
  for af in supported_address_families(enable_ipv6_servers):
    try:
      if host:
        h = host
      elif have_ipv6 and af == socket.AF_INET6:
        h = "::"
      else:
        h = "0.0.0.0"
      for a in socket.getaddrinfo(h, port, af, socket.SOCK_STREAM):
        if a not in ai:
          ai.append(a)
    except socket.gaierror:
      pass

  for a in ai:
    http_listener(addrinfo = a, handlers = handlers)

  rpki.async.event_loop()

class caller(object):
  """
  Handle client-side mechanics for protocols based on HTTP, CMS, and
  rpki.xml_utils.  Calling sequence is intended to nest within
  rpki.async.sync_wrapper.
  """

  debug = False

  def __init__(self, proto, client_key, client_cert, server_ta, server_cert, url, debug = None):
    self.proto = proto
    self.client_key = client_key
    self.client_cert = client_cert
    self.server_ta = server_ta
    self.server_cert = server_cert
    self.url = url
    self.cms_timestamp = None
    if debug is not None:
      self.debug = debug

  def __call__(self, cb, eb, *pdus):

    def done(r_der):
      """
      Handle CMS-wrapped XML response message.
      """
      try:
        r_cms = self.proto.cms_msg(DER = r_der)
        r_msg = r_cms.unwrap((self.server_ta, self.server_cert))
        self.cms_timestamp = r_cms.check_replay(self.cms_timestamp)
        if self.debug:
          print "<!-- Reply -->"
          print r_cms.pretty_print_content()
        cb(r_msg)
      except (rpki.async.ExitNow, SystemExit):
        raise
      except Exception, e:
        eb(e)

    q_msg = self.proto.msg.query(*pdus)
    q_cms = self.proto.cms_msg()
    q_der = q_cms.wrap(q_msg, self.client_key, self.client_cert)
    if self.debug:
      print "<!-- Query -->"
      print q_cms.pretty_print_content()

    client(url = self.url, msg = q_der, callback = done, errback = eb)
