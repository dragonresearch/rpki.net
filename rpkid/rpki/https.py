"""
HTTPS utilities, both client and server.

$Id$

Copyright (C) 2009-2010  Internet Systems Consortium ("ISC")

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
import POW

## @var rpki_content_type
# HTTP content type used for all RPKI messages.
rpki_content_type = "application/x-rpki"

## @var debug_http
# Verbose chatter about HTTP streams.
debug_http = False

## @var debug_tls_certs
# Verbose chatter about TLS certificates.
debug_tls_certs = False

## @var want_persistent_client
# Whether we want persistent HTTP client streams, when server also supports them.
want_persistent_client = False

## @var want_persistent_server
# Whether we want persistent HTTP server streams, when client also supports them.
want_persistent_server = False

## @var default_client_timeout
# Default HTTP client connection timeout.
default_client_timeout = rpki.sundial.timedelta(minutes = 15)

## @var default_server_timeout
# Default HTTP server connection timeouts.  Given our druthers, we'd
# prefer that the client close the connection, as this avoids the
# problem of client starting to reuse connection just as server closes
# it, so this should be longer than the client timeout.
default_server_timeout = rpki.sundial.timedelta(minutes = 20)

## @var default_http_version
# Preferred HTTP version.
default_http_version = (1, 0)

## @var default_tcp_port
# Default port for clients and servers that don't specify one.
default_tcp_port = 443

## @var enable_ipv6_servers
# Whether to enable IPv6 listeners.  Enabled by default, as it should
# be harmless.  Has no effect if kernel doesn't support IPv6.
enable_ipv6_servers = True

## @var enable_ipv6_clients
# Whether to consider IPv6 addresses when making connections.
# Disabled by default, as IPv6 connectivity is still a bad joke in
# far too much of the world.
enable_ipv6_clients = False

## @var use_adns
# Whether to use rpki.adns code.  This is still experimental, so it's
# not (yet) enabled by default.
use_adns = False

## @var have_ipv6
# Whether the current machine claims to support IPv6.  Note that just
# because the kernel supports it doesn't mean that the machine has
# usable IPv6 connectivity.  I don't know of a simple portable way to
# probe for connectivity at runtime (the old test of "can you ping
# SRI-NIC.ARPA?" seems a bit dated...).  Don't set this, it's set
# automatically by probing using the socket() system call at runtime.
try:
  socket.socket(socket.AF_INET6).close()
except:
  have_ipv6 = False
else:
  have_ipv6 = True

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
      raise rpki.exceptions.HTTPSBadVersion, "Couldn't parse version %s" % version
    self.version = tuple(int(i) for i in version[5:].split("."))

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

def log_method(self, msg, logger = rpki.log.debug):
  """
  Logging method used in several different classes.
  """
  assert isinstance(logger, rpki.log.logger)
  if debug_http or logger is not rpki.log.debug:
    logger("%r: %s" % (self, msg))

class http_stream(asynchat.async_chat):
  """
  Virtual class representing an HTTP message stream.
  """

  log = log_method
  tls = None
  retry_read = None
  retry_write = None

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
      self.log("Setting timeout %r" % self.timeout)
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
    etype = sys.exc_info()[0]
    if etype in (SystemExit, rpki.async.ExitNow):
      self.log("Caught %s, propagating" % etype.__name__)
      raise
    self.log("Error in HTTP stream handler", rpki.log.warn)
    rpki.log.traceback()
    if etype not in (rpki.exceptions.HTTPSClientAborted,):
      self.log("Closing due to error", rpki.log.warn)
      self.close(force = True)

  def handle_timeout(self):
    """
    Inactivity timer expired, close connection with prejudice.
    """
    self.log("Timeout, closing")
    self.close(force = True)

  def handle_close(self):
    """
    Wrapper around asynchat connection close handler, so that we can
    log the event.
    """
    self.log("Close event in HTTP stream handler")
    asynchat.async_chat.handle_close(self)

  def send(self, data):
    """
    TLS replacement for normal asyncore .send() method.  Throw an
    exception if TLS hasn't been started or if TLS I/O was already in
    progress, otherwise hand off to the TLS code.
    """
    assert self.retry_read is None and self.retry_write is None, "%r: TLS I/O already in progress, r %r w %r" % (self, self.retry_read, self.retry_write)
    assert self.tls is not None
    return self.tls.write(data)

  def recv(self, buffer_size):
    """
    TLS replacement for normal asyncore .recv() method.  Throw an
    exception if TLS hasn't been started or if TLS I/O was already in
    progress, otherwise hand off to the TLS code.
    """
    assert self.retry_read is None and self.retry_write is None, "%r: TLS I/O already in progress, r %r w %r" % (self, self.retry_read, self.retry_write)
    assert self.tls is not None
    return self.tls.read(buffer_size)

  def readable(self):
    """
    TLS replacement for normal asynchat .readable() method.  A TLS
    connection that's blocked waiting for TLS write is considered not
    readable even if the underlying socket is.
    """
    return self.retry_read is not None or (self.retry_write is None and asynchat.async_chat.readable(self))

  def writeable(self):
    """
    TLS replacement for normal asynchat .writeable() method.  A TLS
    connection that's blocked waiting for TLS read is considered not
    writeable even if the underlying socket is.
    """
    return self.retry_write is not None or (self.retry_read is None and asynchat.async_chat.writeable(self))

  def handle_read(self):
    """
    Asyncore says socket is readable.  Make sure there's no TLS write
    already in progress, retry previous read operation if we had one
    that was waiting for more input, otherwise try to read some data,
    and handle all the weird OpenSSL exceptions that the TLS code
    throws.
    """
    assert self.retry_write is None, "%r: TLS I/O already in progress, w %r" % (self, self.retry_write)
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
        self.handle_close()
      except POW.SSLUnexpectedEOFError:
        self.log("SSLUnexpectedEOF in handle_read()", rpki.log.warn)
        self.handle_error()
        
  def handle_write(self):
    """
    Asyncore says socket is writeable.  Make sure there's no TLS read
    already in progress, retry previous write operation if we had one
    that was blocked on the socket, otherwise try to write some data.
    Handling all the weird OpenSSL exceptions that TLS throws is our
    caller's problem.
    """
    # This used to be an assertion, but apparently this can happen
    # without anything really being wrong, as a sort of race
    # condition, due to select() having signaled that a socket was
    # both readable and writable.  I think.
    #
    if self.retry_read is not None:
      self.log("TLS I/O already in progress, r %r" % self.retry_read)
      return
    if self.retry_write is not None:
      thunk = self.retry_write
      self.retry_write = None
      thunk()
      self.log("Retrying TLS write %r" % thunk)
    else:
      asynchat.async_chat.handle_write(self)

  def initiate_send(self):
    """
    Initiate a write operation.  This is just a wrapper around the
    asynchat method, to handle all the whacky TLS exceptions.
    """
    assert self.retry_read is None and self.retry_write is None, "%r: TLS I/O already in progress, r %r w %r" % (self, self.retry_read, self.retry_write)
    try:
      asynchat.async_chat.initiate_send(self)
    except POW.WantReadError:
      self.retry_read = self.initiate_send
    except POW.WantWriteError:
      self.retry_write = self.initiate_send
    except POW.ZeroReturnError:
      self.log("ZeroReturn in initiate_send()")
      self.handle_close()
    except POW.SSLUnexpectedEOFError:
      self.log("SSLUnexpectedEOF in initiate_send()", rpki.log.warn)
      self.handle_error()

  def close(self, force = False):
    """
    Close the stream.

    Graceful shutdown of a TLS connection requires multiple calls to
    the underlying TLS code.  If the connection should be closed right
    now without waiting (perhaps because it's already dead and we're
    just cleaning up), call with force = True.
    """
    self.log("Close requested")
    assert force or (self.retry_read is None and self.retry_write is None), "%r: TLS I/O already in progress, r %r w %r" % (self, self.retry_read, self.retry_write)
    if self.tls is not None:
      try:
        if self.retry_read is None and self.retry_write is None:
          ret = self.tls.shutdown()
        else:
          ret = None
        self.log("tls.shutdown() returned %s, force_shutdown %s" % (ret, force))
        if ret or force:
          self.tls = None
      except POW.WantReadError:
        self.retry_read = self.close
      except POW.WantWriteError:
        self.retry_write = self.close
      except POW.SSLError, e:
        self.log("tls.shutdown() threw %s, shutting down anyway" % e)
        self.tls = None
    if self.tls is None:
      self.log("TLS layer is done, closing socket")
      self.timer.cancel()
      self.timer.set_handler(None)
      try:
        asynchat.async_chat.close(self)
      except AttributeError:
        if getattr(self, "socket", None) is not None:
          raise

  def log_cert(self, tag, x):
    """
    Log HTTPS certificates, if certificate debugging is enabled.
    """
    if debug_tls_certs:
      rpki.log.debug("%r: HTTPS %s cert %r issuer %s [%s] subject %s [%s]" % (self, tag, x, x.getIssuer(), x.hAKI(), x.getSubject(), x.hSKI()))

class http_server(http_stream):
  """
  HTTP(S) server stream.
  """

  ## @var parse_type
  # Stream parser should look for incoming HTTP request messages.
  parse_type = http_request

  ## @var timeout
  # Use the default server timeout value set in the module header.
  timeout = default_server_timeout

  def __init__(self, sock, handlers, cert = None, key = None, ta = (), dynamic_ta = None):
    self.log("Starting")
    self.handlers = handlers
    http_stream.__init__(self, sock = sock)
    self.expect_close = not want_persistent_server

    self.log("cert %r key %r ta %r dynamic_ta %r" % (cert, key, ta, dynamic_ta))

    self.tls = POW.Ssl(POW.TLSV1_SERVER_METHOD)
    self.log_cert("server", cert)
    self.tls.useCertificate(cert.get_POW())
    self.tls.useKey(key.get_POW())
    ta = rpki.x509.X509.normalize_chain(dynamic_ta() if dynamic_ta else ta)
    assert ta
    for x in ta:
      self.log_cert("trusted", x)
      self.tls.addTrust(x.get_POW())
    self.tls.setVerifyMode(POW.SSL_VERIFY_PEER | POW.SSL_VERIFY_FAIL_IF_NO_PEER_CERT)

    self.tls.setFd(self.fileno())
    self.tls_accept()

  def tls_accept(self):
    """
    Set up TLS for server side connection, handling all the whacky
    OpenSSL exceptions from TLS.

    SSLErrorSSLError exceptions are particularly nasty, because all
    too often they indicate a certificate lookup failure deep within
    the guts of OpenSSL's TLS connection setup logic.  Extracting
    anything resembling a Python data structure from a handler called
    that deep inside the OpenSSL TLS library, while theoretically
    possible, runs a high risk of triggering some kind of memory leak
    or corruption.  So, for now, we just get back a long text string,
    which we break up and log but don't attempt to process further.
    """
    try:
      self.tls.accept()
    except POW.WantReadError:
      self.retry_read = self.tls_accept
    except POW.WantWriteError:
      self.retry_write = self.tls_accept
    except POW.SSLUnexpectedEOFError:
      self.log("SSLUnexpectedEOF in tls_accept()")
      self.handle_error()
    except POW.SSLErrorSSLError, e:
      if "\n" in e:
        for line in str(e).splitlines():
          rpki.log.error(line)
        raise POW.SSLErrorSSLError, "TLS certificate problem, most likely"
      else:
        raise
    
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
    TLS and HTTP layers managed to deliver a complete HTTP request to
    us, figure out what to do with it.  Check the command and
    Content-Type, look for a handler, and if everything looks right,
    pass the message body, path, and a reply callback to the handler.
    """
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
      except Exception, e:
        rpki.log.traceback()
        self.send_error(500, "Unhandled exception %s" % e)
    else:
      self.send_error(code = error[0], reason = error[1])

  def send_error(self, code, reason):
    """
    Send an error response to this request.
    """
    self.send_message(code = code, reason = reason)

  def send_reply(self, code, body):
    """
    Send a reply to this request.
    """
    self.send_message(code = code, body = body)

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
  Listener for incoming HTTP(S) connections.
  """

  log = log_method

  def __init__(self, handlers, addrinfo, cert = None, key = None, ta = None, dynamic_ta = None):
    self.log("Listener cert %r key %r ta %r dynamic_ta %r" % (cert, key, ta, dynamic_ta))
    asyncore.dispatcher.__init__(self)
    self.handlers = handlers
    self.cert = cert
    self.key = key
    self.ta = ta
    self.dynamic_ta = dynamic_ta
    try:
      af, socktype, proto, canonname, sockaddr = addrinfo
      self.create_socket(af, socktype)
      self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      if hasattr(socket, "SO_REUSEPORT"):
        self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
      self.bind(sockaddr)
      self.listen(5)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except:
      self.handle_error()
    self.log("Listening on %r, handlers %r" % (sockaddr, handlers))

  def handle_accept(self):
    """
    Asyncore says we have an incoming connection, spawn an http_server
    stream for it and pass along all of our handler and TLS data.
    """
    self.log("Accepting connection")
    try:
      http_server(sock = self.accept()[0], handlers = self.handlers, cert = self.cert, key = self.key, ta = self.ta, dynamic_ta = self.dynamic_ta)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except:
      self.handle_error()

  def handle_error(self):
    """
    Asyncore signaled an error, pass it along or log it.
    """
    if sys.exc_info()[0] is SystemExit:
      self.log("Caught SystemExit, propagating")
      raise
    else:
      self.log("Error in HTTP listener", rpki.log.warn)
      rpki.log.traceback()

class http_client(http_stream):
  """
  HTTP(S) client stream.
  """

  ## @var parse_type
  # Stream parser should look for incoming HTTP response messages.
  parse_type = http_response

  ## @var timeout
  # Use the default client timeout value set in the module header.
  timeout = default_client_timeout

  def __init__(self, queue, hostport, cert = None, key = None, ta = ()):
    self.log("Creating new connection to %r" % (hostport,))
    self.log("cert %r key %r ta %r" % (cert, key, ta))
    http_stream.__init__(self)
    self.queue = queue
    self.host = hostport[0]
    self.port = hostport[1]
    self.state = "opening"
    self.expect_close = not want_persistent_client
    self.cert = cert
    self.key = key
    self.ta = rpki.x509.X509.normalize_chain(ta)

  def start(self):
    """
    Create socket and request a connection.
    """
    if not use_adns:
      self.gotaddrinfo([(socket.AF_INET, self.host)])
    elif self.host == "localhost":
      self.gotaddrinfo(localhost_addrinfo())
    else:
      import rpki.adns                  # This should move to start of file once we've decided to inflict it on all users
      rpki.adns.getaddrinfo(self.gotaddrinfo, self.dns_error, self.host, supported_address_families(enable_ipv6_clients))

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
      self.af, self.addr = random.choice(addrinfo)
      self.create_socket(self.af, socket.SOCK_STREAM)
      self.connect((self.addr, self.port))
    except (rpki.async.ExitNow, SystemExit):
      raise
    except:
      self.handle_error()

  def handle_connect(self):
    """
    Asyncore says socket has connected, configure TLS junk.
    """
    self.log("Socket connected")
    self.tls = POW.Ssl(POW.TLSV1_CLIENT_METHOD)
    self.log_cert("client", self.cert)
    self.tls.useCertificate(self.cert.get_POW())
    self.tls.useKey(self.key.get_POW())
    assert self.ta
    for x in self.ta:
      self.log_cert("trusted", x)
      self.tls.addTrust(x.get_POW())
    self.tls.setVerifyMode(POW.SSL_VERIFY_PEER | POW.SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
    self.tls.setFd(self.fileno())
    self.tls_connect()

  def tls_connect(self):
    """
    Initialize client side of TLS.
    """
    try:
      self.tls.connect()
    except POW.WantReadError:
      self.retry_read = self.tls_connect
    except POW.WantWriteError:
      self.retry_write = self.tls_connect
    else:
      self.log("TLS connected")
      self.set_state("idle")
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

    if not self.msg.persistent():
      self.expect_close = True

    if self.state != "request-sent":
      if self.state == "closing":
        assert not self.msg.body
        self.log("Ignoring empty response received while closing")
        return
      raise rpki.exceptions.HTTPSUnexpectedState, "%r received message while in unexpected state %s" % (self, self.state)

    if self.expect_close:
      self.log("Closing")
      self.set_state("closing")
      self.queue.detach(self)
      self.close_when_done()
    else:
      self.log("Idling")
      self.set_state("idle")
      self.update_timeout()

    if self.msg.code != 200:
      raise rpki.exceptions.HTTPRequestFailed, "HTTPS request failed with status %s, reason %s, response %s" % (self.msg.code, self.msg.reason, self.msg.body)
    self.queue.return_result(self.msg)

  def handle_close(self):
    """
    Asyncore signaled connection close.  If we were waiting for that
    to find the end of a response message, process the resulting
    message now; if we were waiting for the response to a request we
    sent, signal the error.
    """
    http_stream.handle_close(self)
    self.log("State %s" % self.state)
    self.queue.detach(self)
    if self.get_terminator() is None:
      self.handle_body()
    elif self.state == "request-sent":
      raise rpki.exceptions.HTTPSClientAborted, "HTTPS request aborted by close event"

  def handle_timeout(self):
    """
    Connection idle timer has expired.  Shut down connection in any
    case, noisily if we weren't idle.
    """
    if self.state != "idle":
      self.log("Timeout while in state %s" % self.state, rpki.log.warn)
    http_stream.handle_timeout(self)
    self.queue.detach(self)
    if self.state != "idle":
      try:
        raise rpki.exceptions.HTTPTimeout
      except rpki.exceptions.HTTPTimeout, e:
        self.queue.return_result(e)

  def handle_error(self):
    """
    Asyncore says something threw an exception.  Log it, then shut
    down the connection and pass back the exception.
    """
    eclass, edata = sys.exc_info()[0:2]
    self.log("Error on HTTP client connection %s:%s: %s %s" % (self.host, self.port, eclass, edata), rpki.log.warn)
    http_stream.handle_error(self)
    self.queue.detach(self)
    self.queue.return_result(edata)

class http_queue(object):
  """
  Queue of pending HTTP requests for a single destination.  This class
  is very tightly coupled to http_client; http_client handles the HTTP
  stream itself, this class provides a slightly higher-level API.
  """

  log = log_method

  def __init__(self, hostport, cert = None, key = None, ta = ()):
    self.log("Creating queue for %r" % (hostport,))
    self.log("cert %r key %r ta %r" % (cert, key, ta))
    self.hostport = hostport
    self.client = None
    self.queue = []
    self.cert = cert
    self.key = key
    self.ta = ta

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
        self.client = http_client(self, self.hostport, cert = self.cert, key = self.key, ta = self.ta)
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
      self.return_result(e)

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

  def return_result(self, result):
    """
    Client stream has returned a result, which we need to pass along
    to the original caller.  Result may be either an HTTP response
    message or an exception.  In either case, once we're done
    processing this result, kick off next message in the queue, if any.
    """

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
        self.log("Returning exception %r to caller: %s" % (result, result), rpki.log.warn)
        req.errback(result)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except:
      self.log("Unhandled exception from callback")
      rpki.log.traceback()

    self.log("Queue: %r" % self.queue)

    if self.queue:
      self.restart()

## @var client_queues
# Map of (host, port) tuples to http_queue objects.
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
    rpki.log.debug("Created request %r for %r" % (request, hostport))
  if not isinstance(server_ta, (tuple, list)):
    server_ta = (server_ta,)
  if hostport not in client_queues:
    client_queues[hostport] = http_queue(hostport, cert = client_cert, key = client_key, ta = server_ta)
  client_queues[hostport].request(request)

  # Defer connection attempt until after we've had time to process any
  # pending I/O events, in case connections have closed.

  if debug_http:
    rpki.log.debug("Scheduling connection startup for %r" % request)
  rpki.async.defer(client_queues[hostport].restart)

def server(handlers, server_key, server_cert, port, host ="", client_ta = (), dynamic_https_trust_anchor = None):
  """
  Run an HTTPS server and wait (forever) for connections.
  """

  if not isinstance(handlers, (tuple, list)):
    handlers = (("/", handlers),)

  if not isinstance(client_ta, (tuple, list)):
    client_ta = (client_ta,)

  for af in supported_address_families(enable_ipv6_servers):
    try:
      for addrinfo in socket.getaddrinfo(host if host else "::" if have_ipv6 and af == socket.AF_INET6 else "0.0.0.0",
                                         port, af, socket.SOCK_STREAM):
        http_listener(addrinfo = addrinfo, handlers = handlers, cert = server_cert, key = server_key, ta = client_ta, dynamic_ta = dynamic_https_trust_anchor)
    except socket.gaierror, e:
      rpki.log.info("getaddrinfo() error for AF %d, host %s, port %s, skipping address family: %s" % (af, host, port, e))
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

class caller(object):
  """
  Handle client-side mechanics for protocols based on HTTPS, CMS, and
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
    if debug is not None:
      self.debug = debug

  def __call__(self, cb, eb, *pdus):

    def done(cms):
      """
      Handle CMS-wrapped XML response message.
      """
      result = self.proto.cms_msg.unwrap(cms, (self.server_ta, self.server_cert), pretty_print = self.debug)
      if self.debug:
        msg, xml = result
        print "<!-- Reply -->"
        print xml
      else:
        msg = result
      cb(msg)

    msg = self.proto.msg.query(*pdus)
    result = self.proto.cms_msg.wrap(msg, self.client_key, self.client_cert, pretty_print = self.debug)
    if self.debug:
      cms, xml = result
      print "<!-- Query -->"
      print xml
    else:
      cms = result

    client(
      client_key   = self.client_key,
      client_cert  = self.client_cert,
      server_ta    = self.server_ta,
      url          = self.url,
      msg          = cms,
      callback     = done,
      errback      = eb)
