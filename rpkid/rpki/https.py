"""HTTPS utilities, both client and server.

At the moment this only knows how to use the PEM certs in my
subversion repository; generalizing it would not be hard, but the more
general version should use SQL anyway.

$Id$

Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")

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

import httplib, BaseHTTPServer, tlslite.api, glob, traceback, urlparse, socket, signal
import rpki.x509, rpki.exceptions, rpki.log

# This should be wrapped somewhere in rpki.x509 eventually
import POW

# Do not set this to True for production use!
disable_tls_certificate_validation_exceptions = False

# Chatter about TLS certificates
debug_tls_certs = False

# Debugging hack while converting to event-driven I/O model
trace_synchronous_calls = False

rpki_content_type = "application/x-rpki"

def tlslite_certChain(x509):
  """Utility function to construct tlslite certChains."""
  if isinstance(x509, rpki.x509.X509):
    return tlslite.api.X509CertChain([x509.get_tlslite()])
  else:
    return tlslite.api.X509CertChain([x.get_tlslite() for x in x509])

def build_https_ta_cache(certs):
  """Build a dynamic TLS trust anchor cache."""

  store = POW.X509Store()
  for x in certs:
    if rpki.https.debug_tls_certs:
      rpki.log.debug("HTTPS dynamic trusted cert issuer %s [%s] subject %s [%s]" % (x.getIssuer(), x.hAKI(), x.getSubject(), x.hSKI()))
    store.addTrust(x.get_POW())
  return store

class Checker(tlslite.api.Checker):
  """Derived class to handle X.509 client certificate checking."""

  ## @var refuse_tls_ca_certs
  # Raise an exception upon receiving CA certificates via TLS rather
  # than just quietly ignoring them.

  refuse_tls_ca_certs = False

  ## @var pem_dump_tls_certs
  # Vile debugging hack

  pem_dump_tls_certs = False

  def __init__(self, trust_anchor = None, dynamic_https_trust_anchor = None):
    """Initialize our modified certificate checker."""

    self.dynamic_https_trust_anchor = dynamic_https_trust_anchor

    if dynamic_https_trust_anchor is not None:
      return

    self.x509store = POW.X509Store()

    trust_anchor = rpki.x509.X509.normalize_chain(trust_anchor)
    assert trust_anchor

    for x in trust_anchor:
      if debug_tls_certs:
        rpki.log.debug("HTTPS trusted cert issuer %s [%s] subject %s [%s]" % (x.getIssuer(), x.hAKI(), x.getSubject(), x.hSKI()))
      self.x509store.addTrust(x.get_POW())
      if self.pem_dump_tls_certs:
        print x.get_PEM()

  def x509store_thunk(self):
    if self.dynamic_https_trust_anchor is not None:
      return self.dynamic_https_trust_anchor()
    else:
      return self.x509store

  def __call__(self, tlsConnection):
    """POW/OpenSSL-based certificate checker.

    Given our BPKI model, we're only interested in the TLS EE
    certificates.
    """

    if tlsConnection._client:
      chain = tlsConnection.session.serverCertChain
      peer = "server"
    else:
      chain = tlsConnection.session.clientCertChain
      peer = "client"

    chain = [rpki.x509.X509(tlslite = chain.x509List[i]) for i in range(chain.getNumCerts())]

    ee = None

    for x in chain:

      if debug_tls_certs:
        rpki.log.debug("Received %s TLS %s cert issuer %s [%s] subject %s [%s]"
                       % (peer, "CA" if x.is_CA() else "EE", x.getIssuer(), x.hAKI(), x.getSubject(), x.hSKI()))
        if self.pem_dump_tls_certs:
          print x.get_PEM()

      if x.is_CA():
        if self.refuse_tls_ca_certs:
          raise rpki.exceptions.ReceivedTLSCACert
        continue

      if ee is not None:
        raise rpki.exceptions.MultipleTLSEECert, chain
      ee = x

    result = self.x509store_thunk().verifyDetailed(ee.get_POW())
    if not result[0]:
      rpki.log.debug("TLS certificate validation result %s" % repr(result))
      if disable_tls_certificate_validation_exceptions:
        rpki.log.warn("DANGER WILL ROBINSON!  IGNORING TLS VALIDATION FAILURE!")
      else:
        raise rpki.exceptions.TLSValidationError

class httpsClient(tlslite.api.HTTPTLSConnection):
  """Derived class to let us replace the default Checker."""

  def __init__(self, host, port = None,
               client_cert = None, client_key = None,
               server_ta = None, settings = None):
    """Create a new httpsClient."""

    tlslite.api.HTTPTLSConnection.__init__(
      self, host = host, port = port, settings = settings,
      certChain = client_cert, privateKey = client_key)

    self.checker = Checker(trust_anchor = server_ta)

def client(msg, client_key, client_cert, server_ta, url, timeout = 300, callback = None):
  """Open client HTTPS connection, send a message, wait for response.

  This function wraps most of what one needs to do to send a message
  over HTTPS and get a response.  The certificate checking isn't quite
  up to snuff; it's better than with the other packages I've found,
  but doesn't appear to handle subjectAltName extensions (sigh).
  """

  # This is an easy way to find synchronous calls that need conversion
  if trace_synchronous_calls and callback is None:
    raise RuntimeError, "Syncronous call to rpki.http.client()"

  u = urlparse.urlparse(url)

  assert u.scheme in ("", "https") and \
         u.username is None and \
         u.password is None and \
         u.params   == "" and \
         u.query    == "" and \
         u.fragment == ""

  rpki.log.debug("Contacting %s" % url)

  if debug_tls_certs:
    for cert in (client_cert,) if isinstance(client_cert, rpki.x509.X509) else client_cert:
      rpki.log.debug("Sending client TLS cert issuer %s subject %s" % (cert.getIssuer(), cert.getSubject()))

  # We could add a "settings = foo" argument to the following call to
  # pass in a tlslite.HandshakeSettings object that would let us
  # insist on, eg, particular SSL/TLS versions.

  httpc = httpsClient(host         = u.hostname or "localhost",
                      port         = u.port or 443,
                      client_key   = client_key.get_tlslite(),
                      client_cert  = tlslite_certChain(client_cert),
                      server_ta    = server_ta)
  httpc.connect()
  httpc.sock.settimeout(timeout)
  httpc.request("POST", u.path, msg, {"Content-Type" : rpki_content_type})
  response = httpc.getresponse()
  rpki.log.debug("HTTPS client returned")
  r = response.read()
  if response.status != httplib.OK:
    rpki.log.debug("HTTPS client returned failure")
    r = rpki.exceptions.HTTPRequestFailed("HTTP request failed with status %s, response %s" % (response.status, r))
  if callback is not None:
    rpki.log.debug("HTTPS client callback supplied, using it")
    callback(r)
  elif response.status == httplib.OK:
    rpki.log.debug("HTTPS no client callback, returning success")
    return r
  else:
    rpki.log.debug("HTTPS no client callback, raising exception")
    raise r

class requestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
  """Derived type to supply POST handler and override logging."""

  rpki_handlers = None                  # Subclass must bind

  def rpki_find_handler(self):
    """Helper method to search self.rpki_handlers."""
    for s,h in self.rpki_handlers:
      if self.path.startswith(s):
        return h
    return None

  def do_POST(self):
    """POST handler."""
    try:
      handler = self.rpki_find_handler()
      if self.headers["Content-Type"] != rpki_content_type:
        result = 415, "No handler for Content-Type %s" % self.headers["Content-Type"]
      elif handler is None:
        result = 404, "No handler found for URL " + self.path
      else:
        self.called_back = False
        result = handler(query = self.rfile.read(int(self.headers["Content-Length"])),
                         path  = self.path,
                         cb    = self.do_POST_cb)
        assert result is not None or self.called_back, "Missing HTTPS server callback from %s" % repr(handler)
    except Exception, edata:
      rpki.log.error(traceback.format_exc())
      result = 500, "Unhandled exception %s" % edata
    if result is not None:
      self.do_POST_cb(result[0], result[1])

  def do_POST_cb(self, rcode, rtext):
    """Send result back to client."""
    rpki.log.info("HTTPS server callback")
    self.called_back = True
    self.send_response(rcode)
    self.send_header("Content-Type", rpki_content_type)
    self.end_headers()
    self.wfile.write(rtext)

  def log_message(self, format, *args):
    """Redirect HTTP server logging into our own logging system."""
    if args:
      rpki.log.info(format % args)
    else:
      rpki.log.info(format)

class httpsServer(tlslite.api.TLSSocketServerMixIn, BaseHTTPServer.HTTPServer):
  """Derived type to handle TLS aspects of HTTPS."""

  rpki_sessionCache = None
  rpki_server_key   = None
  rpki_server_cert  = None
  rpki_checker      = None
  
  def handshake(self, tlsConnection):
    """TLS handshake handler."""
    assert self.rpki_server_cert  is not None
    assert self.rpki_server_key   is not None
    assert self.rpki_sessionCache is not None

    try:
      #
      # We could add a "settings = foo" argument to the following call
      # to pass in a tlslite.HandshakeSettings object that would let
      # us insist on, eg, particular SSL/TLS versions.
      #
      tlsConnection.handshakeServer(certChain    = self.rpki_server_cert,
                                    privateKey   = self.rpki_server_key,
                                    sessionCache = self.rpki_sessionCache,
                                    checker      = self.rpki_checker,
                                    reqCert      = True)
      tlsConnection.ignoreAbruptClose = True
      return True
    except (tlslite.api.TLSError, rpki.exceptions.TLSValidationError), error:
      rpki.log.warn("TLS handshake failure: " + str(error))
      return False

  def handle_error(self, request, client_address):
    """Override SOcketServer error handling.  This may be wrong in the
    long run, but at the moment I'm seeing the server hang while
    trying to shut down, because the default handler is intercepting
    ServerShuttingDown in certain states, for reasons unknown.
    """

    raise

def server(handlers, server_key, server_cert, port = 4433, host ="", client_ta = None, dynamic_https_trust_anchor = None, catch_signals = (signal.SIGINT, signal.SIGTERM)):
  """Run an HTTPS server and wait (forever) for connections."""

  if not isinstance(handlers, (tuple, list)):
    handlers = (("/", handlers),)

  class boundRequestHandler(requestHandler):
    rpki_handlers = handlers

  httpd = httpsServer((host, port), boundRequestHandler)

  httpd.rpki_server_key   = server_key.get_tlslite()
  httpd.rpki_server_cert  = tlslite_certChain(server_cert)
  httpd.rpki_sessionCache = tlslite.api.SessionCache()
  httpd.rpki_checker      = Checker(trust_anchor = client_ta, dynamic_https_trust_anchor = dynamic_https_trust_anchor)

  try:
    def raiseServerShuttingDown(signum, frame):
      raise rpki.exceptions.ServerShuttingDown
    old_signal_handlers = tuple((sig, signal.signal(sig, raiseServerShuttingDown)) for sig in catch_signals)
    httpd.serve_forever()
  except rpki.exceptions.ServerShuttingDown:
    pass
  finally:
    for sig,handler in old_signal_handlers:
      signal.signal(sig, handler)
