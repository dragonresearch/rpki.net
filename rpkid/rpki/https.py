# $Id$

# Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""HTTPS utilities, both client and server.

At the moment this only knows how to use the PEM certs in my
subversion repository; generalizing it would not be hard, but the more
general version should use SQL anyway.
"""

import httplib, BaseHTTPServer, tlslite.api, glob, traceback, urlparse, socket
import rpki.x509, rpki.exceptions, rpki.log

rpki_content_type = "application/x-rpki"

class Checker(tlslite.api.Checker):
  """Derived class to handle X.509 client certificate checking."""

  x509TrustList = None

  def __init__(self, x509TrustList = None):
    """Initialize our modified checker."""

    if False:
      self.x509TrustList = x509TrustList
    else:
      rpki.log.debug("Ignoring HTTPS trust anchors %s, validation disabled" % repr(x509TrustList))

  def __call__(self, tlsConnection):
    """Wrap some logging code around standard tlslite.Checker class.

    This is probably also the place where we need to figure out which
    trust anchor to use, since this is the first point at which we
    have access to the certificate chain provided by the client.
    """

    for i in range(tlsConnection.session.clientCertChain.getNumCerts()):
      x = rpki.x509.X509(tlslite = tlsConnection.session.clientCertChain.x509List[i])
      rpki.log.debug("Received cert[%d] %s" % (i, x.getSubject()))

    # Disabling this removes the need for cryptlib_py
    if self.x509TrustList is not None:
      tlslite.api.Checker.__call__(self, tlsConnection)

class httpsClient(tlslite.api.HTTPTLSConnection):
  """Derived class to let us replace the default Checker."""

  def __init__(self, host, port = None,
               certChain = None, privateKey = None,
               x509TrustList = None, settings = None):
    """Create a new httpsClient."""

    tlslite.api.HTTPTLSConnection.__init__(
      self, host = host, port = port, settings = settings,
      certChain = certChain, privateKey = privateKey)

    self.checker = Checker(x509TrustList = x509TrustList)

def client(msg, privateKey, certChain, x509TrustList, url, timeout = 300):
  """Open client HTTPS connection, send a message, wait for response.

  This function wraps most of what one needs to do to send a message
  over HTTPS and get a response.  The certificate checking isn't quite
  up to snuff; it's better than with the other packages I've found,
  but doesn't appear to handle subjectAltName extensions (sigh).
  """
  
  u = urlparse.urlparse(url)

  assert u.scheme in ("", "https") and \
         u.username is None and \
         u.password is None and \
         u.params   == "" and \
         u.query    == "" and \
         u.fragment == ""

  # We could add a "settings = foo" argument to the following call to
  # pass in a tlslite.HandshakeSettings object that would let us
  # insist on, eg, particular SSL/TLS versions.

  httpc = httpsClient(host          = u.hostname or "localhost",
                      port          = u.port or 443,
                      privateKey    = privateKey.get_tlslite(),
                      certChain     = certChain.tlslite_certChain(),
                      x509TrustList = x509TrustList.tlslite_trustList())
  httpc.connect()
  httpc.sock.settimeout(timeout)
  httpc.request("POST", u.path, msg, {"Content-Type" : rpki_content_type})
  response = httpc.getresponse()
  if response.status == httplib.OK:
    return response.read()
  else:
    r = response.read()
    raise rpki.exceptions.HTTPRequestFailed, \
          "HTTP request failed with status %s, response %s" % (response.status, r)

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
        rcode, rtext = 415, "Received Content-Type %s, expected %s" \
                       % (self.headers["Content-Type"], rpki_content_type)
      elif handler is None:
        rcode, rtext = 404, "No handler found for URL " + self.path
      else:
        rcode, rtext = handler(query = self.rfile.read(int(self.headers["Content-Length"])),
                               path  = self.path)
    except Exception, edata:
      rpki.log.error(traceback.format_exc())
      rcode, rtext = 500, "Unhandled exception %s" % edata
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
  rpki_privateKey   = None
  rpki_certChain    = None
  rpki_checker      = None
  
  def handshake(self, tlsConnection):
    """TLS handshake handler."""
    assert self.rpki_certChain    is not None
    assert self.rpki_privateKey   is not None
    assert self.rpki_sessionCache is not None
    try:
      #
      # We could add a "settings = foo" argument to the following call
      # to pass in a tlslite.HandshakeSettings object that would let
      # us insist on, eg, particular SSL/TLS versions.
      #
      tlsConnection.handshakeServer(certChain    = self.rpki_certChain,
                                    privateKey   = self.rpki_privateKey,
                                    sessionCache = self.rpki_sessionCache,
                                    checker      = self.rpki_checker,
                                    reqCert      = self.rpki_checker is not None)
      tlsConnection.ignoreAbruptClose = True
      return True
    except tlslite.api.TLSError, error:
      rpki.log.warn("TLS handshake failure: " + str(error))
      return False

def server(handlers, privateKey, certChain, port = 4433, host = "", x509TrustList = None):
  """Run an HTTPS server and wait (forever) for connections."""

  if not isinstance(handlers, (tuple, list)):
    handlers = (("/", handlers),)

  class boundRequestHandler(requestHandler):
    rpki_handlers = handlers

  httpd = httpsServer((host, port), boundRequestHandler)

  httpd.rpki_privateKey = privateKey.get_tlslite()
  httpd.rpki_certChain = certChain.tlslite_certChain()
  httpd.rpki_sessionCache = tlslite.api.SessionCache()

  if x509TrustList is not None:
    x509TrustList = x509TrustList.tlslite_trustList()
    for x in x509TrustList:
      rpki.log.debug("HTTPS trust anchor %s" % rpki.x509.X509(tlslite = x).getSubject())

    httpd.rpki_checker = Checker(x509TrustList = x509TrustList)

  httpd.serve_forever()
