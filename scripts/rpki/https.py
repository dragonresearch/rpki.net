# $Id$

"""HTTPS utilities, both client and server.

At the moment this only knows how to use the PEM certs in my
subversion repository; generalizing it would not be hard, but the more
general version should use SQL anyway.
"""

import httplib, BaseHTTPServer, tlslite.api, glob, rpki.x509

rpki_content_type = "application/x-rpki"

def client(msg, privateKey, certChain, x509TrustList, host="localhost", port=4433, url="/"):
  """Open client HTTPS connection, send a message, wait for response.

  This function wraps most of what one needs to do to send a message
  over HTTPS and get a response.  The certificate checking isn't quite
  up to snuff; it's better than with the other packages I've found,
  but doesn't appear to handle subjectAltName extensions (sigh).
  """
  
  httpc = tlslite.api.HTTPTLSConnection(host=host,
                                        port=port,
                                        privateKey=privateKey.get_tlslite(),
                                        certChain=certChain.tlslite_certChain(),
                                        x509TrustList=x509TrustList.tlslite_trustList())
  httpc.connect()
  httpc.request("POST", url, msg, {"Content-Type" : rpki_content_type})
  response = httpc.getresponse()
  if response.status == httplib.OK:
    return response.read()
  else:
    r = response.read()
    print "ERROR: Got:", response.status, r
    raise RuntimeError, (response.status, r)

class requestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
  """Derived type to supply POST handler."""

  rpki_handlers = None                  # Subclass must bind

  def do_POST(self):
    """POST handler."""
    assert self.headers["Content-Type"] == rpki_content_type
    query_string = self.rfile.read(int(self.headers["Content-Length"]))
    handler = None
    for s,h in self.rpki_handlers:
      if self.path.startswith(s):
        handler = h
        break
    if handler is None:
      rcode, rtext = 404, "No handler found for URL " + self.path
    else:
      try:
        rcode, rtext = handler(query=query_string, path=self.path)
      except Exception, edata:
        rcode, rtext = 500, "Unhandled exception %s" % edata
    self.send_response(rcode)
    self.send_header("Content-Type", rpki_content_type)
    self.end_headers()
    self.wfile.write(rtext)

class httpServer(tlslite.api.TLSSocketServerMixIn, BaseHTTPServer.HTTPServer):
  """Derived type to handle TLS aspects of HTTPS."""

  rpki_certChain = None
  rpki_privateKey = None
  rpki_sessionCache = None
  
  def handshake(self, tlsConnection):
    """TLS handshake handler."""
    assert self.rpki_certChain is not None
    assert self.rpki_privateKey is not None
    assert self.rpki_sessionCache is not None
    try:
      tlsConnection.handshakeServer(certChain=self.rpki_certChain,
                                    privateKey=self.rpki_privateKey,
                                    sessionCache=self.rpki_sessionCache)
      tlsConnection.ignoreAbruptClose = True
      return True
    except tlslite.api.TLSError, error:
      print "TLS handshake failure:", str(error)
      return False

def server(handlers, privateKey, certChain, port=4433, host=""):
  """Run an HTTPS server and wait (forever) for connections."""

  if not isinstance(handlers, (tuple, list)):
    handlers = (("/", handlers),)

  class boundRequestHandler(requestHandler):
    rpki_handlers = handlers

  httpd = httpServer((host, port), boundRequestHandler)

  httpd.rpki_privateKey = privateKey.get_tlslite()
  httpd.rpki_certChain = certChain.tlslite_certChain()
  httpd.rpki_sessionCache = tlslite.api.SessionCache()

  httpd.serve_forever()
