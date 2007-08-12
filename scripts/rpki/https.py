# $Id$

import httplib, BaseHTTPServer, tlslite.api, glob, rpki.x509

"""HTTPS utilities, both client and server.

At the moment this only knows how to use the PEM certs in my
subversion repository; generalizing it would not be hard, but the more
general version should use SQL anyway.
"""

rpki_content_type = "application/x-rpki"

class CertInfo(object):
  """Certificate context.

  This hides a bunch of grotty details about how we store and name
  certificates in this test setup.  This code will definitely need to
  change, soon, but this class keeps most of this rubbish in one
  place.
  """

  cert_dir = "biz-certs/"

  def __init__(self, myname=None):
    if myname is not None:

      f = open(self.cert_dir + myname + "-EE.key", "r")
      self.privateKey = tlslite.api.parsePEMKey(f.read(), private=True)
      f.close()
      
      chain = rpki.x509.X509_chain()
      chain.load_from_PEM(glob.glob(self.cert_dir + myname + "-*.cer"))
      chain.chainsort()
      self.certChain = chain.tlslite_certChain()

      trustlist = rpki.x509.X509_chain()
      trustlist.load_from_PEM(glob.glob(self.cert_dir + "*-Root.cer"))
      self.x509TrustList = trustlist.tlslite_trustList()

def client(msg, certInfo, host="localhost", port=4433, url="/"):
  """Open client HTTPS connection, send a message, wait for response.

  This function wraps most of what one needs to do to send a message
  over HTTPS and get a response.  The certificate checking isn't quite
  up to snuff; it's better than with the other packages I've found,
  but doesn't appear to handle subjectAltName extensions (sigh).
  """
  
  httpc = tlslite.api.HTTPTLSConnection(host=host,
                                        port=port,
                                        certChain=certInfo.certChain,
                                        privateKey=certInfo.privateKey,
                                        x509TrustList=certInfo.x509TrustList)
  httpc.connect()
  httpc.request("POST", url, msg, {"Content-Type" : rpki_content_type})
  response = httpc.getresponse()
  assert response.status == httplib.OK
  return response.read()

class requestHandler(BaseHTTPServer.BaseHTTPRequestHandler):
  """Derived type to supply POST handler."""

  rpki_handlers = None                  # Subclass must bind

  def do_POST(self):
    """POST handler."""
    assert self.headers["Content-Type"] == rpki_content_type
    query_string = self.rfile.read(int(self.headers["Content-Length"]))
    rcode = None
    try:
      handler = self.rpki_handlers[self.path]
    except KeyError:
      rcode, rtext = 404, ""
    if rcode is None:
      try:
        rcode, rtext = handler(query=query_string, path=self.path)
      except:
        rcode, rtext = 500, ""
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

def server(handlers, certInfo, port=4433, host=""):
  """Run an HTTPS server and wait (forever) for connections."""

  class boundRequestHandler(requestHandler):
    rpki_handlers = handlers

  httpd = httpServer((host, port), boundRequestHandler)
  httpd.rpki_privateKey = certInfo.privateKey
  httpd.rpki_certChain = certInfo.certChain
  httpd.rpki_sessionCache = tlslite.api.SessionCache()

  httpd.serve_forever()
