# $Id$

import httplib, BaseHTTPServer, tlslite.api, glob

"""
HTTPS utilities, both client and server.

At the moment this only knows how to use the PEM certs in my
subversion repository; generalizing it would not be hard, but the more
general version should use SQL anyway.
"""

rpki_content_type = "application/x-rpki"

class CertInfo(object):

  cert_dir = "biz-certs/"

  def __init__(self, myname=None):

    if myname is not None:

      f = open(self.cert_dir + myname + "-EE.key", "r")
      self.privateKey = tlslite.api.parsePEMKey(f.read(), private=True)
      f.close()

      chain = []
      for file in glob.glob(self.cert_dir + myname + "-*.cer"):
        f = open(file, "r")
        x509 = tlslite.api.X509()
        x509.parse(f.read())
        f.close()
        chain.append(x509)
      self.certChain = tlslite.api.X509CertChain(chain)

      self.x509TrustList = []
      for file in glob.glob(self.cert_dir + "*-Root.cer"):
        if file != self.cert_dir + myname + "-Root.cer":
          f = open(file, "r")
          x509 = tlslite.api.X509()
          x509.parse(f.read())
          f.close()
          self.x509TrustList.append(x509)

def client(msg, certInfo, host="localhost", port=4433, url="/"):
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

  rpki_handler = None                   # Subclass must bind

  def do_POST(self):
    assert self.headers["Content-Type"] == rpki_content_type
    self.query_string = self.rfile.read(int(self.headers["Content-Length"]))
    rcode, rtext = self.rpki_handler(self.query_string)
    self.send_response(rcode)
    self.send_header("Content-Type", rpki_content_type)
    self.end_headers()
    self.wfile.write(rtext)

class httpServer(tlslite.api.TLSSocketServerMixIn, BaseHTTPServer.HTTPServer):

  rpki_certChain = None
  rpki_privateKey = None
  rpki_sessionCache = None
  
  def handshake(self, tlsConnection):
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

def server(handler, certInfo, port=4433, host=""):

  # BaseHTTPServer.HTTPServer takes a class, not an instance, so
  # binding our handler requires creating a new subclass.  Weird.

  class boundRequestHandler(requestHandler):
    rpki_handler = handler

  httpd = httpServer((host, port), boundRequestHandler)
  httpd.rpki_privateKey = certInfo.privateKey
  httpd.rpki_certChain = certInfo.certChain
  httpd.rpki_sessionCache = tlslite.api.SessionCache()

  httpd.serve_forever()
