# $Id$

import BaseHTTPServer, tlslite.api

class requestHandler(BaseHTTPServer.BaseHTTPRequestHandler):

  def do_POST(self):
    echo = ""
    for h in self.headers:
      echo += "%s: %s\n" % (h, self.headers[h])
    self.query_string = self.rfile.read(int(self.headers["Content-Length"]))
    echo += self.query_string

    if False:
      f = open("http-server.log", "a")
      f.write(echo)
      f.close()

    self.send_response(200)
    self.send_header("Content-Type", "application/x-wombat")
    self.end_headers()

    self.wfile.write(echo)

class httpServer(tlslite.api.TLSSocketServerMixIn, BaseHTTPServer.HTTPServer):

  def handshake(self, tlsConnection):
    try:
      tlsConnection.handshakeServer(certChain=certChain,
                                    privateKey=privateKey,
                                    sessionCache=sessionCache)
      tlsConnection.ignoreAbruptClose = True
      return True
    except tlslite.api.TLSError, error:
      print "TLS handshake failure:", str(error)
      return False
    
f = open("biz-certs/Carol-EE.cer", "r")
x509 = tlslite.api.X509()
x509.parse(f.read())
f.close()

certChain = tlslite.api.X509CertChain([x509])

f = open("biz-certs/Carol-EE.key", "r")
privateKey = tlslite.api.parsePEMKey(f.read(), private=True)
f.close()

sessionCache = tlslite.api.SessionCache()

httpd = httpServer(("", 8080), requestHandler)
httpd.serve_forever()
