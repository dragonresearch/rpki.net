# $Id$

import socket, POW, time

key = POW.pemRead(POW.RSA_PRIVATE_KEY, open("Alice.key", "r").read())
cer = POW.pemRead(POW.X509_CERTIFICATE, open("Alice.cer", "r").read())
ta  = POW.pemRead(POW.X509_CERTIFICATE, open("Carol-TA.cer", "r").read())

listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
listener.bind(('',6666))
listener.listen(5)

s, addr = listener.accept()
while not s:
  time.sleep(2)
  s, addr = listener.accept()

s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

print "Got connection %r from %r" % (s, addr)

ssl = POW.Ssl(POW.TLSV1_SERVER_METHOD)

ssl.useCertificate(cer)
ssl.useKey(key)
ssl.setVerifyMode(POW.SSL_VERIFY_PEER | POW.SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
ssl.trustCertificate(ta)

ssl.setFd(s.fileno())
ssl.accept()

peer = ssl.peerCertificate()
if peer is not None:
  print peer.pprint()

ssl.write("Hello, TLS")
print ssl.read(100)
