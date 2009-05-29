# $Id$

import socket, POW, time

key = POW.pemRead(POW.RSA_PRIVATE_KEY, open("Alice.key", "r").read())
cer = POW.pemRead(POW.X509_CERTIFICATE, open("Alice.cer", "r").read())

listener = socket.socket()
listener.bind(('',6666))
listener.listen(5)

s, addr = listener.accept()
while not s:
  time.sleep(2)
  s, addr = listener.accept()

print "Got connection %r from %r" % (s, addr)

ssl = POW.Ssl(POW.TLSV1_SERVER_METHOD)

ssl.useCertificate(cer)
ssl.useKey(key)

ssl.setFd(s.fileno())
ssl.accept()

# POW.SSLError: ('SSL routines', 'SSL3_GET_CLIENT_HELLO', 'no shared cipher', 336109761, 's3_srvr.c', 1135)

ssl.write("Hello, TLS")
print ssl.read(100)
