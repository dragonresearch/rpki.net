# $Id$

import socket, POW, time

key = POW.pemRead(POW.RSA_PRIVATE_KEY, open("Carol.key", "r").read())
cer = POW.pemRead(POW.X509_CERTIFICATE, open("Carol.cer", "r").read())
ta  = POW.pemRead(POW.X509_CERTIFICATE, open("Alice-TA.cer", "r").read())

s = socket.socket()
s.connect(('',6666))

ssl = POW.Ssl(POW.TLSV1_CLIENT_METHOD)

ssl.useCertificate(cer)
ssl.useKey(key)
ssl.setVerifyMode(POW.SSL_VERIFY_PEER | POW.SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
ssl.trustCertificate(ta)

ssl.setFd(s.fileno())
ssl.connect()

print ssl.read(100)
ssl.write("Bye")
