# $Id$

import socket, POW, time

s = socket.socket()
s.connect(('',6666))

ssl = POW.Ssl(POW.TLSV1_CLIENT_METHOD)
ssl.setFd(s.fileno())
ssl.connect()

print ssl.read(100)
ssl.write("Bye")
