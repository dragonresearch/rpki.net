"""
Grope towards testing TLS functionality in POW

$Id$

Copyright (C) 2008  American Registry for Internet Numbers ("ARIN")

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

# openssl s_server -tls1 -Verify 9 -cert biz-certs/Alice-EE.cer -key biz-certs/Alice-EE.key -www -CApath biz-certs -chain

# openssl s_client -connect localhost:4433 -tls1 -cert biz-certs/Bob-EE.cer -key biz-certs/Bob-EE.key -verify 9 -CApath biz-certs -crlf

import POW, socket

def pow_error_iterator():
  err = POW.getError()
  if err is None:
    raise StopIteration
  else:
    yield err

key = POW.pemRead(POW.RSA_PRIVATE_KEY,  open("biz-certs/Bob-EE.key").read())
cer = POW.pemRead(POW.X509_CERTIFICATE, open("biz-certs/Bob-EE.cer").read())
ca  = POW.pemRead(POW.X509_CERTIFICATE, open("biz-certs/Bob-CA.cer").read())

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("localhost", 4433))

try:
  t = POW.Ssl(POW.TLSV1_CLIENT_METHOD)
  t.useCertificate(cer)
  t.useKey(key)
  t.addCertificate(ca)
  t.setFd(s.fileno())
  t.connect()
  x = t.peerCertificate()
  if x is not None:
    print "Peer", x.pprint()
  t.write("GET / HTTP/1.0\r\n")
  if False:
    print t.read(10000)
  else:
    while True:
      print t.read()
except:
  print "ERROR:"
  for e in pow_error_iterator():
    print e
  raise
