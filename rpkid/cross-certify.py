"""
Cross-certification tool to issue a new certificate based on an old
one that was issued by somebody else.  The point of the exercise is to
end up with a valid certificate in our own BPKI which has the same
subject name and subject public key as the one we're replacing.

Much of this code lifted from rpki.x509.X509.issue(), but this is a
sufficiently different purpose that it's probably not worth
refactoring.

Usage: python cross-certify.py { -i | --in     } input_cert
                               { -c | --ca     } issuing_cert
                               { -k | --key    } issuing_cert_key
                               { -s | --serial } serial_filename
                               [ { -h | --help } ]
                               [ { -o | --out  }     filename  (default: stdout)  ]
                               [ { -l | --lifetime } timedelta (default: 30 days) ]

$Id$

Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")

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

import os, time, getopt, sys, POW
import rpki.x509, rpki.sundial

os.environ["TZ"] = "UTC"
time.tzset()

def usage(code):
  print __doc__
  sys.exit(code)

output = None
lifetime = rpki.sundial.timedelta(days = 30)

opts,argv = getopt.getopt(sys.argv[1:], "h?i:o:c:k:s:l:",
                          ["help", "in=", "out=", "ca=", "key=", "serial=", "lifetime="])
for o,a in opts:
  if o in ("-h", "--help", "-?"):
    usage(0)
  elif o in ("-i", "--in"):
    child = rpki.x509.X509(Auto_file = a)
  elif o in ("-o", "--out"):
    output = a
  elif o in ("-c", "--ca"):
    parent = rpki.x509.X509(Auto_file = a)
  elif o in ("-k", "--key"):
    keypair = rpki.x509.RSA(Auto_file = a)
  elif o in ("-s", "--serial"):
    serial_file = a
  elif o in ("-l", "--lifetime"):
    lifetime = rpki.sundial.timedelta.parse(a)
if argv:
  usage(1)

now = rpki.sundial.now()
notAfter = now + lifetime

try:
  f = open(serial_file, "r")
  serial = f.read()
  f.close()
  serial = int(serial.splitlines()[0], 16)
except IOError:
  serial = 1

x = POW.pkix.Certificate()
x.setVersion(2)
x.setSerial(serial)
x.setIssuer(parent.get_POWpkix().getSubject())
x.setSubject(child.get_POWpkix().getSubject())
x.setNotBefore(now.toASN1tuple())
x.setNotAfter(notAfter.toASN1tuple())
x.tbs.subjectPublicKeyInfo.set(child.get_POWpkix().tbs.subjectPublicKeyInfo.get())
x.setExtensions(((rpki.oids.name2oid["subjectKeyIdentifier"], False,
                     child.get_SKI()),
                    (rpki.oids.name2oid["authorityKeyIdentifier"], False,
                     (parent.get_SKI(), (), None)),
                    (rpki.oids.name2oid["basicConstraints"], True,
                     (1, 0))))
x.sign(keypair.get_POW(), POW.SHA256_DIGEST)

cert = rpki.x509.X509(POWpkix = x)

f = open(serial_file, "w")
f.write("%02x\n" % (serial + 1))
f.close()

if output is None:
  print cert.get_PEM()
else:
  f = open(output, "w")
  f.write(cert.get_PEM())
  f.close()

