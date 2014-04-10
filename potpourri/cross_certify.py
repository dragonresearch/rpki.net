# $Id$
# 
# Copyright (C) 2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2009--2012  Internet Systems Consortium ("ISC")
# Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
# 
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL, ISC, AND ARIN DISCLAIM ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL DRL,
# ISC, OR ARIN BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
# OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
Cross-certification tool to issue a new certificate based on an old
one that was issued by somebody else.  The point of the exercise is to
end up with a valid certificate in our own BPKI which has the same
subject name and subject public key as the one we're replacing.
"""

import os
import sys
import time
import argparse
import rpki.x509
import rpki.sundial

os.environ["TZ"] = "UTC"
time.tzset()

parser = argparse.ArgumentParser(description = __doc__)
parser.add_argument("-i", "--in", required = True, dest = "input",
                    type = lambda s: rpki.x509.X509(Auto_file = s),
                    help = "input certificate")
parser.add_argument("-c", "--ca", required = True,
                    type = lambda s: rpki.x509.X509(Auto_file = s),
                    help = "issuing certificate")
parser.add_argument("-k", "--key", required = True,
                    type = lambda s: rpki.x509.RSA(Auto_file = s),
                    help = "private key of issuing certificate")
parser.add_argument("-s", "--serial", required = True,
                    help = "serial number file")
parser.add_argument("-o", "--out",
                    help = "output filename")
parser.add_argument("-l", "--lifetime",
                    type = rpki.sundial.timedelta, default = "30d",
                    help = "lifetime of generated certificate")
args = parser.parse_args()

now = rpki.sundial.now()
notAfter = now + args.lifetime

try:
  with open(args.serial, "r") as f:
    serial = int(f.read().splitlines()[0], 16)
except IOError:
  serial = 1

cert = args.ca.cross_certify(args.key, args.input, serial, notAfter, now)

with open(args.serial, "w") as f:
  f.write("%02x\n" % (serial + 1))

if args.out is None:
  sys.stdout.write(cert.get_PEM())
else:
  with open(args.out, "w") as f:
    f.write(cert.get_PEM())
