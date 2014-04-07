#!/usr/bin/env python
# $Id$
# 
# Copyright (C) 2014 Dragon Research Labs ("DRL")
# 
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL DRL BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
Scan rcynic validated output looking for router certificates, print
out stuff that the rpki-rtr code cares about.
"""

# This program represents a weird temporary state, mostly to avoid
# diving into a recursive yak shaving exercise.
#
# Under the old scheme, anything used by the RP code should be either
# C code or pure Python code using just the standard libraries.  This
# has gotten silly, but we haven't yet refactored the current packaged
# builds from two packages into three (adding a -libs package).
#
# So, by rights, this program should be a C monstrosity written using
# the OpenSSL C API.  I started coding it that way, but it was just
# too painful for something we're probably going to rewrite as a few
# lines of Python once we refactor, but by the same token I didn't
# want to delay router certificate support until the refactoring.
#
# So this program anticipates the new scheme of things, but makes one
# concession to current reality: if it has a problem importing the
# RPKI-specific libraries, it just quietly exits as if everything were
# fine and there simply are no router certificates to report.  This
# isn't the right answer in the long run, but will suffice to avoid
# further bald yaks.

import os
import sys
import base64

try:
  import rpki.POW
  import rpki.oids
except ImportError:
  sys.exit(0)

rcynic_dir = sys.argv[1]

for root, dirs, files in os.walk(rcynic_dir):
  for fn in files:
    if not fn.endswith(".cer"):
      continue
    x = rpki.POW.X509.derReadFile(os.path.join(root, fn))

    if rpki.oids.id_kp_bgpsec_router not in (x.getEKU() or ()):
      continue

    sys.stdout.write(base64.urlsafe_b64encode(x.getSKI()).rstrip("="))
    for min_asn, max_asn in x.getRFC3779()[0]:
      for asn in xrange(min_asn, max_asn + 1):
        sys.stdout.write(" %s" % asn)
    sys.stdout.write(" %s\n" % base64.b64encode(x.getPublicKey().derWritePublic()))
