#!/usr/bin/env python
# $Id$

# Copyright (C) 2013  Internet Systems Consortium ("ISC")
# 
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

# Kludge to extract Subversion revision number from environment at
# build time, if possible, using it to construct the software version
# number that one of our users so desperately wants us to have.  This
# is a bit tricky because we want this to be automatic (hence use of
# Subversion revision number, which isn't really intended for this
# purpose), want it to work whether installing from binary package or
# subversion checkout or frozen tarball, and need to be careful both
# to update it whenever the revision changes and not to stomp on it
# when the subversion revision number isn't available.
#
# I did say this was a kludge.

import subprocess

try:
  v = subprocess.Popen(("svnversion", "-c"), stdout = subprocess.PIPE).communicate()[0]
except:
  v = "Unknown"

if any(s in v for s in ("Unversioned", "Uncommitted", "Unknown")):
  v = "Unknown"
else:
  v = "0." + v.strip().split(":")[-1].translate(None, "SMP")

try:
  old = open("VERSION", "r").read().strip()
except:
  old = None

if old is None or v != old:
  with open("VERSION", "w") as f:
    f.write(v + "\n")
  with open("rpkid/rpki/version.py", "w") as f:
    f.write("VERSION = \"%s\"\n" % v)
