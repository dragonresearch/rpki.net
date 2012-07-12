"""
Look for ROAs for particular prefixes, like find_roa, then, for each
ROA we find, dig out the expiration times of all the certificates
involved in the authorization chain, all the way back to the root.

$Id$

Copyright (C) 2012 Internet Systems Consortium, Inc. ("ISC")

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import sys
import subprocess
import rpki.POW

def filename_to_uri(filename):
  if not filename.startswith(sys.argv[1]):
    raise ValueError
  return "rsync://" + filename[len(sys.argv[1]):].lstrip("/")

def uri_to_filename(uri):
  if not uri.startswith("rsync://"):
    raise ValueError
  return sys.argv[1] + "/" + uri[len("rsync://"):]

def get_aia(x):
  for i in xrange(x.countExtensions()):
    ext = x.getExtension(i)
    if ext[0] == "authorityInfoAccess":
      return ext[2][ext[2].index("rsync://"):]
  return None

for line in subprocess.check_output(["find_roa"] + sys.argv[1:]).splitlines():

  words = line.split()
  fn = words.pop()
  del words[-1]
  print " ".join(words)

  x = rpki.POW.derRead(rpki.POW.CMS_MESSAGE, open(fn, "rb").read()).certs()[0]
  uri = get_aia(x)
  print x.getNotAfter(), filename_to_uri(fn)

  while uri:
    fn = uri_to_filename(uri)
    x = rpki.POW.derRead(rpki.POW.X509_CERTIFICATE, open(fn, "rb").read())
    print x.getNotAfter(), uri
    uri = get_aia(x)

  print
