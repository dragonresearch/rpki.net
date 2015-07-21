#!/usr/bin/env python
# $Id$
#
# Copyright (C) 2014  Dragon Research Labs ("DRL")
#
# Permission to use, copy, modify, and distribute this software for any
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
Fetch an RRDP notifcation file and follow all the links.  Should be
merged into rrdp-test-tool eventually, but one thing at a time.
"""

from urllib2            import urlopen
from lxml.etree         import ElementTree, XML
from socket             import getfqdn
from rpki.x509          import sha256
from rpki.relaxng       import rrdp
from urlparse           import urlparse
from argparse           import ArgumentParser, ArgumentDefaultsHelpFormatter

class BadHash(Exception):
  "Calculated hash value doesn't match expected hash value."

def fetch(elt):
  uri = elt.get("uri")
  hash = elt.get("hash").lower()
  print "Fetching", uri

  text = urlopen(uri).read()
  h = sha256(text).encode("hex")
  if h != hash:
    raise BadHash("Bad hash for %s: expected %s got %s" % (uri, hash, h))

  xml = XML(text)
  rrdp.schema.assertValid(xml)

  u = urlparse(uri)
  fn = u.netloc + u.path

  return elt, xml, fn

parser = ArgumentParser(description = __doc__, formatter_class = ArgumentDefaultsHelpFormatter)
parser.add_argument("uri", nargs = "?",
                    default = "http://" + getfqdn() + "/rrdp/updates.xml",
                    help = "RRDP notification file to fetch")
args = parser.parse_args()

updates = ElementTree(file = urlopen(args.uri))
rrdp.schema.assertValid(updates)

snapshot = fetch(updates.find(rrdp.xmlns + "snapshot"))

deltas = [fetch(elt) for elt in updates.findall(rrdp.xmlns + "delta")]

print updates
print snapshot
for delta in deltas:
  print delta
