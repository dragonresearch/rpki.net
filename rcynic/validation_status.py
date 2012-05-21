"""
Flat text listing of <validation_status/> elements from rcynic.xml.

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

try:
  from lxml.etree            import ElementTree
except ImportError:
  from xml.etree.ElementTree import ElementTree

for filename in ([sys.stdin] if len(sys.argv) < 2 else sys.argv[1:]):
  for elt in ElementTree(file = filename).findall("validation_status"):
    print "%s %8s %-40s %s" % (
      elt.get("timestamp"),
      elt.get("generation"),
      elt.get("status"),
      elt.text.strip())
