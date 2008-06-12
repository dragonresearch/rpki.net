"""
Script to generate rpki/relaxng.py.

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

print "# Automatically generated, do not edit."
print
print "import lxml.etree"

for varname, filename in (("left_right",  "left-right-schema.rng"),
                          ("up_down",     "up-down-schema.rng"),
                          ("publication", "publication-schema.rng")):
  f = open(filename)
  print "\n## @var %s\n## Parsed RelaxNG %s schema\n%s = lxml.etree.RelaxNG(lxml.etree.fromstring('''%s'''))" % (varname, varname, varname, f.read())
  f.close()
