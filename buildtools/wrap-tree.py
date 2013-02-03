"""
Package a directory tree inside a Python script.  This is mostly
useful when generating templates for small trees of files one wants to
generate automatically with some customizations (eg, the skeleton for
some the packaging files needed by some platform or another).

$Id$

Copyright (C) 2013 Internet Systems Consortium, Inc. ("ISC")

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

import os
import sys

result = {}

for root, dirs, files in os.walk("."):
  for dn in dirs:
    dn = os.path.relpath(os.path.join(root, dn))
    result[dn] = None
  for fn in files:
    fn = os.path.relpath(os.path.join(root, fn))
    with open(fn, "r") as f:
      result[fn] = f.read()

sys.stdout.write("# Automatically generated.  Hack if you like, but beware of overwriting.\n\nimport os\n")

for k in sorted(result):
  v = result[k]
  if v is None:
    sys.stdout.write("\nos.makedirs(%r)\n" % k)
  else:
    sys.stdout.write("\nwith open(%r, \"wb\") as f:\n" % k)
    lines = v.splitlines()
    if v.endswith("\n"):
      lines.append("")
    sys.stdout.write("  f.write('''\\\n")
    while lines:
      words = lines.pop(0).replace("\\", "\\\\").split("'''")
      sys.stdout.write(words[0])
      for word in words[1:]:
        sys.stdout.write("''' + \"'''\" + '''")
        sys.stdout.write(word)
      if not lines:
        sys.stdout.write("''')")
      sys.stdout.write("\n")
