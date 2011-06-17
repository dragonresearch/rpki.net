"""
Convert a Python script into an executable Python script.  Mostly this
means constructing a header based on a few parameters supplied by
autoconf.

$Id$

Copyright (C) 2011  Internet Systems Consortium ("ISC")

Permission to use, copy, modify, and distribute this software for any
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

# Some scripts need this, and it must be first executable statement
from __future__ import with_statement

import os, sys

sys.stdout.write('''\
#!%(AC_PYTHON_INTERPRETER)s
# Automatically constructed script header

# Set location of global rpki.conf file
if __name__ == "__main__":
  import rpki.config
  rpki.config.default_dirname = "%(AC_RPKI_CONFIG_DIR)s"

# Original script starts here

''' % os.environ)

sys.stdout.write(sys.stdin.read())
