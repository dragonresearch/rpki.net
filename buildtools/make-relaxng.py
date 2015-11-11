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
Script to generate rpki/relaxng.py.
"""

import sys

header = """\
# Automatically generated, do not edit.

# pylint: skip-file

from rpki.relaxng_parser import RelaxNGParser
"""

format = """
## @var %(name)s
## Parsed RelaxNG %(name)s schema
%(name)s = RelaxNGParser(r'''%(rng)s''')
"""

footer = """
del RelaxNGParser
"""

def symbol(s):
    for suffix in (".rng", "-schema"):
        if s.endswith(suffix):
            s = s[:-len(suffix)]
    return s.replace("-", "_")

sys.stdout.write(header)
for fn in sys.argv[1:]:
    with open(fn, "r") as f:
        sys.stdout.write(format % dict(name = symbol(fn), rng = f.read()))
sys.stdout.write(footer)
