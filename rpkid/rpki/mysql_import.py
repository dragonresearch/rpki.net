"""
Import wrapper for MySQLdb.

MySQLdb is an independent package, not part of Python, and has some
minor version skew issues with respect to Python itself, which we want
to suppress so that they don't annoy the user.  None of this is
particularly hard, but the maze of whacky incantations required to do
this in multiple version of Python on multiple platforms is somewhat
tedious, and turns out to cause other problems when combined with the
way we construct executable Python scripts containing a standard
header indicating the location of our config file.

So it turns out to be easier just to put all of the import voodoo
here, and have other modules that need MySQLdb import the MySQL module
object from this module.  Looks kind of strange, but seems to work.

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

Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")

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

from __future__ import with_statement

import warnings

if hasattr(warnings, "catch_warnings"):
  with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    import MySQLdb
else:
  import MySQLdb

import _mysql_exceptions

warnings.simplefilter("error", _mysql_exceptions.Warning)
