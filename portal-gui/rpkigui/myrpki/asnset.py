# $Id$
"""
Copyright (C) 2010  SPARTA, Inc. dba Cobham Analytic Solutions

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

class asnset(object):
    """A set-like object for containing sets of ASN values."""
    v = set()

    def __init__(self, init=None):
        """
        May be initialized from a comma separated list of positive integers.
        """
        if init:
            self.v = set(int(x) for x in init.split(',') if x.strip() != '')
            if any([x for x in self.v if x < 0]):
                raise ValueError, "Can't contain negative values."

    def __str__(self):
        return ','.join(str(x) for x in sorted(self.v))

    def __iter__(self):
        return iter(self.v)

    def add(self, n):
        assert isinstance(n, int)
        assert n > 0
        self.v.add(n)
