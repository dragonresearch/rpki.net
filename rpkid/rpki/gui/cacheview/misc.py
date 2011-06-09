"""
Copyright (C) 2011  SPARTA, Inc. dba Cobham Analytic Solutions

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND SPARTA DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL SPARTA BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

from rpki.resource_set import resource_range_ipv4, resource_range_ipv6
from rpki.exceptions import BadIPResource

def parse_ipaddr(s):
    # resource_set functions only accept str
    if isinstance(s, unicode):
        s = s.encode()
    s = s.strip()
    r = resource_range_ipv4.parse_str(s)
    try:
        r = resource_range_ipv4.parse_str(s)
        return 4, r
    except BadIPResource:
        r = resource_range_ipv6.parse_str(s)
        return 6, r

# vim:sw=4 ts=8 expandtab
