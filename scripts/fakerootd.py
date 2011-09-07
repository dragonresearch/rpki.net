"""
Hack to fake a catatonic rootd, for testing.

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

import sys, socket, datetime, signal

port  = int(sys.argv[1]) if len(sys.argv) > 1 else 4405
limit = int(sys.argv[2]) if len(sys.argv) > 2 else 5

print "Listening on port", port

s4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
s4.bind(('', port))
s4.listen(limit)

s6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
s6.bind(('::1', port))
s6.listen(limit)

print "Going to sleep at", datetime.datetime.utcnow()

try:
  signal.pause()
except KeyboardInterrupt:
  sys.exit(0)

