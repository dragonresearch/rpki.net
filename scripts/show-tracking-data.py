"""
Show tracking data for a bunch of objects retrieved by rcynic.

This script takes one required argument, which is the name of a
directory tree containing the validated outpt of an rcynic run.  If
you follow the default naming scheme this will be
/some/where/rcynic-data/authenticated.

$Id$

Copyright (C) 2012  Internet Systems Consortium ("ISC")

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

import os
import sys
import rpki.x509

rcynic_dir = sys.argv[1]

for root, dirs, files in os.walk(rcynic_dir):
  for f in files:
    path = os.path.join(root, f)
    uri = "rsync://" + path[len(rcynic_dir):].lstrip("/")
    obj = rpki.x509.uri_dispatch(uri)(DER_file = path)
    print obj.tracking_data(uri)
