#!/bin/sh -
# $Id$

# Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

: ${instance=R0}

python ../rpkid.py    -c $instance.conf &
rpkid=$!

python ../irbe-cli.py -c $instance.conf bsc --self_id 1 --action list |
qh 2>/dev/null |
awk '
  /\(signing_cert/ {p = 1}
  /\)signing_cert/ {p = 0}
  p && /^-/ {
    sub(/-/,"");
    cmd = "mimencode -u | openssl x509 -text -inform DER -out " NR ".pem";
    print | cmd;
  }
'

kill $rpkid
