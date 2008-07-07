#!/bin/sh -
#
# Copyright (C) 2006--2008  American Registry for Internet Numbers ("ARIN")
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
#
# $Id$

auth_dir="${1?"usage: $0 authenticated_certificate_tree prefix [prefix...]"}"

rm -rf hashed-pem-dir
mkdir  hashed-pem-dir

../hashdir/hashdir "$auth_dir" hashed-pem-dir >/dev/null

./find_roa "$@" | awk '
  $1 == "ASN" && $3 == "prefix" && $5 == "ROA" {
    print "";
    print "Found match:"
    print;
    print "Verifying certificate chain and signatures:"
    roa = $6;
    if (!system("../../openssl/openssl/apps/openssl cms -verify -inform DER -out /dev/null -CApath hashed-pem-dir -in " roa))
      system("../print_roa/print_roa " roa);
  }'
