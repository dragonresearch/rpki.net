#!/bin/sh -
# $Id$
#
# Copyright (C) 2010  Internet Systems Consortium, Inc. ("ISC")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

# Generate an indirect trust anchor given the rsync URI for a
# self-signed RFC 3779 certificate.
#
# Usage: make-tal.sh uri [local_copy_of_certificate]
#
# The optional second parameter is the name of a local copy of the
# certificate to be checked against the copy retrieved from the URI;
# if present, this should be a local X.509 file in DER format.

case "$1" in rsync://*) :;; *) echo 1>&2 "\"$1\" is not a rsync URI"; exit 1;; esac

tmpfile="make-tal.tmp.$$"
trap "rm -f $tmpfile" 0 1 2 15

rsync "$1" "$tmpfile" || exit

if test -n "$2"
then
  diff -q "$tmpfile" "$2" || exit
fi

echo "$1"
openssl x509 -inform DER -in "$tmpfile" -pubkey -noout |
awk '!/-----(BEGIN|END)/'
