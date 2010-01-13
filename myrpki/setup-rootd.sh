#!/bin/sh -
#
# $Id$
#
# Copyright (C) 2010  Internet Systems Consortium ("ISC")
# 
# Permission to use, copy, modify, and distribute this software for any
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

# Setting up rootd requires cross-certifying rpkid's resource-holding
# BPKI trust anchor under the BPKI trust anchor that rootd uses.  This
# script handles that, albiet in a very ugly way.
#
# Filenames are wired in, you might need to change these if you've
# done something more complicated.

export RANDFILE=.OpenSSL.whines.unless.I.set.this
export BPKI_DIRECTORY=`pwd`/bpki.myirbe

openssl=../openssl/openssl/apps/openssl

$openssl ca -notext -batch -config myrpki.conf \
	-ss_cert bpki.myrpki/ca.cer \
	-out bpki.myirbe/child.cer \
	-extensions ca_x509_ext_xcert0

$openssl x509 -noout -text -in bpki.myirbe/child.cer
