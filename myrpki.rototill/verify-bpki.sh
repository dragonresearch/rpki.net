#!/bin/sh -
# $Id$
#
# Copyright (C) 2009-2010  Internet Systems Consortium ("ISC")
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

# Tests of generated BPKI certificates.  Kind of cheesy, but does test
# the basic stuff.

exec 2>&1

for bpki in bpki/*
do
  crls=$(find $bpki -name '*.crl')

  # Check that CRLs verify properly
  for crl in $crls
  do
    echo -n "$crl: "
    openssl crl -CAfile $bpki/ca.cer -noout -in $crl
  done

  # Check that issued certificates verify properly
  cat $bpki/ca.cer $crls | openssl verify -crl_check -CAfile /dev/stdin $(find $bpki -name '*.cer' ! -name 'ca.cer' ! -name '*.cacert.cer')

done

# Check that cross-certified BSC certificates verify properly
if test -d bpki/servers
then
    cat bpki/servers/xcert.*.cer | openssl verify -verbose -CAfile bpki/servers/ca.cer -untrusted /dev/stdin bpki/resources/bsc.*.cer
fi
