#!/bin/sh -
# $Id$
#
# Tests of generated BPKI certificates.  This is kind of cheesy but
# does test some of the basic stuff.

# Check that CRLs verify properly
find bpki.* -name '*.crl' | sed 's=^\(.*\)/\(.*\)$=echo -n "&: "; openssl crl -CAfile \1/ca.cer -noout -in &=' | sh

# Check that issued certs verify properly
find bpki.* -name '*.cer' ! -name 'ca.cer' ! -name '*.cacert.cer' | sed 's=^\(.*\)/.*$=openssl verify -CAfile \1/ca.cer &=' | sh

# Attempt to check that cross-certified certs verify properly
if test -d bpki.myirbe
then
    cat bpki.myirbe/xcert.*.cer | openssl verify -verbose -CAfile bpki.myirbe/ca.cer -untrusted /dev/stdin bpki.myrpki/bsc.*.cer
fi
