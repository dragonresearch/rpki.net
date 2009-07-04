#!/bin/sh -
# $Id$
#
# Tests of generated BPKI certificates.

find bpki.* -name '*.crl' | sed 's=^\(.*\)/\(.*\)$=echo -n "&: "; openssl crl -CAfile \1/ca.cer -noout -in &=' | sh

find bpki.* -name '*.cer' ! -name 'ca.cer' ! -name '*.cacert.cer' | sed 's=^\(.*\)/.*$=openssl verify -CAfile \1/ca.cer &=' | sh

# This won't work once there are more certs in the picture, but will
# suffice as an initial test of the pathlen-restricted
# cross-certification.

for bpki in bpki.pubd bpki.rpkid
do
  openssl verify -verbose -CAfile $bpki/ca.cer -untrusted $bpki/xcert.*.cer bpki.myrpki/bsc.*.cer
done
