#!/bin/sh -
# $Id$

# Quick hack to generate a set of business keys and certs for use with
# early prototype code.  Not for production use.
#
# All we're trying to do here is generate a three-level-deep set of
# certs for each of several independent entities.  Could easily be
# deeper in practice but this should be enough for simple tests: a
# self-signed root cert to use as a trust anchor, a working CA, and an
# EE cert used for CMS or TLS.

for i in Alice Bob Carol Dave
do
  for j in Root CA EE
  do

    case $j in
      EE) ca=false;;
      *)  ca=true;;
    esac

    test -r $i-$j.cnf || cat >$i-$j.cnf <<-EOF

	[ req ]
	distinguished_name	= req_dn
	x509_extensions		= req_x509_ext
	prompt			= no
	default_md		= sha1

	[ req_dn ]
	CN			= Test Certificate $i $j

	[ req_x509_ext ]
	basicConstraints	= CA:$ca
	subjectKeyIdentifier	= hash
	authorityKeyIdentifier	= keyid:always

	EOF

    test -r $i-$j.key -a -r $i-$j.req ||
    openssl req -new -newkey rsa:2048 -nodes -keyout $i-$j.key -out $i-$j.req -config $i-$j.cnf

  done

  test -r $i-Root.cer || openssl x509 -req -in $i-Root.req -out $i-Root.cer -extfile $i-Root.cnf -extensions req_x509_ext -signkey $i-Root.key
  test -r $i-CA.cer   || openssl x509 -req -in $i-CA.req   -out $i-CA.cer   -extfile $i-CA.cnf   -extensions req_x509_ext -CA $i-Root.cer -CAkey $i-Root.key -CAcreateserial
  test -r $i-EE.cer   || openssl x509 -req -in $i-EE.req   -out $i-EE.cer   -extfile $i-EE.cnf   -extensions req_x509_ext -CA $i-CA.cer   -CAkey $i-CA.key   -CAcreateserial

done
