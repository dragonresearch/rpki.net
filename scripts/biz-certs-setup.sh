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

# Quick hack to generate a set of business keys and certs for use with
# early prototype code.  Not for production use.
#
# All we're trying to do here is generate a three-level-deep set of
# certs for each of several independent entities.  Could easily be
# deeper in practice but this should be enough for simple tests: a
# self-signed root cert to use as a trust anchor, a working CA, and an
# EE cert used for CMS or TLS.
#
# Among other things missing here, we're not doing any restrictions
# beyond basicConstraints and we're not doing CRLs.
#
# One can extract the public key from a .key file by doing:
#
#   $ openssl rsa -in foo.key -pubout
#
# I ended up needing this to build simulated packets for the
# left-right protocol.

for i in Alice Bob Carol Dave Elena Frank Ginny Harry
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
	default_md		= sha256

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

  test -r $i-Root.cer || openssl x509 -req -in $i-Root.req -out $i-Root.cer -extfile $i-Root.cnf -extensions req_x509_ext -signkey $i-Root.key -days 60
  test -r $i-CA.cer   || openssl x509 -req -in $i-CA.req   -out $i-CA.cer   -extfile $i-CA.cnf   -extensions req_x509_ext -CA $i-Root.cer -CAkey $i-Root.key -CAcreateserial
  test -r $i-EE.cer   || openssl x509 -req -in $i-EE.req   -out $i-EE.cer   -extfile $i-EE.cnf   -extensions req_x509_ext -CA $i-CA.cer   -CAkey $i-CA.key   -CAcreateserial

done

for i in *.cer
do
  h=`openssl x509 -noout -hash -in $i`.0
  test -r $h ||
  ln -s $i $h
done
