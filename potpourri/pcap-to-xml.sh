#!/bin/sh -
# $Id$
#
# Copyright (C) 2011  Internet Systems Consortium ("ISC")
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

# Zeroeth cut at a packet decoder for RPKI up-down / left-right /
# publication traffic captured off the wire.  Needs work, not suitable
# for general use, depends on a bunch of external programs that I
# happen to have installed...but has been useful to me.

for p in *.pcap
do
    tcptrace -e $p
    for i in *.dat
    do
	j=${i%_contents.dat}
	sed '1,/^$/d' $i >$j.der
	openssl cms -verify -noverify -inform DER -in $j.der | xmlindent > $j.xml
	k=$(dumpasn1 -a $j.der 2>/dev/null | awk 'BEGIN {FS = "[ \t/:]+"} /signingTime/ {nr = NR + 2} NR == nr {print $6 "-" $5 "-" $4 "T" $7 ":" $8 ":" $9 "Z"}')
	mv $j.der $k.$j.der
	mv $j.xml $k.$j.xml
	rm $i
    done
done
