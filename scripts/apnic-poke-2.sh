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

openssl=../openssl/openssl/apps/openssl

# Halt on first error and show what's happening

set -ex

# Blow away old rpkid database (!) so we can start clean

mysql -u rpki -p`awk '$1 == "sql-password" {print $3}' rpkid.conf` rpki <../docs/rpki-db-schema.sql

# Clear out any old publication results

rm -rf publication/*

# Start rpkid so we can configure it, make sure we shut it down on exit
# If we're running under screen, just run it in a different screen instead.

if test -n "$STY"
then
  screen python rpkid.py
else
  python rpkid.py >>rpkid.log 2>&1 & rpkid=$!
  trap "kill $rpkid" 0 1 2 3 13 15
fi

# Create a self instance

python irbe-cli.py self --action create --crl_interval 84600

# Create a business signing context, issue the necessary business cert, and set up the cert chain

python irbe-cli.py --pem_out bsc.req bsc --action create --self_id 1 \
    --generate_keypair --signing_cert biz-certs/Bob-CA.cer
$openssl x509 -req -in bsc.req -out bsc.cer \
    -CA biz-certs/Bob-CA.cer -CAkey biz-certs/Bob-CA.key -CAserial biz-certs/Bob-CA.srl
python irbe-cli.py bsc --action set --self_id 1 --bsc_id 1 --signing_cert bsc.cer
rm -f bsc.req bsc.cer

# List what's in the BSC, for today's debugging fun

#python irbe-cli.py bsc --action list --self_id 1

# Create a repository context

python irbe-cli.py repository --self_id 1 --action create --bsc_id 1

# Create a parent context pointing at APNIC -- this is where we plug in the values from their YAML

cat >apnic.pem <<-'EOF'
	-----BEGIN CERTIFICATE-----
	MIIEFjCCAv6gAwIBAgIBADANBgkqhkiG9w0BAQsFADBJMUcwRQYDVQQDEz5Eb2N1
	bWVudGF0aW9uIFByZWZpeGVzIENNUyBQYXJlbnQgVEEgc2lnbmVyIC0gTm90IGZv
	ciByZWFsIHVzZTAeFw0wNzEyMDEwNjMyNDdaFw0xNzExMjgwNjMyNDdaMEkxRzBF
	BgNVBAMTPkRvY3VtZW50YXRpb24gUHJlZml4ZXMgQ01TIFBhcmVudCBUQSBzaWdu
	ZXIgLSBOb3QgZm9yIHJlYWwgdXNlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
	CgKCAQEAtsRcgBpO7cTN+QGPnBaPtmfdsUZbctrfSBycS3QhwAItzZryqIHN9stP
	A+0WEOC4+cfaY9xETqGwbq725p8FRwxUx9NBQS7jrL1ToNCJ+2qSH5ThK2hOQiCT
	3fv2FNJ/7gFFqofWt3mLyNEmnis95pRwzTtqH6ZaAaZk+AzwL77ww8AlwL/qfLtD
	mjrsUfoELfkbS4ywFK0orjVKeGvzG8Dx7WiGvwmdhNNJ8/IAZmJC0NI8r9VIfcw3
	2B7bnDGkKH3E0NNRIajPmLbaNfT0Dxw+BjIC3Ty48o3ghSScqviyThNFyj8cr9SB
	Ww8ReAU6v9q4XWRnlZt8Lc9WIsF/MwIDAQABo4IBBzCCAQMwDAYDVR0TBAUwAwEB
	/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFPzZTgRZylsJph8KV9AU3klSgl8r
	MHEGA1UdIwRqMGiAFPzZTgRZylsJph8KV9AU3klSgl8roU2kSzBJMUcwRQYDVQQD
	Ez5Eb2N1bWVudGF0aW9uIFByZWZpeGVzIENNUyBQYXJlbnQgVEEgc2lnbmVyIC0g
	Tm90IGZvciByZWFsIHVzZYIBADBRBgNVHR8ESjBIMEagRKBChkBodHRwOi8vbWly
	aW4uYXBuaWMubmV0L2RvY3VtZW50YXRpb24tcHJlZml4ZXMvY21zL3BhcmVudC9j
	bXMuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQCNz/BUN5bsAyMPi0X7oKZV/cAwmr2S
	gQgIxaUHnQ6EJp4b2CUmlpPQ9pT/m+gPbajaRgUZmANfMF0uAFZpCP3hTRAc6NMH
	3Pwjzw1ICGSRRJASSizYN4hSxGpWW1hgghGTB3w5CjCm2VlwrQKJjb7/9H/gb4hi
	RRZpaudithCEDlgkFhgU4uttSDLH2Rv14GtfmtyqDpmCE33STA7K+e9rdxaCqHC8
	u33zqm4oQxOX7wuJ/JxeJxExtZ0amu8yTZ+tDtQ4Iiu1VPl67o0mjYrBKRV4z2fC
	wa/PKqombrC/qs+2+t/66mB9xaK1YpKnW2FL6Rjs+rZUJJQ16JhJkF7T
	-----END CERTIFICATE-----
EOF

python irbe-cli.py parent --self_id 1 --action create --bsc_id 1 --repository_id 1 \
    --peer_contact_uri https://mirin.apnic.net/cgi-bin/up-down-parent.cgi \
    --cms_ta   apnic.pem \
    --https_ta apnic.pem \
    --sia_base rsync://wombat.invalid/ \
    --recipient_name PARENT \
    --sender_name    CHILD

rm -f apnic.pem

# Create a child context

python irbe-cli.py child --self_id 1 --action create --bsc_id 1 --cms_ta biz-certs/Frank-Root.cer

# Run the other daemons, arrange for everything to go away on shutdown,
# run initial cron job to set things up, then wait

if test -n "$STY"
then
  screen python irdbd.py
else
  python irdbd.py >>irdbd.log 2>&1 & irdbd=$!
  trap "kill $rpkid $irdbd" 0 1 2 3 13 15
fi

python cronjob.py

if test -z "$STY"
then
  tail +0f rpkid.log
fi
