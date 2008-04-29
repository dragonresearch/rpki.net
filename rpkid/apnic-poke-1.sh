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

# Script to let APNIC test against my server.
#
# This blows away rpkid's database and rebuilds it with what we need
# for this test, and knows far too much about the id numbers that
# rpkid and mysql will assign.  In the long run we must do better than
# this, but gotta start somewhere.

openssl=../openssl/openssl/apps/openssl

# Halt on first error and show what's happening

set -ex

# Generate new key and cert for rootd.py if needed

if test ! -r rootd.cer -o ! -r rootd.key
then
  $openssl req -new -newkey rsa:2048 -nodes -keyout rootd.key -out rootd.req -config rootd.cnf

  $openssl x509 -req -in rootd.req -out rootd.cer -extfile rootd.cnf -extensions req_x509_ext \
      -signkey rootd.key -text -sha256

  rm -f rootd.req
fi

# Blow away old rpkid database (!) so we can start clean

mysql -u rpki -p`awk '$1 == "sql-password" {print $3}' rpkid.conf` rpki <rpki-db-schema.sql

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

$openssl x509 -req -in bsc.req -out bsc.cer -CA biz-certs/Bob-CA.cer \
    -CAkey biz-certs/Bob-CA.key -CAserial biz-certs/Bob-CA.srl

python irbe-cli.py bsc --action set --self_id 1 --bsc_id 1 --signing_cert bsc.cer

rm -f bsc.req bsc.cer

# Create a repository context

python irbe-cli.py repository --self_id 1 --action create --bsc_id 1

# Create a parent context pointing at rootd.py

python irbe-cli.py parent --self_id 1 --action create --bsc_id 1 --repository_id 1 \
    --peer_contact_uri https://localhost:44333/ \
    --cms_ta biz-certs/Elena-Root.cer \
    --https_ta biz-certs/Elena-Root.cer \
    --sia_base rsync://wombat.invalid/

# Create a child context

python irbe-cli.py child --self_id 1 --action create --bsc_id 1 --cms_ta biz-certs/Frank-Root.cer

# Run the other daemons, arrange for everything to go away on shutdown,
# run initial cron job to set things up, then wait

if test -n "$STY"
then
  screen python rootd.py
  screen python irdbd.py
else
  python rootd.py >>rootd.log 2>&1 & rootd=$!
  python irdbd.py >>irdbd.log 2>&1 & irdbd=$!
  trap "kill $rpkid $irdbd $rootd" 0 1 2 3 13 15
fi

python cronjob.py

if test -z "$STY"
then
  tail +0f rpkid.log
fi
