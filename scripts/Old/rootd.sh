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

# Script to test against rootd.py.
#
# This blows away rpkid's database and rebuilds it with what we need
# for this test, and knows far too much about the id numbers that
# rpkid and mysql will assign.  In the long run we must do better than
# this, but gotta start somewhere.

openssl=../openssl/openssl/apps/openssl

# Halt on first error

set -e

# Generate new key and cert for rootd.py if needed

if test ! -r rootd.cer -o ! -r rootd.key
then
  $openssl req -new -newkey rsa:2048 -nodes -keyout rootd.key -out rootd.req -config rootd.cnf
  $openssl x509 -req -in rootd.req -out rootd.cer -extfile rootd.cnf -extensions req_x509_ext -signkey rootd.key -text -sha256
  rm -f rootd.req
fi

# Blow away old rpkid database (!) so we can start clean

mysql -u rpki -p`awk '$1 == "sql-password" {print $3}' rpkid.conf` rpki <rpki-db-schema.sql

# Start rpkid so we can configure it, make sure we shut it down on exit

python rpkid.py & rpkid=$!
trap "kill $rpkid" 0 1 2 3 13 15

: Waiting to let rpkid start up; sleep 5

# Create a self instance

time python irbe_cli.py self --action create --crl_interval 84600

# Create a business signing context, issue the necessary business cert, and set up the cert chain

time python irbe_cli.py --pem_out bsc.req bsc --action create --self_id 1 --generate_keypair --signing_cert biz-certs/Bob-CA.cer
time $openssl x509 -req -in bsc.req -out bsc.cer -CA biz-certs/Bob-CA.cer -CAkey biz-certs/Bob-CA.key -CAserial biz-certs/Bob-CA.srl
time python irbe_cli.py bsc --action set --self_id 1 --bsc_id 1 --signing_cert bsc.cer
rm -f bsc.req bsc.cer

# Create a repository context

time python irbe_cli.py repository --self_id 1 --action create --bsc_id 1

# Create a parent context pointing at rootd.py

time python irbe_cli.py parent --self_id 1 --action create --bsc_id 1 --repository_id 1 \
    --peer_contact_uri https://localhost:44333/ \
    --cms_ta biz-certs/Elena-Root.cer \
    --https_ta biz-certs/Elena-Root.cer \
    --sia_base rsync://wombat.invalid/ \
    --sender_name tweedledee \
    --recipient_name tweedledum

# Create a child context

time python irbe_cli.py child --self_id 1 --action create --bsc_id 1 --cms_ta biz-certs/Frank-Root.cer

# Need to link irdb to created child and clear conflicting links.
# For now, just do this "manually" in MySQL CLI.

echo '
  UPDATE registrant SET rpki_self_id = NULL, rpki_child_id = NULL;
  UPDATE registrant SET rpki_self_id = 1, rpki_child_id = 1 WHERE subject_name = "Epilogue Technology Corporation";
' |
mysql -u irdb -p`awk '$1 == "sql-password" {print $3}' irbe.conf` irdb

if test "$1" = "run"
then

  rm -rf publication

  python rootd.py & rootd=$!
  python irdbd.py & irdbd=$!
  trap "kill $rpkid $irdbd $rootd" 0 1 2 3 13 15

  : Waiting to let daemons start up; sleep 5

  date; time python cronjob.py
  date; time python testpoke.py -r list
  date; time python testpoke.py -r issue

  date; time python cronjob.py
  date; time python testpoke.py -r list
  date; time python testpoke.py -r issue

  date; python testpoke.py -r issue |
  qh |
  sed -n '/^(certificate/,/^)certificate/s/^-//p' |
  mimencode -u |
  $openssl x509 -noout -inform DER -text

  date; time python testpoke.py -r revoke
  date; time python testpoke.py -r list
  date; time python cronjob.py
  date; time python testpoke.py -r list

  date; time python cronjob.py
  date; time python testpoke.py -r list
  date; time python testpoke.py -r issue

  date; time python testpoke.py -r revoke
  date; time python testpoke.py -r list
  date; time python cronjob.py
  date; time python testpoke.py -r list

  date; time python testpoke.py -r issue
  date; time python testpoke.py -r revoke
  date; time python testpoke.py -r issue
  date; time python testpoke.py -r revoke
  date; time python testpoke.py -r issue
  date; time python testpoke.py -r revoke
  date; time python testpoke.py -r list
  date; time python cronjob.py
  date; time python testpoke.py -r list

  date; time python testpoke.py -r issue
  date; time python cronjob.py
  date; time python testpoke.py -r list
  date

fi
