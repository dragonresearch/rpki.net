#!/bin/sh -
# $Id$
#
# Script to test against testroot.py.
#
# This blows away rpkid's database and rebuilds it with what we need
# for this test, and knows far too much about the id numbers that
# rpkid and mysql will assign.  In the long run we must do better than
# this, but gotta start somewhere.

openssl=../openssl/openssl/apps/openssl

# Halt on first error

set -e

# Generate new key and cert for testroot.py if needed

if test ! -r testroot.cer -o ! -r testroot.key
then
  $openssl req -new -newkey rsa:2048 -nodes -keyout testroot.key -out testroot.req -config testroot.cnf
  $openssl x509 -req -in testroot.req -out testroot.cer -extfile testroot.cnf -extensions req_x509_ext -signkey testroot.key -text -sha256
  rm -f testroot.req
fi

# Blow away old rpkid database (!) so we can start clean

mysql -u rpki -p`awk '$1 == "sql-password" {print $3}' rpkid.conf` rpki <../docs/rpki-db-schema.sql

# Start rpkid so we can configure it, make sure we shut it down on exit

python rpkid.py & rpkid=$!
trap "kill $rpkid" 0

# Create a self instance

time python irbe-cli.py self --action create --crl_interval 84600

# Create a business signing context, issue the necessary business cert, and set up the cert chain

time python irbe-cli.py --pem_out bsc.req bsc --action create --self_id 1 --generate_keypair --signing_cert biz-certs/Bob-CA.cer
time $openssl x509 -req -in bsc.req -out bsc.cer -CA biz-certs/Bob-CA.cer -CAkey biz-certs/Bob-CA.key -CAserial biz-certs/Bob-CA.srl
time python irbe-cli.py bsc --action set --self_id 1 --bsc_id 1 --signing_cert bsc.cer
rm -f bsc.req bsc.cer

# Create a repository context

time python irbe-cli.py repository --self_id 1 --action create --bsc_id 1

# Create a parent context pointing at testroot.py

time python irbe-cli.py parent --self_id 1 --action create --bsc_id 1 --repository_id 1 \
    --peer_contact_uri https://localhost:44333/ \
    --cms_ta biz-certs/Elena-Root.cer \
    --https_ta biz-certs/Elena-Root.cer \
    --sia_base rsync://wombat.invalid/ \
    --sender_name tweedledee \
    --recipient_name tweedledum

# Create a child context

time python irbe-cli.py child --self_id 1 --action create --bsc_id 1 --cms_ta biz-certs/Frank-Root.cer

# Need to link irdb to created child.  For now, just do this manually in MySQL CLI:
#
#   UPDATE registrant SET rpki_self_id = 1, rpki_child_id = 1 WHERE subject_name = "Epilogue Technology Corporation"

if test "$1" = "run"
then

  rm -rf publication

  python testroot.py & testroot=$!
  python irdb.py     & irdb=$!
  trap "kill $rpkid $irdb $testroot" 0

  date; time python http-client.py
  date; time python testpoke.py -r list
  date; time python testpoke.py -r issue

  date; time python http-client.py
  date; time python testpoke.py -r list
  date; time python testpoke.py -r issue

  date; python testpoke.py -r issue |
  qh |
  sed -n '/^(certificate/,/^)certificate/s/^-//p' |
  mimencode -u |
  $openssl x509 -noout -inform DER -text

  date; time python testpoke.py -r revoke
  date; time python testpoke.py -r list
  date; time python http-client.py
  date; time python testpoke.py -r list

  date; time python http-client.py
  date; time python testpoke.py -r list
  date; time python testpoke.py -r issue

  date; time python testpoke.py -r revoke
  date; time python testpoke.py -r list
  date; time python http-client.py
  date; time python testpoke.py -r list

  date; time python testpoke.py -r issue
  date; time python testpoke.py -r revoke
  date; time python testpoke.py -r issue
  date; time python testpoke.py -r revoke
  date; time python testpoke.py -r issue
  date; time python testpoke.py -r revoke
  date; time python testpoke.py -r list
  date; time python http-client.py
  date; time python testpoke.py -r list

  date; time python testpoke.py -r issue
  date; time python http-client.py
  date; time python testpoke.py -r list
  date

fi
