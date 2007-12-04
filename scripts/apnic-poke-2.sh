#!/bin/sh -
# $Id$

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

# Create a repository context

python irbe-cli.py repository --self_id 1 --action create --bsc_id 1

# Create a parent context pointing at APNIC -- this is where we plug in the values from their YAML

python irbe-cli.py parent --self_id 1 --action create --bsc_id 1 --repository_id 1 \
    --peer_contact_uri https://localhost:44333/ \
    --cms_ta biz-certs/Elena-Root.cer \
    --https_ta biz-certs/Elena-Root.cer \
    --sia_base rsync://wombat.invalid/

# Create a child context -- note that we're using the -CA as trust anchor rather than -Root,
# because the APNIC poke tool doesn't offer any way to construct CMS chains

python irbe-cli.py child --self_id 1 --action create --bsc_id 1 --cms_ta biz-certs/Frank-Root.cer

# Run the other daemons, arrange for everything to go away on shutdown,
# run initial cron job to set things up, then wait

if test -n "$STY"
then
  screen python irdb.py
else
  python irdb.py     >>irdb.log     2>&1 & irdb=$!
  trap "kill $rpkid $irdb" 0 1 2 3 13 15
fi

python http-client.py

if test -z "$STY"
then
  tail +0f rpkid.log
fi
