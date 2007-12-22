#!/bin/sh -
# $Id$

: ${instance=R0}

python ../rpkid.py    -c $instance.conf &
rpkid=$!

python ../irbe-cli.py -c $instance.conf bsc --self_id 1 --action list |
qh 2>/dev/null |
awk '
  /\(signing_cert/ {p = 1}
  /\)signing_cert/ {p = 0}
  p && /^-/ {
    sub(/-/,"");
    cmd = "mimencode -u | openssl x509 -text -inform DER -out " NR ".pem";
    print | cmd;
  }
'

kill $rpkid
