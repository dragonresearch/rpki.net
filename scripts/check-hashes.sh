#!/bin/sh -
# $Id$

cd `dirname $0`

openssl=/u/sra/isc/route-pki/subvert-rpki.hactrn.net/openssl/trunk/apps/openssl

capth=$(echo $(find hashed -type d) | tr \\040 :)

find hashed -type f -name '*.?' |
xargs $openssl verify -verbose -crl_check_all -policy_check -explicit_policy -policy 1.3.6.1.5.5.7.14.2 -x509_strict -CApath $capth 
