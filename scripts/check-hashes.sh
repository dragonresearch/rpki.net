#!/bin/sh -
# $Id$

: ${openssl=/u/sra/isc/route-pki/subvert-rpki.hactrn.net/openssl/trunk/apps/openssl}
: ${switches='-verbose -crl_check_all -policy_check -explicit_policy -policy 1.3.6.1.5.5.7.14.2 -x509_strict'}
: ${hashtree=hashed}

find $hashtree -type f -name '*.[0-9]*' 2>&1 -print -exec \
    $openssl verify $switches -CApath $(find $hashtree -type d | tr \\012 : | sed 's=:$==') {} \;

# Hack for analyzing results of running this script:
#
# awk -F: '/^hashed/ && NF == 1 {f = $0; p = 1; next} /^hashed/ && NF == 2 && $1 == f && $2 == " OK" {next} p {print "\n" f; p = 0} {print}' check-hashes.log
