#!/bin/sh -
# $Id$

cd `dirname $0`

: ${openssl=/u/sra/isc/route-pki/subvert-rpki.hactrn.net/openssl/trunk/apps/openssl}
: ${switches='-verbose -crl_check_all -policy_check -explicit_policy -policy 1.3.6.1.5.5.7.14.2 -x509_strict'}
: ${hashtree=hashed}

find $hashtree -type f -name '*.[0-9]*' 2>&1 -exec \
    $openssl verify $switches -CApath $(find $hashtree -type d | tr \\012 : | sed 's=:$==') {} \;
