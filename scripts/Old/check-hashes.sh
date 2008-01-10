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

: ${openssl=/u/sra/isc/route-pki/subvert-rpki.hactrn.net/openssl/openssl/apps/openssl}
: ${switches='-verbose -crl_check_all -policy_check -explicit_policy -policy 1.3.6.1.5.5.7.14.2 -x509_strict'}
: ${hashtree=hashed}

find $hashtree -type f -name '*.[0-9]*' 2>&1 -print -exec \
    $openssl verify $switches -CApath $(find $hashtree -type d | tr \\012 : | sed 's=:$==') {} \;

# Hack for analyzing results of running this script:
#
# awk -F: '/^hashed/ && NF == 1 {f = $0; p = 1; next} /^hashed/ && NF == 2 && $1 == f && $2 == " OK" {next} p {print "\n" f; p = 0} {print}' check-hashes.log
