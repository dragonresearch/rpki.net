#!/bin/sh -
# $Id$

scripts="subvert-rpki.hactrn.net/scripts"

repositories="ca-trial.ripe.net/RIPE ca-trial.ripe.net/ARIN repository.apnic.net"

cd `dirname $0`

. $scripts/mirror-apnic.sh
. $scripts/mirror-ripe.sh

perl $scripts/gen-verify-test.pl $repositories |
tee verify.sh |
sh 2>&1 |
tee verify.log

perl $scripts/make-hashes.pl $repositories |
tee make-hashes.sh |
sh 2>&1 |
tee make-hashes.log

sh $scripts/check-hashes.sh 2>&1 |
tee check-hashes.log
