#!/bin/sh -
# $Id$

cd `dirname $0`
. mirror-apnic.sh
. mirror-ripe.sh
perl gen-verify-test.pl		\
    ca-trial.ripe.net/RIPE	\
    ca-trial.ripe.net/ARIN	\
    repository.apnic.net/APNIC	|
tee test.sh |
sh 2>&1 |
tee test.log
