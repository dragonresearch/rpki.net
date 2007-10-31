#!/bin/sh -
# $Id$
#
# Generate test root resource certificate for use with testroot.py server.

tempfiles='01.pem testroot.index testroot.index.old testroot.serial testroot.serial.old testroot.index.attr testroot.req'

rm -f $tempfiles
touch testroot.index
echo 01 >testroot.serial
../openssl/openssl/apps/openssl genrsa -out testroot.key 2048
../openssl/openssl/apps/openssl req -new -config testroot.cnf -key testroot.key -out testroot.req
../openssl/openssl/apps/openssl ca -batch -out testroot.cer -in testroot.req -extfile testroot.cnf -config testroot.cnf -selfsign
rm -f $tempfiles
