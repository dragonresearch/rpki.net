# $Id$

VERSION = SNAP-20090310

# Kludge alert:
#
# The --prefix=`pwd` and LIBRPATH=`pwd` settings below are to force
# OpenSSL's baroque configuration mechansim to build shared libraries
# that will run out of the build tree.  This is temporary.  Once we
# write "make install" code, we'll have to change that to point to the
# directory where the OpenSSL shared libraries will be installed.
#
# I would have avoided shared libraries entirely if I could, but the
# GNU linker isn't able to build POW (see ../pow/) from static
# libraries on 64-bit hardware.
#
# "You are lost in a maze of twisty programs, all broken in different
# ways" 

all: openssl-${VERSION}/Makefile
	cd openssl-${VERSION}; ${MAKE} $@ LIBRPATH=`pwd`
	ln -sf openssl-${VERSION} openssl

clean:
	rm -rf openssl-${VERSION} openssl
	cd tests; ${MAKE} $@

openssl-${VERSION}/Makefile: openssl-${VERSION}/config
	cd openssl-${VERSION}; PERL=/usr/bin/perl ./config enable-rfc3779 enable-cms no-dso enable-shared --prefix=`pwd`

openssl-${VERSION}/config: openssl-${VERSION}.tar.gz
	gzip -c -d openssl-${VERSION}.tar.gz | tar -xf -
	ln -s . openssl-${VERSION}/lib
	touch $@

install:
	@echo Not attempting to install modified OpenSSL, if you want that, do it yourself

sandblast:
	svn st -v openssl* | awk '/^I/ && NF == 2 {system("set -x; rm -rf " $$2)}'

test: all
	cd tests; ${MAKE} $@
