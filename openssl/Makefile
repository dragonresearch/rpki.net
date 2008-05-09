# $Id$

VERSION = SNAP-20080509

all: openssl-${VERSION}/Makefile
	cd openssl-${VERSION}; make $@
	ln -sf openssl-${VERSION} openssl

clean:
	rm -rf openssl-${VERSION} openssl

openssl-${VERSION}/Makefile: openssl-${VERSION}/config
	cd openssl-${VERSION}; PERL=/usr/bin/perl ./config enable-rfc3779 no-dso

openssl-${VERSION}/config: openssl-${VERSION}.tar.gz
	gzip -c -d openssl-${VERSION}.tar.gz | tar -xf -
	ln -s . openssl-${VERSION}/lib
	touch $@

install:
	@echo Not attempting to install modified OpenSSL, if you want that, do it yourself

sandblast:
	svn st -v openssl* | awk '/^I/ && NF == 2 {system("set -x; rm -rf " $$2)}'

test:
	@true
