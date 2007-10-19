# $Id$

VERSION = 0.9.8f

all: openssl-${VERSION}/Makefile
	cd openssl-${VERSION}; make $@

clean:
	rm -rf openssl-${VERSION}

openssl-${VERSION}/Makefile: openssl-${VERSION}/config
	cd openssl-${VERSION}; PERL=/usr/bin/perl ./config enable-rfc3779 no-dso

openssl-${VERSION}/config: openssl-${VERSION}.tar.gz
	gzcat openssl-${VERSION}.tar.gz | tar -xf -
	ln -s . openssl-${VERSION}/lib
	touch $@

install:
	@echo Not attempting to install modified OpenSSL, if you want that, do it yourself
