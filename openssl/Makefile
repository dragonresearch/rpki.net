# $Id$

all: trunk/Makefile
	cd trunk; make $@

clean:
	-cd trunk; make $@
	rm -f trunk/Makefile

trunk/Makefile: trunk/Makefile.org trunk/Configure trunk/config
	cd trunk; PERL=/usr/bin/perl ./config enable-rfc3779 no-dso

install:
	@echo Not attempting to install modified OpenSSL, if you want that, do it yourself
