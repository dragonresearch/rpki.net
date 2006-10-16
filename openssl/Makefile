# $Id$

all: .configured
	cd trunk; make $@

clean:
	cd trunk; make $@
	rm -f .configured

.configured: trunk/Configure trunk/config
	cd trunk; PERL=/usr/bin/perl ./config enable-rfc3779 no-dso
	touch $@

install:
	@echo Not attempting to install modified OpenSSL, if you want that, do it yourself
