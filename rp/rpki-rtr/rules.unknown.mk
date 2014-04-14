# $Id$

install-always:

install-postconf: install-listener

install-listener:
	@echo "Don't know how to make $@ on this platform"; exit 1
