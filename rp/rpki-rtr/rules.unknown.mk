# $Id$

install-always: install-binary

install-postconf: install-listener

install-listener:
	@echo "Don't know how to make $@ on this platform"; exit 1
