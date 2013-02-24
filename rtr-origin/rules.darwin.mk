# $Id$

install-always: install-binary

install-postconf: install-listener

install-listener:
	@echo "No rule for $@ on this platform (yet), you'll have to do that yourself if it matters."

