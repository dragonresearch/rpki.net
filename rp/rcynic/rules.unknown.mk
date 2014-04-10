# $Id$

install-user-and-group install-shared-libraries install-rc-scripts: .FORCE
	@echo "Don't know how to make $@ on this platform"; exit 1
