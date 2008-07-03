# $Id$

SUBDIRS = uri print_manifest print_roa hashdir find_roa

all clean test:
	@for i in ${SUBDIRS}; do echo "Making $@ in $$i"; (cd $$i && ${MAKE} $@); done

install:
	@true
