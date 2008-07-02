# $Id$

SUBDIRS = uri manifest roa hashdir

all clean test:
	@for i in ${SUBDIRS}; do echo "Making $@ in $$i"; (cd $$i && ${MAKE} $@); done

install:
	@true
