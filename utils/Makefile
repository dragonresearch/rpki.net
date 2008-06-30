# $Id$

SUBDIRS = uri manifest cert_hash roa hashdir

all clean test:
	@for i in ${SUBDIRS}; do echo "Making $@ in $$i"; (cd $$i && ${MAKE} $@); done

install:
	@true
