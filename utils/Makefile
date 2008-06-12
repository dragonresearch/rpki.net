# $Id$

SUBDIRS = resource-set uri

all clean test:
	@for i in ${SUBDIRS}; do echo "Making $@ in $$i"; (cd $$i && make $@); done

install:
	@true
