# $Id$

SUBDIRS = openssl rcynic tests

all install clean:
	@for i in ${SUBDIRS}; do echo "Making $@ in $$i"; (cd $$i && make $@); done
