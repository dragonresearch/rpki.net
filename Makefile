# $Id$

SUBDIRS = openssl rcynic tests pow

all install clean:
	@for i in ${SUBDIRS}; do echo "Making $@ in $$i"; (cd $$i && make $@); done
