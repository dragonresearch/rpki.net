# $Id$

SUBDIRS = openssl rcynic utils pow rpkid

all install clean test:
	@for i in ${SUBDIRS}; do echo "Making $@ in $$i"; (cd $$i && ${MAKE} $@); done

test: all

export:
	svn export http://subvert-rpki.hactrn.net/
	-cd subvert-rpki.hactrn.net/scripts/rpki; PATH=/bin:/usr/bin:/usr/local/bin /usr/local/bin/doxygen </dev/null
	tar czf subvert-rpki.hactrn.net-$$(date +%Y.%m.%d).tar.gz subvert-rpki.hactrn.net
	rm -rf subvert-rpki.hactrn.net
