# $Id$

VERSION	= 2.6.8

CFG_ENV	= LDFLAGS=-static
CFG_ARG	=

TARBALL = rsync-${VERSION}.tar.gz
DIRNAME	= rsync-${VERSION}

BIN	= rsync

all: ${BIN}

${BIN}: ${DIRNAME}/${BIN}
	ln ${DIRNAME}/${BIN} $@

${DIRNAME}/${BIN}: configured.stamp
	cd ${DIRNAME} && ${MAKE}

extracted.stamp: ${TARBALL}
	gzcat ${TARBALL} | tar -xf -
	touch $@

configured.stamp: extracted.stamp
	cd ${DIRNAME} && ${CFG_ENV} ./configure ${CFG_ARG}
	touch $@

clean:
	rm -rf ${BIN} ${DIRNAME} *.stamp
