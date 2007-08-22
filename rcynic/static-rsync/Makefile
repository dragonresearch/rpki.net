# $Id$

VERSION	= 2.6.9

CFG_ENV	= LDFLAGS=-static
CFG_ARG	=

TARBALL = rsync-${VERSION}.tar.gz
DIRNAME	= rsync-${VERSION}

CFG_LOG	= > ../config.log 2>&1 
BIN_LOG	= > ../build.log  2>&1

BIN	= rsync

all: ${BIN}

${BIN}: ${DIRNAME}/${BIN}
	ln ${DIRNAME}/${BIN} $@
	file $@

${DIRNAME}/${BIN}: configured.stamp
	cd ${DIRNAME} && ${MAKE} ${BIN_LOG}

extracted.stamp: ${TARBALL}
	gzcat ${TARBALL} | tar -xf -
	touch $@

configured.stamp: extracted.stamp
	cd ${DIRNAME} && ${CFG_ENV} ./configure ${CFG_ARG} ${CFG_LOG}
	touch $@

clean:
	rm -rf ${BIN} ${DIRNAME} *.stamp *.log
