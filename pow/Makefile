# $Id$

VERSION = 0.7
STAMP	= POW-${VERSION}/build/.timestamp

SOURCES = POW-${VERSION}/lib/__init__.py	\
	  POW-${VERSION}/lib/_der.py		\
	  POW-${VERSION}/lib/_simpledb.py	\
	  POW-${VERSION}/lib/pkix.py		\
	  POW-${VERSION}/setup.py		\
	  POW-${VERSION}/cfgparse.py		\
	  POW-${VERSION}/dumpasn1.cfg		\
	  POW-${VERSION}/POW.c

all: ${STAMP}

${STAMP}: ${SOURCES}
	cd POW-${VERSION}; python setup.py build
	touch $@

clean:
	rm -rf POW-${VERSION}/build

install:
	@echo Not attempting to install modified POW, if you want that, do it yourself

test: all
	cp -p POW-${VERSION}/test/test.py POW-${VERSION}/build/lib.*/.
	cd POW-${VERSION}/build/lib.*/. && python test.py
