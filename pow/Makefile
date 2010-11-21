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

all: ${STAMP} pywrap/python

${STAMP}: ${SOURCES}
	cd POW-${VERSION}; python setup.py build
	ln -sf POW-${VERSION}/build/lib.* buildlib
	touch $@

pywrap/python:
	cd pywrap; ${MAKE} python

clean:
	rm -rf POW-${VERSION}/build buildlib
	cd pywrap; ${MAKE} $@

install:
	@echo Not attempting to install modified POW, if you want that, do it yourself

# Doesn't really work at the moment
#
#test: all
#	cp -p POW-${VERSION}/test/test.py POW-${VERSION}/build/lib.*/.
#	cd POW-${VERSION}/build/lib.*/. && python test.py

test:
	@true
