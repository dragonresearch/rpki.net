# $Id$

.SUFFIXES: .pdf .sql

.sql.pdf:
	-sh ../scripts/graphviz-sql.sh $<

all:: left-right-protocol-samples/.stamp

left-right-protocol-samples/.stamp: left-right-protocol-samples.xml split-protocol-samples.xsl 
	xsltproc --stringparam dir left-right-protocol-samples split-protocol-samples.xsl left-right-protocol-samples.xml
	touch $@

all:: left-right-schema.rng

rpki/relaxng.py: left-right-schema.rng

left-right-schema.rng: left-right-schema.rnc
	trang left-right-schema.rnc left-right-schema.rng

all:: up-down-schema.rng 

rpki/relaxng.py: up-down-schema.rng

up-down-schema.rng: up-down-schema.rnc
	trang up-down-schema.rnc up-down-schema.rng

all:: publication-protocol-samples/.stamp

publication-protocol-samples/.stamp: publication-protocol-samples.xml split-protocol-samples.xsl 
	xsltproc --stringparam dir publication-protocol-samples split-protocol-samples.xsl publication-protocol-samples.xml
	touch $@

all:: publication-schema.rng 

rpki/relaxng.py: publication-schema.rng

publication-schema.rng: publication-schema.rnc
	trang publication-schema.rnc publication-schema.rng

clean:
	find . -type f -name '*.pyc' -delete

install:
	@true

dont-run-trang:
	touch *.rng

relaxng: left-right-protocol-samples/.stamp left-right-schema.rng up-down-schema.rng publication-protocol-samples/.stamp publication-schema.rng
	xmllint --noout --relaxng  left-right-schema.rng  left-right-protocol-samples/*.xml
	xmllint --noout --relaxng     up-down-schema.rng     up-down-protocol-samples/*.xml
	xmllint --noout --relaxng publication-schema.rng publication-protocol-samples/*.xml

unit-tests: all
	PWD=`pwd`; for i in rpki/*.py; do echo "[$$i]"; PYTHONPATH=$$PWD python $$i; done

all-tests:: unit-tests

parse-test: all
	python xml-parse-test.py

# all:: resource-cert-samples-regen

all-tests:: relaxng

all-tests:: parse-test

resource-cert-samples-regen: resource-cert-samples/.stamp
	cd resource-cert-samples && make

resource-cert-samples/.stamp: generate-testrepo.py Makefile
	python generate-testrepo.py
	touch $@

TWEAKHTML  := xsltproc --html tweak-doc.xsl
#HTML2TEXT := w3m  -dump -T text/html
HTML2TEXT  := lynx -dump -nolist -force_html /dev/stdin

dox doxygen:
	cd rpki && TZ='' doxygen
	${TWEAKHTML} rpki/html/Installation.html | ${HTML2TEXT} >INSTALLATION
	${TWEAKHTML} rpki/html/Operation.html    | ${HTML2TEXT} >OPERATION

doc:: dox

tags:
	find . -type f -name '*.py' ! -name relaxng.py | etags -

all:: rpki/relaxng.py

rpki/relaxng.py: make-relaxng.py
	python make-relaxng.py >$@.tmp
	mv $@.tmp $@

pdf: rpkid.pdf irdbd.pdf

doc:: pdf

# all-tests:: all; sh -x rootd.sh run

test all-tests:: all
	python testbed.py -y testbed.1.yaml

all-tests:: all
	python testbed.py -y testbed.2.yaml
