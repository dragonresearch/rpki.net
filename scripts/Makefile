# $Id$

all:: left-right-protocol-samples/.stamp

left-right-protocol-samples/.stamp: left-right-protocol-samples.xsl ../docs/left-right-xml
	xsltproc left-right-protocol-samples.xsl ../docs/left-right-xml
	touch $@

all:: left-right-schema.rng

left-right-schema.rng: left-right-schema.rnc
	trang left-right-schema.rnc left-right-schema.rng

all:: up-down-medium-schema.rng

up-down-medium-schema.rng: up-down-medium-schema.rnc
	trang up-down-medium-schema.rnc up-down-medium-schema.rng

all:: up-down-schema.rng

up-down-schema.rng: up-down-schema.rnc
	trang up-down-schema.rnc up-down-schema.rng

test: all
	python xml-parse-test.py

dont-run-trang:
	touch *.rng

relaxng: left-right-protocol-samples/.stamp
	xmllint --noout --relaxng left-right-schema.rng left-right-protocol-samples/*.xml
	xmllint --noout --relaxng    up-down-schema.rng    up-down-protocol-samples/*.xml

# all:: resource-cert-samples-regen

resource-cert-samples-regen: resource-cert-samples/.stamp
	cd resource-cert-samples && make

resource-cert-samples/.stamp: generate-testrepo.py Makefile
	python generate-testrepo.py
	touch $@

wraptest: all
	(echo '<wrapper>'; python xml-parse-test.py; echo '</wrapper>') | fgrep -v '<?xml' | xmlindent

doxygen:
	cd rpki && doxygen
