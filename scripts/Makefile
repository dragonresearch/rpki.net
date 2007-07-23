# $Id$

all: left-right-protocol-samples/.stamp left-right-schema.rng up-down-medium-schema.rng up-down-schema.rng

left-right-protocol-samples/.stamp: left-right-protocol-samples.xsl ../docs/left-right-xml
	xsltproc left-right-protocol-samples.xsl ../docs/left-right-xml
	touch $@

left-right-schema.rng: left-right-schema.rnc
	trang left-right-schema.rnc left-right-schema.rng

up-down-medium-schema.rng: up-down-medium-schema.rnc
	trang up-down-medium-schema.rnc up-down-medium-schema.rng

up-down-schema.rng: up-down-schema.rnc
	trang up-down-schema.rnc up-down-schema.rng

test: all
	python xml-parse-test.py

dont-run-trang:
	touch *.rng

relaxng: left-right-protocol-samples/.stamp
	xmllint --noout --relaxng left-right-schema.rng left-right-protocol-samples/*.xml
	xmllint --noout --relaxng    up-down-schema.rng    up-down-protocol-samples/*.xml
