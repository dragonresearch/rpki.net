# $Id$

all: samples schemas

samples: left-right-protocol-samples/.stamp

left-right-protocol-samples/.stamp: left-right-protocol-samples.xsl ../docs/left-right-xml
	xsltproc left-right-protocol-samples.xsl ../docs/left-right-xml
	touch $@

schemas: left-right-schema.rng up-down-medium-schema.rng up-down-schema.rng

.rnc.rng:
	trang $< $@

.SUFFIXES: .rnc .rng

test: all
	python xml-parse-test.py
