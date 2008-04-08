# $Id$

all:: left-right-protocol-samples/.stamp

left-right-protocol-samples/.stamp: left-right-protocol-samples.xsl ../docs/left-right-xml
	xsltproc left-right-protocol-samples.xsl ../docs/left-right-xml
	touch $@

all:: left-right-schema.rng

left-right-schema.rng: left-right-schema.rnc
	trang left-right-schema.rnc left-right-schema.rng

all:: up-down-schema.rng

up-down-schema.rng: up-down-schema.rnc
	trang up-down-schema.rnc up-down-schema.rng

dont-run-trang:
	touch *.rng

relaxng: left-right-protocol-samples/.stamp left-right-schema.rng up-down-schema.rng
	xmllint --noout --relaxng left-right-schema.rng left-right-protocol-samples/*.xml
	xmllint --noout --relaxng    up-down-schema.rng    up-down-protocol-samples/*.xml

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
	cd rpki && doxygen
	${TWEAKHTML} rpki/html/Installation.html | ${HTML2TEXT} >INSTALLATION
	${TWEAKHTML} rpki/html/Operation.html    | ${HTML2TEXT} >OPERATION

tags:
	find . -type f -name '*.py' | etags -

all:: rpki/relaxng.py

rpki/relaxng.py: left-right-schema.rng up-down-schema.rng make-relaxng.py
	python make-relaxng.py >$@.tmp
	mv $@.tmp $@

# all-tests:: all; sh -x rootd.sh run

test all-tests:: all
	python testbed.py -y testbed.1.yaml

all-tests:: all
	python testbed.py -y testbed.2.yaml
