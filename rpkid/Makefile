# $Id$

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
	cd resource-cert-samples && ${MAKE}

resource-cert-samples/.stamp: generate-testrepo.py Makefile
	python generate-testrepo.py
	touch $@

irbe_cli.usage: irbe_cli.py
	python irbe_cli.py --help | sed 's/^/      /' >$@

tags:
	find . -type f -name '*.py' ! -name relaxng.py | etags -

all:: rpki/relaxng.py

rpki/relaxng.py: make-relaxng.py
	python make-relaxng.py >$@.tmp
	mv $@.tmp $@

# all-tests:: all; sh -x rootd.sh run

all-tests:: all
	python testbed.py -y testbed.1.yaml

all-tests:: all
	python testbed.py -y testbed.2.yaml

test all-tests:: all
	python testbed.py -y testbed.3.yaml

all-tests:: all
	python testbed.py -y testbed.4.yaml

all-tests:: all
	python testbed.py -y testbed.5.yaml

test all-tests:: all
	python testbed.py -y testbed.6.yaml

# Documentation

doc/irdbd.dot: irdbd.sql
	sh ../scripts/graphviz-sql.sh $? >$@

doc/pubd.dot: pubd.sql
	sh ../scripts/graphviz-sql.sh $? >$@

doc/rpkid.dot: rpkid.sql
	sh ../scripts/graphviz-sql.sh $? >$@

doc:: doc/irdbd.dot doc/pubd.dot doc/rpkid.dot

doc/irdbd.pdf: doc/irdbd.dot
	dot -Tps2 $? | ps2pdf - $@

doc/pubd.pdf: doc/pubd.dot
	dot -Tps2 $? | ps2pdf - $@

doc/rpkid.pdf: doc/rpkid.dot
	dot -Tps2 $? | ps2pdf - $@

doc:: doc/irdbd.pdf doc/pubd.pdf doc/rpkid.pdf

# Certain invocations of Graphviz by Doxygen whine about fonts.  Not
# clear whose bug this is.  Apparently harmless, so just ignore it.

dox doxygen: irbe_cli.usage doc/irdbd.dot doc/pubd.dot doc/rpkid.dot
	TZ='' doxygen 2>&1 | awk '$$0 != "Error: Could not find/open font"'
	cd doc/latex && TZ='' ${MAKE} >/dev/null 2>&1
	for i in Installation Operation Left-right Publication; do \
		xsltproc --html tweak-doc.xsl doc/html/$$i.html | lynx -dump -nolist -force_html /dev/stdin >doc/$$i; \
	done
	cd doc; ln -f latex/refman.pdf manual.pdf
	cd doc; tar -cf - html | gzip -9 >manual.tar.gz

doc:: dox

lint:
	pylint --rcfile ../scripts/pylint.rc rpki/[a-z]*.py cronjob.py cross_certify.py irbe_cli.py irdbd.py pubd.py rootd.py rpkid.py testbed.py testpoke.py
