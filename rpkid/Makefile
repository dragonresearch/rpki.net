# $Id$

all:: left-right-protocol-samples/.stamp

left-right-protocol-samples/.stamp: left-right-protocol-samples.xml split-protocol-samples.xsl 
	rm -f left-right-protocol-samples/*.xml
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
	rm -f publication-protocol-samples/*.xml
	xsltproc --stringparam dir publication-protocol-samples split-protocol-samples.xsl publication-protocol-samples.xml
	touch $@

all:: publication-schema.rng 

rpki/relaxng.py: publication-schema.rng

publication-schema.rng: publication-schema.rnc
	trang publication-schema.rnc publication-schema.rng

clean:
	find . -type f -name '*.pyc' -delete
	rm -rf testbed.dir

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

all-tests:: relaxng

all-tests:: parse-test

irbe_cli.usage: irbe_cli.py
	python irbe_cli.py --help | sed 's/^/      /' >$@

tags:
	find . -type f \( -name '*.py' -o -name '*.sql' -o -name '*.rnc' \) ! -name relaxng.py | etags -

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

all-tests:: all
	python testbed.py -y testbed.7.yaml

# Documentation

doc/irdbd.dot: irdbd.sql
	sh ../scripts/graphviz-sql.sh $? >$@

doc/pubd.dot: pubd.sql
	sh ../scripts/graphviz-sql.sh $? >$@

doc/rpkid.dot: rpkid.sql
	sh ../scripts/graphviz-sql.sh $? >$@

.SUFFIXES: .dot .png .pdf .eps

.dot.pdf:
	dot -Tps2 $? | ps2pdf - $@

.dot.eps:
	dot -o $@ -Teps $?

.dot.png:
	dot -o $@ -Tpng $?

docs:: doc/irdbd.dot doc/pubd.dot doc/rpkid.dot
docs:: doc/irdbd.eps doc/pubd.eps doc/rpkid.eps doc/rpkid-bpki.eps doc/pubd-bpki.eps
docs:: doc/irdbd.png doc/pubd.png doc/rpkid.png doc/rpkid-bpki.png doc/pubd-bpki.png
docs:: doc/irdbd.pdf doc/pubd.pdf doc/rpkid.pdf doc/rpkid-bpki.pdf doc/pubd-bpki.pdf
docs::
	TZ='' doxygen
	cd doc/latex && TZ='' ${MAKE}
	for i in Installation Operation Left-right Publication; do \
		xsltproc --html tweak-doc.xsl doc/html/$$i.html | lynx -dump -nolist -force_html /dev/stdin >doc/$$i; \
	done
	cd doc; ln -f latex/refman.pdf manual.pdf
	cd doc; tar -cf - html | gzip -9 >manual.tar.gz

lint:
	pylint --rcfile ../scripts/pylint.rc rpki/[a-z]*.py cronjob.py cross_certify.py irbe_cli.py irdbd.py pubd.py rootd.py rpkid.py testbed.py testpoke.py
