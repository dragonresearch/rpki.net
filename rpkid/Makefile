# $Id$

all: rpki/relaxng.py

rpki/relaxng.py: ../scripts/make-relaxng.py left-right-schema.rng up-down-schema.rng publication-schema.rng
	python ../scripts/make-relaxng.py >$@.tmp
	mv $@.tmp $@

left-right-schema.rng: left-right-schema.rnc
	trang left-right-schema.rnc left-right-schema.rng

up-down-schema.rng: up-down-schema.rnc
	trang up-down-schema.rnc up-down-schema.rng

publication-schema.rng: publication-schema.rnc
	trang publication-schema.rnc publication-schema.rng

clean:
	find . -type f -name '*.pyc' -delete
	cd tests; $(MAKE) $@

install:
	@true

dont-run-trang:
	touch *.rng

relaxng: left-right-schema.rng up-down-schema.rng publication-schema.rng
	cd tests; $(MAKE) protocol-samples
	xmllint --noout --relaxng  left-right-schema.rng  tests/left-right-protocol-samples/*.xml
	xmllint --noout --relaxng     up-down-schema.rng     tests/up-down-protocol-samples/*.xml
	xmllint --noout --relaxng publication-schema.rng tests/publication-protocol-samples/*.xml

unit-tests: all
	PWD=`pwd`; for i in rpki/*.py; do echo "[$$i]"; PYTHONPATH=$$PWD python $$i; done

all-tests:: unit-tests

all-tests:: relaxng

test all-tests parse-test profile::
	cd tests; $(MAKE) $@


irbe_cli.usage: irbe_cli.py
	python irbe_cli.py --help | sed 's/^/      /' >$@

tags:
	find . -type f \( -name '*.py' -o -name '*.sql' -o -name '*.rnc' \) ! -name relaxng.py | etags -

lint:
	pylint --rcfile ../scripts/pylint.rc rpki/[a-z]*.py irbe_cli.py irdbd.py pubd.py rootd.py rpkid.py tests/smoketest.py tests/testpoke.py ../myrpki/myrpki.py ../myrpki/yamltest.py

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
	for i in Installation Configuration Operation Left-right Publication; do \
		xsltproc --html doc/tweak-doc.xsl doc/html/$$i.html | \
		lynx -dump -nolist -force_html -stdin >doc/$$i; \
	done 2>&1 | \
	awk -f doc/tweak-doc.awk 1>&2
	cd doc/latex && TZ='' ${MAKE} && ln -f refman.pdf ../manual.pdf
	cd doc && tar -cf - html | gzip -9 >manual.tar.gz
