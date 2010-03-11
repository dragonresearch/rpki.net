# $Id$

all: myrpki.rng

relaxng: myrpki.rng
	xmllint --noout --relaxng myrpki.rng `find test -type f -name '*.xml'`

lint: myrpki.xml myrpki.rng
	xmllint --noout --relaxng myrpki.rng myrpki.xml

myrpki.rng: myrpki.rnc
	trang myrpki.rnc myrpki.rng

parse: myrpki.xml all
	python xml-parse-test.py

clean:
	rm -rf *.xml bpki test screenlog.* .OpenSSL.whines.unless.I.set.this
	python sql-cleaner.py

format: myrpki.xml
	xmllint --format myrpki.xml

graph:
	find . -type d -path '*/bpki/*' | while read b; do python ../scripts/x509-dot.py $$b | unflatten -l 8 -f | dot -T ps2 | ps2pdf - $$b/graph.pdf; done

verify:
	sh verify-bpki.sh

backup:
	python sql-dumper.py
	tar cvvzf test.$$(TZ='' date +%Y.%m.%d.%H.%M.%S).tgz screenlog.* test backup.*.sql
	rm backup.*.sql

test: myrpki.rng
	MYRPKI_RNG=`pwd`/myrpki.rng python yamltest.py
