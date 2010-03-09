# $Id$

all: myrpki.rng

lint: myrpki.xml myrpki.rng
	xmllint --noout --relaxng myrpki.rng myrpki.xml

myrpki.rng: myrpki.rnc
	trang myrpki.rnc myrpki.rng

parse: myrpki.xml all
	python xml-parse-test.py

clean:
	rm -rf *.xml bpki bpki.myrpki bpki.myirbe test screenlog.* .OpenSSL.whines.unless.I.set.this
	python sql-cleaner.py

format: myrpki.xml
	xmllint --format myrpki.xml

graph:
	find . -name .svn -prune -o -type d -name 'bpki.*' -print | while read b; do python ../scripts/x509-dot.py $$b | dot -T ps2 | ps2pdf - $$b/graph.pdf; done

verify:
	sh verify-bpki.sh

backup:
	python sql-dumper.py
	tar cvvzf test.$$(TZ='' date +%Y.%m.%d.%H.%M.%S).tgz screenlog.* test backup.*.sql
	rm backup.*.sql

test: all
	python yamltest.py
