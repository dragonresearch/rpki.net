# $Id$

all: schema.py

lint: myrpki.xml schema.rng
	xmllint --noout --relaxng schema.rng myrpki.xml

schema.rng: schema.rnc
	trang schema.rnc schema.rng

schema.py: schema.rng
	echo >$@ 'import lxml.etree'
	echo >>$@  -n "myrpki = lxml.etree.RelaxNG(lxml.etree.fromstring('''"
	cat >>$@ schema.rng
	echo >>$@ "'''))"

parse: myrpki.xml schema.py
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

test: schema.py
	python yamltest.py
