# $Id$

#all:: relatives
#all:: myrpki.xml
#all:: lint
#all:: parse
#all:: graph
all:: load

myrpki.xml: myrpki.py asns.csv children.csv parents.csv prefixes.csv roas.csv
	python myrpki.py

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

load: myrpki.xml schema.py
	python myirbe.py

bpki.myrpki:
	python myirbe.py

clean:
	rm -rf *.xml bpki.myrpki bpki.rpkid bpki.pubd bpki.rootd
	python sql-cleaner.py

format: myrpki.xml
	xmllint --format myrpki.xml

graph:
	for b in  bpki.myrpki bpki.rpkid bpki.pubd bpki.rootd; do python ../scripts/x509-dot.py $$b | dot -T ps2 | ps2pdf - $$b/graph.pdf; done

verify:
	sh verify-bpki.sh
