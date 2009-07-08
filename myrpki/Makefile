# $Id$

#all:: relatives
#all:: myrpki.xml
#all:: lint
#all:: parse
#all:: graph
all:: load

myrpki.xml: myrpki.py asns.csv prefixes.csv roas.csv validity.csv children.csv parents.csv
	python myrpki.py

lint: myrpki.xml myrpki.rng
	xmllint --noout --relaxng myrpki.rng myrpki.xml

myrpki.rng: myrpki.rnc
	trang myrpki.rnc myrpki.rng

parse: myrpki.xml myrpki.rng
	python xml-parse-test.py

load: myrpki.xml myrpki.rng
	python myirbe.py

bpki.myrpki:
	python myirbe.py

clean:
	rm -rf *.xml bpki.myrpki bpki.rpkid bpki.pubd bpki.rootd
	python sql-cleaner.py

relatives: mom.pem dad.pem bro.pem sis.pem

mom.pem dad.pem bro.pem sis.pem: relatives.conf
	CN=$@ openssl req -new -sha256 -x509 -verbose -config relatives.conf -extensions req_x509_ext -newkey rsa:2048 -nodes -keyout /dev/null -out $@

format: myrpki.xml
	xmllint --format myrpki.xml

graph:
	for b in  bpki.myrpki bpki.rpkid bpki.pubd bpki.rootd; do python ../scripts/x509-dot.py $$b | dot -T ps2 | ps2pdf - $$b/graph.pdf; done

verify:
	sh verify-bpki.sh
