# $Id$

all:: myrpki.xml
all:: lint
#all:: parse
all:: load

myrpki.xml: myrpki.py asns.csv prefixes.csv roas.csv validity.csv
	python myrpki.py

lint: myrpki.xml myrpki.rng
	xmllint --noout --relaxng myrpki.rng myrpki.xml

myrpki.rng: myrpki.rnc
	trang myrpki.rnc myrpki.rng

parse: myrpki.xml myrpki.rng
	python xml-parse-test.py

load: myrpki.xml myrpki.rng
	python myirbe.py

clean:
	rm -f *.xml *.pem

relatives: mom.pem dad.pem bro.pem sis.pem

mom.pem dad.pem bro.pem sis.pem:
	openssl req -new -sha256 -x509 -verbose -config myrpki.conf -extensions req_x509_ext -newkey rsa:2048 -nodes -keyout /dev/null -subj CN=$@ -out $@

format: myrpki.xml
	xmllint --format myrpki.xml
