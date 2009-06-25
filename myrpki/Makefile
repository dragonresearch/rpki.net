# $Id$

all: myrpki.xml lint parse


myrpki.xml: myrpki.py asns.csv prefixes.csv roas.csv validity.csv
	python myrpki.py

lint: myrpki.xml myrpki.rng
	xmllint --noout --relaxng myrpki.rng myrpki.xml

myrpki.rng: myrpki.rnc
	trang myrpki.rnc myrpki.rng

parse: myrpki.xml myrpki.rng
	python xml-parse-test.py

clean:
	rm -f *.xml *.pem
