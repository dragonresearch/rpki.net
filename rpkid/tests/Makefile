# $Id$

all: protocol-samples

clean:
	rm -rf testbed.dir left-right-protocol-samples/*.xml publication-protocol-samples/*.xml

protocol-samples: left-right-protocol-samples/.stamp publication-protocol-samples/.stamp

left-right-protocol-samples/.stamp: left-right-protocol-samples.xml split-protocol-samples.xsl 
	rm -f left-right-protocol-samples/*.xml
	xsltproc --stringparam dir left-right-protocol-samples split-protocol-samples.xsl left-right-protocol-samples.xml
	touch $@

publication-protocol-samples/.stamp: publication-protocol-samples.xml split-protocol-samples.xsl 
	rm -f publication-protocol-samples/*.xml
	xsltproc --stringparam dir publication-protocol-samples split-protocol-samples.xsl publication-protocol-samples.xml
	touch $@

parse-test: protocol-samples
	python xml-parse-test.py

all-tests:: parse-test

all-tests:: 
	python testbed.py -y testbed.1.yaml

all-tests::
	python testbed.py -y testbed.2.yaml

test all-tests::
	python testbed.py -y testbed.3.yaml

all-tests::
	python testbed.py -y testbed.4.yaml

all-tests::
	python testbed.py -y testbed.5.yaml

test all-tests::
	python testbed.py -y testbed.6.yaml

all-tests::
	python testbed.py -y testbed.7.yaml
