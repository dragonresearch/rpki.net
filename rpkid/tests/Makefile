# $Id$

all: protocol-samples

clean:
	rm -rf smoketest.dir left-right-protocol-samples publication-protocol-samples

protocol-samples: left-right-protocol-samples/.stamp publication-protocol-samples/.stamp

left-right-protocol-samples/.stamp: left-right-protocol-samples.xml split-protocol-samples.xsl 
	rm -rf left-right-protocol-samples
	mkdir  left-right-protocol-samples
	xsltproc --param verbose 0 --stringparam dir left-right-protocol-samples split-protocol-samples.xsl left-right-protocol-samples.xml
	touch $@

publication-protocol-samples/.stamp: publication-protocol-samples.xml split-protocol-samples.xsl 
	rm -rf publication-protocol-samples
	mkdir  publication-protocol-samples
	xsltproc --param verbose 0 --stringparam dir publication-protocol-samples split-protocol-samples.xsl publication-protocol-samples.xml
	touch $@

parse-test: protocol-samples
	python xml-parse-test.py

all-tests:: parse-test

all-tests:: 
	python smoketest.py -y smoketest.1.yaml

all-tests::
	python smoketest.py -y smoketest.2.yaml

test all-tests::
	python smoketest.py -y smoketest.3.yaml

all-tests::
	python smoketest.py -y smoketest.4.yaml

all-tests::
	python smoketest.py -y smoketest.5.yaml

test all-tests::
	python smoketest.py -y smoketest.6.yaml

all-tests::
	python smoketest.py -y smoketest.7.yaml

profile: all
	find smoketest.dir -name '*.prof' -delete
	python smoketest.py -y smoketest.2.yaml -p
	for i in smoketest.dir/*.prof; do python -c "import pstats;pstats.Stats('$$i').sort_stats('time').print_stats()"; done
