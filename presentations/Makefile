# $Id$

all: repository-engine-objects.pdf bpki.pdf

bpki.pdf: bpki-symmetric.pdf bpki-asymmetric.pdf

.SUFFIXES: .pdf .dot .tex

.dot.pdf:
	dot -Tps2 $< | ps2pdf - $@

.tex.pdf:
	pdflatex $<
	pdflatex $<
	rm -f $*.log $*.aux
