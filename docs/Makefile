# $Id$

all: rpki-db-schema.pdf sample-irdb.pdf repository-engine-objects.pdf bpki.pdf

bpki.pdf: bpki-symmetric.pdf bpki-asymmetric.pdf

.SUFFIXES: .pdf .sql .dot .tex

.sql.pdf:
	sh ../scripts/graphviz-sql.sh $<

.dot.pdf:
	dot -Tps2 $< | ps2pdf - $@

.tex.pdf:
	pdflatex $<
	pdflatex $<
	rm -f $*.log $*.aux
