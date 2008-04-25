# $Id$

all: rpki-db-schema.pdf sample-irdb.pdf repository-engine-objects.pdf bpki.pdf

.SUFFIXES: .pdf .sql .dot

.sql.pdf:
	sh ../scripts/graphviz-sql.sh $<

.dot.pdf:
	dot -Tps2 $< | ps2pdf - $@
