# $Id$

all:: rpki-db-schema.pdf

rpki-db-schema.pdf: rpki-db-schema.sql
	sh ../scripts/graphviz-sql.sh rpki-db-schema.sql

all:: sample-irdb.pdf

sample-irdb.pdf: sample-irdb.sql
	sh ../scripts/graphviz-sql.sh sample-irdb.sql

all:: repository-engine-objects.pdf

repository-engine-objects.pdf: repository-engine-objects.dot
	dot -Tps2 repository-engine-objects.dot | ps2pdf - $@.tmp
	mv $@.tmp $@
