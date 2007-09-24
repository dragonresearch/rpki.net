#!/bin/sh -
# $Id$

# This uses the SQL::Translator package (aka "SQL Fairy") to parse
# an SQL schema and graph the result via GraphViz.
#
# SQL::Translator appears to be pretty good at analyzing SQL.  It's not
# so hot at generating the "dot" language, or maybe it's just that
# the Perl GraphViz module is buggy, but the simplest solution is just
# to whack sqlt-graph's broken output into shape.

# Bugs: this assumes that SQL::Translate always draws edges one->many.

for i in *.sql
do
  sqlt-graph --db MySQL --output-type canon --show-datatypes $i |
  perl -0777 -pe '
    s/\\\n/ /g;
    s/\\{//g;
    s/\\\|-\\ /|{/g;
    s/\\ *\\ *l *-\\ /|/g;
    s/\\ *\\l\\}/}/g;
    s/{\n/{\n\tedge [arrowtail=none, arrowhead=crow];\n/;
  ' |
  tee ${i%.sql}.dot |
  dot -Tps2 |
  ps2pdf - ${i%.dot}.pdf
done
