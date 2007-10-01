#!/bin/sh -
# $Id$
#
# This uses the SQL::Translator package (aka "SQL Fairy") to parse
# a MYSQL schema and diagram the result using GraphViz.
#
# SQL::Translator appears to be pretty good at analyzing SQL, but is
# badly confused about how to format record labels in the "dot"
# language.  I should send the author a patch, but simplest solution
# for now is just to whack sqlt-graph's broken output into shape.
#
# On FreeBSD, SQL Fairy is /usr/ports/databases/p5-SQL-Translator.

for i in "$@"
do
  sqlt-graph --db MySQL --output-type canon --show-datatypes --show-constraints $i |
  perl -0777 -pe '
    s/\\\n//g;
    s/  +/ /g;
    s/\\\|/|/g;
    s/\\{([a-z0-9_]+)\|/${1}|{/gi;
    s/-\\ +//g;
    s/\\ \\l/|/g;
    s/\|\\l \\}/}/g;
    s/\|\\}/}/g;
    s/{\n/{\n\tedge [arrowtail=none, arrowhead=crow];\n/;
  ' |
  dot -Tps2 |
  ps2pdf - ${i%.sql}.pdf
done
