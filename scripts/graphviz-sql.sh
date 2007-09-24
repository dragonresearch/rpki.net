#!/bin/sh -
# $Id$
#
# This uses the SQL::Translator package (aka "SQL Fairy") to parse
# an SQL schema and graph the result via GraphViz.
#
# SQL::Translator appears to be pretty good at analyzing SQL, but is
# badly confused about how to format record labels in the "dot"
# language.  Simplest solution for now is just to whack sqlt-graph's
# broken output into shape, in the long run I should send the author a
# patch.

for i in *.sql
do
  sqlt-graph --db MySQL --output-type canon --show-datatypes --show-constraints $i |
  perl -0777 -pe '
    s/\\\n/ /g;
    s/  +/ /g;
    s/\\\|/|/g;
    s/\\{([a-z0-9_]+)\|/${1}|{/gi;
    s/-\\ +//g;
    s/\\ \\l/|/g;
    s/\|\\l \\}/}/g;
    s/\|\\}/}/g;
    s/{\n/{\n\tedge [arrowtail=none, arrowhead=crow];\n/;
  ' |
  tee ${i%.sql}.dot |
  dot -Tps2 |
  ps2pdf - ${i%.dot}.pdf
done
