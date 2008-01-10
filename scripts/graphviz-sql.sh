#!/bin/sh -
# $Id$

# Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

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
