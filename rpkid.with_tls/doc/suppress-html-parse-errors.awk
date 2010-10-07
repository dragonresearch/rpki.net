# $Id$
#
# Copyright (C) 2010  Internet Systems Consortium ("ISC")
# 
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.
#
# Doxygen's (X)HTML output is a bit buggy, and libxml2 is picky.
# This script suppresses xsltproc error messages that arise when 
# xlstproc's HTML parser gags on known Doxygen problems that turn out
# not to make any difference to us in this particular context.
#
# The intent is to suppress known harmless messages while letting
# everything else through.  This is intended as a stderr filter.

/HTML parser error : Unexpected end tag : p/ {
  nr = NR;
  next;
}

/^<\/pre><\/div><\/p>/ && nr && NR == nr + 1 {
  next;
}

/^ +\^/ && nr && NR == nr + 2 {
  next;
}

{
  print;
}
