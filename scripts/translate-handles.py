"""
Translate handles from the ones provided in a database dump into the
ones we use in our testbed.  This has been broken out into a separate
program for two reasons:

- Conversion of some of the RIR data is a very slow process, and it's
  both annoying and unnecessary to run it every time we add a new
  participant to the testbed.

- This handle translation business now has fingers into half a dozen
  scripts, so it needs refactoring in any case, either as a common
  library function or as a separate script.

This program takes a list of .CSV files on its command line, and
rewrites them as needed after performing the translation.

$Id$

Copyright (C) 2010  Internet Systems Consortium ("ISC")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import os, sys, rpki.myrpki

translations = dict((src, dst) for src, dst in rpki.myrpki.csv_reader("translations.csv", columns = 2))

for filename in sys.argv[1:]:

  f = rpki.myrpki.csv_writer(filename)

  for cols in rpki.myrpki.csv_reader(filename):
    if cols[0] in translations:
      cols[0] = translations[cols[0]]
    f.writerow(cols)

  f.close()
