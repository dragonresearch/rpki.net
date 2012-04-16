## @file
# @details
# Doxygen documentation source, expressed as Python comments to make Doxygen happy.
#
# $Id$
#
# Copyright (C) 2009--2012  Internet Systems Consortium ("ISC")
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
# Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
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

## @mainpage RPKI Engine Reference Manual
#
# This collection of Python modules implements an RPKI CA engine.
#
# See http://trac.rpki.net/ for the RPKI tools package documentation.
#
# The documentation you're reading is generated automatically by
# Doxygen from comments and documentation in
# <a href="http://trac.rpki.net/browser/trunk">the code</a>.
#
# At one point this manual also included documentation for the CA
# tools, but that has been integrated into the overall package
# documentation.  This manual is now just the CA tools internals.

## @page sql-schemas SQL database schemas
#
# @li @subpage rpkid-sql "rpkid database schema"
# @li @subpage pubd-sql  "pubd database schema"

## @page rpkid-sql rpkid SQL schema
#
# @image html  rpkid.png "Diagram of rpkid.sql"
# @image latex rpkid.eps "Diagram of rpkid.sql" height=\textheight
#
# @verbinclude rpkid.sql

## @page pubd-sql pubd SQL Schema
#
# @image html  pubd.png "Diagram of pubd.sql"
# @image latex pubd.eps "Diagram of pubd.sql" width=\textwidth
#
# @verbinclude pubd.sql

# Local Variables:
# mode:python
# compile-command: "cd ../.. && ./config.status && cd rpkid && make docs"
# End:
