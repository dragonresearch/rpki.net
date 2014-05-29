# $Id$
#
# Copyright (C) 2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2009--2013  Internet Systems Consortium ("ISC")
# Portions copyright (C) 2006--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL, ISC, AND ARIN DISCLAIM ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL DRL,
# ISC, OR ARIN BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
# OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# pylint: disable=W0622,W0401

from rpki.POW._POW import *
from rpki.POW._POW import __doc__

# Set callback to let POW construct rpki.sundial.datetime objects

from rpki.sundial import datetime as sundial_datetime
customDatetime(sundial_datetime)
del sundial_datetime
