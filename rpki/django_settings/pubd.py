# $Id$

# Copyright (C) 2015-2016  Parsons Government Services ("PARSONS")
# Portions copyright (C) 2014  Dragon Research Labs ("DRL")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND PARSONS AND DRL DISCLAIM ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL
# PARSONS OR DRL BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
# OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
This module contains configuration settings for Django libraries for
the pubd program.
"""

from .common import *                   # pylint: disable=W0401,W0614

__version__ = "$Id$"


# Database configuration.

DATABASES = DatabaseConfigurator().configure(cfg, "pubd")
del DatabaseConfigurator


# Apps.

INSTALLED_APPS =  ["rpki.pubdb"]


# Allow local site to override any setting above -- but if there's
# anything that local sites routinely need to modify, please consider
# putting that configuration into rpki.conf and just adding code here
# to read that configuration.
try:
    from local_settings import *        # pylint: disable=W0401,F0401
except ImportError:
    pass
