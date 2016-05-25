# $Id: gui.py 6427 2016-05-07 04:14:02Z sra $

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
This module contains settings for the GUI's auxillary scripts which just need
enough configuration to use the ORM.
"""

# Pull in the irdb configuration, which in turn pulls in the common configuration.

from .irdb import *                     # pylint: disable=W0401,W0614

__version__ = "$Id: gui.py 6427 2016-05-07 04:14:02Z sra $"

INSTALLED_APPS.extend((
    #"django.contrib.contenttypes", # not sure if required for aux scripts?
    "rpki.gui.app",
    "rpki.gui.gui_rpki_cache",
    "rpki.gui.routeview",
    "rpki.rcynicdb"
))

LOGGING_CONFIG = None # we handle logging configuration ourself via rpki.conf

# Allow local site to override any setting above -- but if there's
# anything that local sites routinely need to modify, please consider
# putting that configuration into rpki.conf and just adding code here
# to read that configuration.
try:
    from local_settings import *        # pylint: disable=W0401,F0401
except ImportError:
    pass
