# Copyright (C) 2013  SPARTA, Inc. a Parsons Company
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND SPARTA DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL SPARTA BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
This module contains utility functions for use in standalone scripts.
"""

from django.conf import settings

from rpki import config
from rpki import autoconf

__version__ = '$Id$'


def setup():
    """
    Configure Django enough to use the ORM.
    """
    cfg = config.parser(section='web_portal')
    # INSTALLED_APPS doesn't seem necessary so long as you are only accessing
    # existing tables.
    settings.configure(
        DATABASES={
            'default': {
                'ENGINE': 'django.db.backends.mysql',
                'NAME': cfg.get('sql-database'),
                'USER': cfg.get('sql-username'),
                'PASSWORD': cfg.get('sql-password'),
            }
        },
    )
