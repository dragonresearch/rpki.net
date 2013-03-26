"""
This module contains utility functions for use in standalone scripts.
"""

from django.conf import settings

from rpki.config import parser

__version__ = '$Id$'


def setup():
    """
    Configure Django enough to use the ORM.
    """
    cfg = parser(section='web_portal')
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
