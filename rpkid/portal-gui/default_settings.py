"""
This module contains static configuration settings for the web portal.
"""

__version__ = '$Id$'

# must end with a slash!
STATIC_URL = '/media/'

# where to email server errors
ADMINS = (('Administrator', 'root@localhost'),)

LOGGING = {
    'version': 1,
    'formatters': {
        'verbose': {
            # see http://docs.python.org/2.7/library/logging.html#logging.LogRecord
            'format': '%(levelname)s %(asctime)s %(name)s %(message)s'
        },
    },
    'handlers': {
        'stderr': {
            'class': 'logging.StreamHandler',
            'level': 'DEBUG',
            'formatter': 'verbose',
        },
        'mail_admins': {
            'level': 'ERROR',
            'class': 'django.utils.log.AdminEmailHandler',
        },
    },
    'loggers': {
        'django': {
            'level': 'ERROR',
            'handlers': ['stderr', 'mail_admins'],
        },
        'rpki.gui': {
            'level': 'DEBUG',
            'handlers': ['stderr'],
        },
    },
}
