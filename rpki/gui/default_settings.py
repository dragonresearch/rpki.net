"""
This module contains static configuration settings for the web portal.
"""

__version__ = '$Id$'

import os
import random
import string
import socket

import rpki.config
import rpki.autoconf

# Where to put static files.
STATIC_ROOT = rpki.autoconf.datarootdir + '/rpki/media'

# Must end with a slash!
STATIC_URL = '/media/'

# Where to email server errors.
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
            'level': 'WARNING',
            'handlers': ['stderr'],
        },
    },
}

# Load the SQL authentication bits from the system rpki.conf.
rpki_config = rpki.config.parser(section='web_portal')

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': rpki_config.get('sql-database'),
        'USER': rpki_config.get('sql-username'),
        'PASSWORD': rpki_config.get('sql-password'),

        # Ensure the default storage engine is InnoDB since we need
        # foreign key support.  The Django documentation suggests
        # removing this after the syncdb is performed as an optimization,
        # but there isn't an easy way to do this automatically.

        'OPTIONS': {
            'init_command': 'SET storage_engine=INNODB',
        }
    }
}


def select_tz():
    "Find a supported timezone that looks like UTC"
    for tz in ('UTC', 'GMT', 'Etc/UTC', 'Etc/GMT'):
        if os.path.exists('/usr/share/zoneinfo/' + tz):
            return tz
    # Can't determine the proper timezone, fall back to UTC and let Django
    # report the error to the user.
    return 'UTC'

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# If running in a Windows environment this must be set to the same as your
# system time zone.
TIME_ZONE = select_tz()

def get_secret_key():
    """Retrieve the secret-key value from rpki.conf or generate a random value
    if it is not present."""
    d = string.letters + string.digits
    val = ''.join([random.choice(d) for _ in range(50)])
    return rpki_config.get('secret-key', val)

# Make this unique, and don't share it with anybody.
SECRET_KEY = get_secret_key()

# See https://docs.djangoproject.com/en/1.5/ref/settings/#allowed-hosts
# for details on why you might need this.
def get_allowed_hosts():
    allowed_hosts = set(rpki_config.multiget("allowed-hosts"))
    allowed_hosts.add(socket.getfqdn())
    try:
        import netifaces
        for interface in netifaces.interfaces():
            addresses = netifaces.ifaddresses(interface)
            for af in (netifaces.AF_INET, netifaces.AF_INET6):
                if af in addresses:
                    for address in addresses[af]:
                        if "addr" in address:
                            allowed_hosts.add(address["addr"])
    except ImportError:
        pass
    return list(allowed_hosts)

ALLOWED_HOSTS = get_allowed_hosts()

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
    'django.template.loaders.eggs.Loader'
)

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware'
)

ROOT_URLCONF = 'rpki.gui.urls'

INSTALLED_APPS = (
    'django.contrib.auth',
    #'django.contrib.admin',
    #'django.contrib.admindocs',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.staticfiles',
    'rpki.irdb',
    'rpki.gui.app',
    'rpki.gui.cacheview',
    'rpki.gui.routeview',
    'south',
)

TEMPLATE_CONTEXT_PROCESSORS = (
    "django.contrib.auth.context_processors.auth",
    "django.core.context_processors.debug",
    "django.core.context_processors.i18n",
    "django.core.context_processors.media",
    "django.contrib.messages.context_processors.messages",
    "django.core.context_processors.request",
    "django.core.context_processors.static"
)

# Allow local site to override any setting above -- but if there's
# anything that local sites routinely need to modify, please consider
# putting that configuration into rpki.conf and just adding code here
# to read that configuration.
try:
    from local_settings import *
except:
    pass
