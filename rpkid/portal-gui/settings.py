# DO NOT EDIT!  Modifications should be placed in local_settings.py

__version__ = '$Id$'

import rpki.config
import os.path
from local_settings import *

DEBUG = True
TEMPLATE_DEBUG = DEBUG

# load the sql authentication bits from the system rpki.conf
rpki_config = rpki.config.parser(section='web_portal')


def get_conv():
    """Add a custom data converter to encode long() as a hex string
    in generated SQL statements.

    This is necessary since Django doesn't support binary field types, and
    assumes all strings are UTF-8.  Without this conversion, the generated SQL
    uses a raw byte string.

    See https://trac.rpki.net/ticket/434

    """
    from MySQLdb.converters import conversions
    import types
    conv = conversions.copy()
    conv[types.LongType] = lambda x, conv: "0x%x" % x
    return conv

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
            'conv': get_conv(),
        }
    }
}


def select_tz():
    "Find a supported timezone that looks like UTC"
    for tz in ('UTC', 'GMT', 'Etc/UTC', 'Etc/GMT'):
        if os.path.exists('/usr/share/zoneinfo/' + tz):
            return tz
    # Can't determine the proper timezone, fall back to UTC and let Django
    # report the error to the user
    return 'UTC'

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# If running in a Windows environment this must be set to the same as your
# system time zone.
TIME_ZONE = select_tz()

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
    'django.template.loaders.eggs.Loader'
)

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',

    # order is important here.  if csrfmidware is put before condgetmidware,
    # the returned pages get truncated for some reason!
    'django.middleware.http.ConditionalGetMiddleware',

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

# must end with a slash!
STATIC_URL = '/media/'
