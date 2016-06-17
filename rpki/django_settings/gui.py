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
This module contains GUI-specific configuration settings for Django libraries.
"""

# Pull in the irdb configuration, which in turn pulls in the common configuration.

from .irdb import *                     # pylint: disable=W0401,W0614

__version__ = "$Id$"

import socket

# GUI uses the IRDB database configuration, so we don't need to set
# anything here.

# Where to put static files.
STATIC_ROOT = rpki.autoconf.datarootdir + "/rpki/media"

# Must end with a slash!
STATIC_URL = "/media/"

LOGGING = {
    "version": 1,
    "formatters": {
        "verbose": {
            # see http://docs.python.org/2.7/library/logging.html#logging.LogRecord
            "format": "%(levelname)s %(asctime)s %(name)s %(message)s"
        },
    },
    "handlers": {
        "stderr": {
            "class": "logging.StreamHandler",
            "level": "DEBUG",
            "formatter": "verbose",
        },
    },
    "loggers": {
        # override default behavior to avoid emailing, and send it to stderr
        "django.request": {
            "level": 'ERROR',
            "handlers": ["stderr"],
            "propagate": False,
        },
        # override default behavior to avoid emailing, and send it to stderr
        "django.security": {
            "level": 'ERROR',
            "handlers": ["stderr"],
            "propagate": False,
        },
        "rpki.gui": {
            "level": cfg.get('log-level', 'WARNING', section='web_portal'),
            "handlers": ["stderr"],
        },
    },
}

def select_tz():
    "Find a supported timezone that looks like UTC"
    for tz in ("UTC", "GMT", "Etc/UTC", "Etc/GMT"):
        if os.path.exists("/usr/share/zoneinfo/" + tz):
            return tz
    # Can't determine the proper timezone, fall back to UTC and let Django
    # report the error to the user.
    return "UTC"

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# If running in a Windows environment this must be set to the same as your
# system time zone.
TIME_ZONE = select_tz()

# See https://docs.djangoproject.com/en/1.5/ref/settings/#allowed-hosts
# for details on why you might need this.
def get_allowed_hosts():
    allowed_hosts = set(cfg.multiget("allowed-hosts", section = "web_portal"))
    allowed_hosts.add(socket.getfqdn())
    allowed_hosts.add("127.0.0.1")
    allowed_hosts.add("::1")
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

DOWNLOAD_DIRECTORY = cfg.get("download-directory", "/var/tmp", section = "web_portal")

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    "django.template.loaders.filesystem.Loader",
    "django.template.loaders.app_directories.Loader",
    "django.template.loaders.eggs.Loader"
)

MIDDLEWARE_CLASSES = (
    "django.middleware.common.CommonMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware"
)

ROOT_URLCONF = "rpki.gui.urls"

INSTALLED_APPS.extend((
    "django.contrib.auth",
    #"django.contrib.admin",
    #"django.contrib.admindocs",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.staticfiles",
    "rpki.gui.app",
    "rpki.gui.gui_rpki_cache",
    "rpki.gui.routeview",
    "rpki.rcynicdb"
))

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
    from local_settings import *        # pylint: disable=W0401,F0401
except ImportError:
    pass
