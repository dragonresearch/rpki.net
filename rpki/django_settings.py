# $Id$

# Copyright (C) 2014  Dragon Research Labs ("DRL")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL DRL BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
This module contains configuration settings for Django libraries.

Most of our CA code uses at least the Django ORM; the web interface
uses a lot more of Django.  We also want to handle all normal user
configuration via rpki.conf, so some of the code here is just pulling
settings from rpki.conf and stuffing them into the form Django wants.
"""

__version__ = "$Id$"

import os
import socket

import rpki.config
import rpki.autoconf

# Some configuration, including SQL authorization, comes from rpki.conf.
cfg = rpki.config.parser()


# Do -not- turn on DEBUG here except for short-lived tests, otherwise
# long-running programs like irdbd will eventually run out of memory
# and crash.  This is also why this is controlled by an environment
# variable rather than by an rpki.conf setting: just because we want
# debugging enabled in the GUI doesn't mean we want it in irdb.
#
# If you must enable debugging, you may need to add code that uses
# django.db.reset_queries() to clear the query list manually, but it's
# probably better just to run with debugging disabled, since that's
# the expectation for production code.
#
# https://docs.djangoproject.com/en/dev/faq/models/#why-is-django-leaking-memory

if os.getenv("RPKI_DJANGO_DEBUG") == "yes":
    DEBUG = True


# Database configuration.  This is always enabled, and uses a database
# "router" to handle multiple databases.  We may want to add yet
# another database to hold South's migration tables, to avoid the
# silliness of requiring an IRDB on, eg, a pubd-only server.
#
# We used to set an option to force MySQL to create InnnoDB databases,
# and we used to set HOST and PORT to the null string, but all of
# these are the defaults with recent versions of MySQL and Django, so
# in theory none of them should be necessary.

DATABASES = dict(
    default = dict(ENGINE   = "django.db.backends.mysql",
                   NAME     = cfg.get("sql-database", section = "irdbd"),
                   USER     = cfg.get("sql-username", section = "irdbd"),
                   PASSWORD = cfg.get("sql-password", section = "irdbd")))

if cfg.getboolean("start_rpkid", section = "myrpki"):
    DATABASES.update(
        rpkidb = dict(ENGINE   = "django.db.backends.mysql",
                      NAME     = cfg.get("sql-database", section = "rpkid"),
                      USER     = cfg.get("sql-username", section = "rpkid"),
                      PASSWORD = cfg.get("sql-password", section = "rpkid")))
                                
if cfg.getboolean("start_pubd", section = "myrpki"):
    DATABASES.update(
        pubdb = dict(ENGINE   = "django.db.backends.mysql",
                     NAME     = cfg.get("sql-database", section = "pubd"),
                     USER     = cfg.get("sql-username", section = "pubd"),
                     PASSWORD = cfg.get("sql-password", section = "pubd")))

# ORM database "router" to sort out which apps use which databases.

DATABASE_ROUTERS = ["rpki.db_router.RPKIDBRouter"]

# Figure out which apps we're running -- GUI code below adds many more.

INSTALLED_APPS = ["south"]

if cfg.getboolean("start_irdbd", section = "myrpki"):
    INSTALLED_APPS.append("rpki.irdb")

if cfg.getboolean("start_rpkid", section = "myrpki"):
    INSTALLED_APPS.append("rpki.rpkidb")

if cfg.getboolean("start_pubd", section = "myrpki"):
    INSTALLED_APPS.append("rpki.pubdb")

# That's about it if we just need the ORM, but Django throws a hissy
# fit if SECRET_KEY isn't set, whether we use it for anything or not.
#
# Make this unique, and don't share it with anybody.
if cfg.has_option("secret-key", section = "web_portal"):
    SECRET_KEY = cfg.get("secret-key", section = "web_portal")
else:
    SECRET_KEY = os.urandom(66).encode("hex")


# If we're the GUI (or a program like rpki-manage that might be
# configuring the GUI) we need a lot of other stuff, so check for an
# environment variable that rpki.wsgi and rpki-manage set for us.

if os.getenv("RPKI_GUI_ENABLE") == "yes":

    # Where to put static files.
    STATIC_ROOT = rpki.autoconf.datarootdir + "/rpki/media"

    # Must end with a slash!
    STATIC_URL = "/media/"

    # Where to email server errors.
    ADMINS = (("Administrator", "root@localhost"),)

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
            "mail_admins": {
                "level": "ERROR",
                "class": "django.utils.log.AdminEmailHandler",
            },
        },
        "loggers": {
            "django": {
                "level": "ERROR",
                "handlers": ["stderr", "mail_admins"],
            },
            "rpki.gui": {
                "level": "WARNING",
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
        "rpki.gui.cacheview",
        "rpki.gui.routeview",
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

# End of GUI-specific settings.


# Allow local site to override any setting above -- but if there's
# anything that local sites routinely need to modify, please consider
# putting that configuration into rpki.conf and just adding code here
# to read that configuration.
try:
    from local_settings import *
except:
    pass
