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

__version__ = '$Id$'


def setup():
    """
    Configure Django enough to use the ORM.
    """

    # In theory we no longer need to call settings.configure, which
    # probably means this whole module can go away soon, but leave
    # breadcrumbs for now.

    if True:
	os.environ.update(DJANGO_SETTINGS_MODULE = "rpki.django_settings")

    else:
	import django
	from rpki import config
	from rpki import autoconf
	from django.conf import settings

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
		},
	    },
	    MIDDLEWARE_CLASSES = (),
	)
	# Can't populate apps if we don't know what they are.  If this
	# explodes with an AppRegistryNotReady exception, the above comment
	# about not needing to set INSTALLED_APPS is no longer true and
	# you'll need to fix that here.
	if False and django.VERSION >= (1, 7):
	    from django.apps import apps
	    apps.populate(settings.INSTALLED_APPS)
