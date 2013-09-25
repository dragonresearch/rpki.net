# Copyright (C) 2010, 2011  SPARTA, Inc. dba Cobham Analytic Solutions
# Copyright (C) 2012, 2013  SPARTA, Inc. a Parsons Company
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

# This is an example wsgi application for use with mod_wsgi and apache.

__version__ = '$Id$'

import sys
import os
import rpki.autoconf

os.environ['DJANGO_SETTINGS_MODULE'] = 'rpki.gui.default_settings'

# Needed for local_settings.py
sys.path.insert(1, rpki.autoconf.sysconfdir + '/rpki')

# Kludge to disable use of setproctitle in rpki.log.  For reasons
# unknown, at least on Ubuntu 12.04 LTS, we dump core with a segment
# violation if we try to load that module in this process, even though
# it works fine in other processes on the same system.  Not yet sure
# what this is about, just disable setproctitle in WSGI case for now.
os.environ['DISABLE_SETPROCTITLE'] = 'yes'

# Kludge to set PYTHON_EGG_CACHE, mostly for FreeBSD where the ports
# system installs Python eggs in their zipped format and expects each
# user application to unpack them into its own egg cache.
if not os.environ.get('PYTHON_EGG_CACHE') and rpki.autoconf.WSGI_PYTHON_EGG_CACHE_DIR:
    os.environ['PYTHON_EGG_CACHE'] = rpki.autoconf.WSGI_PYTHON_EGG_CACHE_DIR

import django.core.handlers.wsgi
application = django.core.handlers.wsgi.WSGIHandler()

# vim:ft=python
