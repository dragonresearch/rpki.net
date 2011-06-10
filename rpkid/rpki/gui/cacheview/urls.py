# $Id$
"""
Copyright (C) 2011  SPARTA, Inc. dba Cobham Analytic Solutions

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND SPARTA DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL SPARTA BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

from django.conf.urls.defaults import *

urlpatterns = patterns('',
    (r'^query$',              'rpki.gui.cacheview.views.query_view'),
    (r'^search$',             'rpki.gui.cacheview.views.search_view'),
    (r'^as/(?P<pk>[^/]+)$',   'rpki.gui.cacheview.views.asrange_detail'),
    (r'^addr/(?P<pk>[^/]+)$', 'rpki.gui.cacheview.views.addressrange_detail'),
    (r'^cert/(?P<pk>[^/]+)$', 'rpki.gui.cacheview.views.cert_detail'),
    (r'^gbr/(?P<pk>[^/]+)$',  'rpki.gui.cacheview.views.ghostbuster_detail'),
    (r'^roa/(?P<pk>[^/]+)$',  'rpki.gui.cacheview.views.roa_detail'),
)

# vim:sw=4 ts=8 expandtab
