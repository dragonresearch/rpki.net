# Copyright (C) 2011  SPARTA, Inc. dba Cobham Analytic Solutions
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

__version__ = '$Id$'

from django.conf.urls import patterns, url
from rpki.gui.cacheview.views import (CertDetailView, RoaDetailView,
                                      GhostbusterDetailView)

urlpatterns = patterns('',
    url(r'^search$', 'rpki.gui.cacheview.views.search_view',
        name='res-search'),
    url(r'^cert/(?P<pk>[^/]+)$', CertDetailView.as_view(), name='cert-detail'),
    url(r'^gbr/(?P<pk>[^/]+)$', GhostbusterDetailView.as_view(),
        name='ghostbuster-detail'),
    url(r'^roa/(?P<pk>[^/]+)$', RoaDetailView.as_view(), name='roa-detail'),
    (r'^$', 'rpki.gui.cacheview.views.global_summary'),
)

# vim:sw=4 ts=8 expandtab
