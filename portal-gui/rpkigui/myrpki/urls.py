# $Id$
"""
Copyright (C) 2010  SPARTA, Inc. dba Cobham Analytic Solutions

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
from django.views.generic.list_detail import object_list
from rpkigui.myrpki import views

urlpatterns = patterns('',
    (r'^$', views.dashboard),
#    (r'^conf/add$', views.conf_add),
    (r'^conf/export$', views.conf_export),
    (r'^conf/list$', views.conf_list),
    (r'^conf/select$', views.conf_select),
#    (r'^import/parent$', views.parent_import),
#    (r'^import/child$', views.child_import),
    (r'^parent/(?P<parent_handle>[^/]+)$', views.parent_view),
    (r'^child/(?P<child_handle>[^/]+)$', views.child_view),
#    (r'^parent/(?P<parent_handle>[^/]+)/address$', views.parent_address),
#    (r'^parent/(?P<parent_handle>[^/]+)/asn$', views.parent_asn),
    (r'^address/(?P<pk>\d+)$', views.address_view),
    (r'^address/(?P<pk>\d+)/split$', views.prefix_split_view),
    (r'^address/(?P<pk>\d+)/allocate$', views.prefix_allocate_view),
    (r'^address/(?P<pk>\d+)/roa$', views.prefix_roa_view),
    (r'^address/(?P<pk>\d+)/delete$', views.prefix_delete_view),
    (r'^asn/(?P<pk>\d+)$', views.asn_view),
    (r'^asn/(?P<pk>\d+)/allocate$', views.asn_allocate_view),
    (r'^roa/(?P<pk>\d+)/delete$', views.roa_request_delete_view)
)

# vim:sw=4 ts=8 expandtab
