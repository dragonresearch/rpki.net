# $Id$
"""
Copyright (C) 2010, 2011  SPARTA, Inc. dba Cobham Analytic Solutions

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
from rpki.gui.app import views

urlpatterns = patterns('',
    (r'^$', views.dashboard),
    (r'^conf/export$', views.conf_export),
    (r'^conf/list$', views.conf_list),
    (r'^conf/select$', views.conf_select),
    (r'^parent/(?P<parent_handle>[^/]+)$', views.parent_view),
    (r'^child/(?P<child_handle>[^/]+)$', views.child_view),
    (r'^address/(?P<pk>\d+)$', views.address_view),
    (r'^address/(?P<pk>\d+)/split$', views.prefix_split_view),
    (r'^address/(?P<pk>\d+)/allocate$', views.prefix_allocate_view),
    (r'^address/(?P<pk>\d+)/roa$', views.prefix_roa_view),
    (r'^address/(?P<pk>\d+)/delete$', views.prefix_delete_view),
    (r'^asn/(?P<pk>\d+)$', views.asn_view),
    (r'^asn/(?P<pk>\d+)/allocate$', views.asn_allocate_view),
    (r'^gbr/$', views.ghostbusters_list),
    (r'^gbr/create$', views.ghostbuster_create),
    (r'^gbr/(?P<pk>\d+)$', views.ghostbuster_view),
    (r'^gbr/(?P<pk>\d+)/edit$', views.ghostbuster_edit),
    (r'^gbr/(?P<pk>\d+)/delete$', views.ghostbuster_delete),
    (r'^refresh$', views.refresh),
    (r'^roa/(?P<pk>\d+)$', views.roa_view),
    (r'^roareq/(?P<pk>\d+)$', views.roa_request_view),
    (r'^roareq/(?P<pk>\d+)/delete$', views.roa_request_delete_view),
    (r'^demo/down/asns/(?P<self_handle>[^/]+)$', views.download_asns),
    (r'^demo/down/prefixes/(?P<self_handle>[^/]+)$', views.download_prefixes),
    (r'^demo/down/roas/(?P<self_handle>[^/]+)$', views.download_roas),
    (r'^demo/login', views.login),
    (r'^demo/myrpki-xml/(?P<self_handle>[^/]+)$', views.myrpki_xml),
    (r'^demo/parent-request/(?P<self_handle>[^/]+)$', views.parent_request),
    (r'^demo/repository-request/(?P<self_handle>[^/]+)$', views.repository_request),
)

# vim:sw=4 ts=8 expandtab
