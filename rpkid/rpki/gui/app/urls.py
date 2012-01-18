# $Id$
"""
Copyright (C) 2010, 2011  SPARTA, Inc. dba Cobham Analytic Solutions
Copyright (C) 2012  SPARTA, Inc. a Parsons Company

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
from rpki.gui.app import views

urlpatterns = patterns('',
    (r'^$', views.dashboard),
    (r'^conf/export$', views.conf_export),
    (r'^conf/list$', views.conf_list),
    (r'^conf/select$', views.conf_select),
    (r'^parent/$', views.parent_list),
    (r'^parent/(?P<pk>\d+)$', views.parent_view),
    (r'^parent/(?P<pk>\d+)/delete$', views.parent_delete),
    (r'^child/$', views.child_list),
    (r'^child/(?P<pk>\d+)$', views.child_view),
    (r'^child/(?P<pk>\d+)/add_asn/$', views.child_add_asn),
    (r'^child/(?P<pk>\d+)/add_address/$', views.child_add_address),
    (r'^child/(?P<pk>\d+)/delete$', views.child_delete),
    (r'^child/(?P<pk>\d+)/edit$', views.child_edit),
    (r'^child/(?P<pk>\d+)/export$', views.export_child_response),
    (r'^child/(?P<pk>\d+)/export_repo$', views.export_child_repo_response),
    (r'^child/(?P<pk>\d+)/destroy$', views.destroy_handle),
    (r'^gbr/$', views.ghostbusters_list),
    (r'^gbr/create$', views.ghostbuster_create),
    (r'^gbr/(?P<pk>\d+)$', views.ghostbuster_view),
    (r'^gbr/(?P<pk>\d+)/edit$', views.ghostbuster_edit),
    (r'^gbr/(?P<pk>\d+)/delete$', views.ghostbuster_delete),
    (r'^refresh$', views.refresh),
    (r'^roa/$', views.roa_list),
    (r'^roa/(?P<pk>\d+)/$', views.roa_detail),
    (r'^roa/(?P<pk>\d+)/delete$', views.roa_delete),
    (r'^routes/$', views.route_view),
    (r'^import_child$', views.import_child),
    (r'^import_parent$', views.import_parent),
    (r'^import_pubclient$', views.import_pubclient),
    (r'^import_repository$', views.import_repository),
    (r'^child_wizard$', views.child_wizard),
    (r'^update_bpki', views.update_bpki),
)

# vim:sw=4 ts=8 expandtab
