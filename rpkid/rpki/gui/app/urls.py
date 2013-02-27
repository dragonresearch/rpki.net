# Copyright (C) 2010, 2011  SPARTA, Inc. dba Cobham Analytic Solutions
# Copyright (C) 2012  SPARTA, Inc. a Parsons Company
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

from django.conf.urls.defaults import *
from rpki.gui.app import views

urlpatterns = patterns(
    '',
    (r'^$', views.dashboard),
    (r'^conf/export$', views.conf_export),
    (r'^conf/list$', views.conf_list),
    (r'^conf/select$', views.conf_select),
    (r'^parent/import$', views.parent_import),
    (r'^parent/(?P<pk>\d+)/$', views.parent_detail),
    (r'^parent/(?P<pk>\d+)/delete$', views.parent_delete),
    (r'^parent/(?P<pk>\d+)/export$', views.parent_export),
    (r'^child/import$', views.child_import),
    (r'^child/(?P<pk>\d+)/$', views.child_detail),
    (r'^child/(?P<pk>\d+)/add_address$', views.child_add_prefix),
    (r'^child/(?P<pk>\d+)/add_asn$', views.child_add_asn),
    (r'^child/(?P<pk>\d+)/delete$', views.child_delete),
    (r'^child/(?P<pk>\d+)/edit$', views.child_edit),
    (r'^child/(?P<pk>\d+)/export$', views.child_response),
    url(r'^gbr/create$', views.ghostbuster_create, name='gbr-create'),
    url(r'^gbr/(?P<pk>\d+)/$', views.GhostbusterDetailView.as_view(), name='gbr-detail'),
    url(r'^gbr/(?P<pk>\d+)/edit$', views.ghostbuster_edit, name='gbr-edit'),
    url(r'^gbr/(?P<pk>\d+)/delete$', views.ghostbuster_delete, name='gbr-delete'),
    (r'^refresh$', views.refresh),
    (r'^client/import$', views.client_import),
    (r'^client/$', views.client_list),
    (r'^client/(?P<pk>\d+)/$', views.client_detail),
    (r'^client/(?P<pk>\d+)/delete$', views.client_delete),
    (r'^client/(?P<pk>\d+)/export$', views.client_export),
    (r'^repo/import$', views.repository_import),
    (r'^repo/(?P<pk>\d+)/$', views.repository_detail),
    (r'^repo/(?P<pk>\d+)/delete$', views.repository_delete),
    (r'^resource_holder/$', views.resource_holder_list),
    (r'^resource_holder/create$', views.resource_holder_create),
    (r'^resource_holder/(?P<pk>\d+)/delete$', views.resource_holder_delete),
    (r'^resource_holder/(?P<pk>\d+)/edit$', views.resource_holder_edit),
    (r'^roa/(?P<pk>\d+)/$', views.roa_detail),
    (r'^roa/create$', views.roa_create),
    (r'^roa/create_multi$', views.roa_create_multi),
    (r'^roa/confirm$', views.roa_create_confirm),
    (r'^roa/confirm_multi$', views.roa_create_multi_confirm),
    (r'^roa/(?P<pk>\d+)/delete$', views.roa_delete),
    url(r'^roa/(?P<pk>\d+)/clone$', views.roa_clone, name="roa-clone"),
    (r'^route/$', views.route_view),
    (r'^route/(?P<pk>\d+)/$', views.route_detail),
    (r'^user/$', views.user_list),
    (r'^user/create$', views.user_create),
    (r'^user/(?P<pk>\d+)/delete$', views.user_delete),
    (r'^user/(?P<pk>\d+)/edit$', views.user_edit),
)
