# Copyright (C) 2010, 2011  SPARTA, Inc. dba Cobham Analytic Solutions
# Copyright (C) 2012, 2014  SPARTA, Inc. a Parsons Company
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
from rpki.gui.app import views

urlpatterns = patterns(
    '',
    (r'^$', 'rpki.gui.app.views.dashboard'),
    url(r'^alert/$', views.AlertListView.as_view(), name='alert-list'),
    url(r'^alert/clear_all$', views.alert_clear_all, name='alert-clear-all'),
    url(r'^alert/(?P<pk>\d+)/$', views.AlertDetailView.as_view(),
        name='alert-detail'),
    url(r'^alert/(?P<pk>\d+)/delete$', views.AlertDeleteView.as_view(),
        name='alert-delete'),
    (r'^conf/export$', 'rpki.gui.app.views.conf_export'),
    (r'^conf/list$', 'rpki.gui.app.views.conf_list'),
    (r'^conf/select$', 'rpki.gui.app.views.conf_select'),
    url(r'^conf/export_asns$', views.export_asns, name='export-asns'),
    url(r'^conf/export_prefixes$', views.export_prefixes, name='export-prefixes'),
    url(r'^conf/import_asns$', views.import_asns, name='import-asns'),
    url(r'^conf/import_prefixes$', views.import_prefixes, name='import-prefixes'),
    (r'^parent/import$', 'rpki.gui.app.views.parent_import'),
    (r'^parent/(?P<pk>\d+)/$', 'rpki.gui.app.views.parent_detail'),
    (r'^parent/(?P<pk>\d+)/delete$', 'rpki.gui.app.views.parent_delete'),
    (r'^parent/(?P<pk>\d+)/export$', 'rpki.gui.app.views.parent_export'),
    (r'^child/import$', 'rpki.gui.app.views.child_import'),
    (r'^child/(?P<pk>\d+)/$', 'rpki.gui.app.views.child_detail'),
    (r'^child/(?P<pk>\d+)/add_address$', 'rpki.gui.app.views.child_add_prefix'),
    (r'^child/(?P<pk>\d+)/add_asn$', 'rpki.gui.app.views.child_add_asn'),
    (r'^child/(?P<pk>\d+)/delete$', 'rpki.gui.app.views.child_delete'),
    (r'^child/(?P<pk>\d+)/edit$', 'rpki.gui.app.views.child_edit'),
    (r'^child/(?P<pk>\d+)/export$', 'rpki.gui.app.views.child_response'),
    url(r'^gbr/create$', views.ghostbuster_create, name='gbr-create'),
    url(r'^gbr/(?P<pk>\d+)/$', views.GhostbusterDetailView.as_view(), name='gbr-detail'),
    url(r'^gbr/(?P<pk>\d+)/edit$', views.ghostbuster_edit, name='gbr-edit'),
    url(r'^gbr/(?P<pk>\d+)/delete$', views.ghostbuster_delete, name='gbr-delete'),
    (r'^refresh$', 'rpki.gui.app.views.refresh'),
    (r'^client/import$', 'rpki.gui.app.views.client_import'),
    (r'^client/$', 'rpki.gui.app.views.client_list'),
    (r'^client/(?P<pk>\d+)/$', 'rpki.gui.app.views.client_detail'),
    (r'^client/(?P<pk>\d+)/delete$', 'rpki.gui.app.views.client_delete'),
    url(r'^client/(?P<pk>\d+)/export$', views.client_export, name='client-export'),
    (r'^repo/import$', 'rpki.gui.app.views.repository_import'),
    (r'^repo/(?P<pk>\d+)/$', 'rpki.gui.app.views.repository_detail'),
    (r'^repo/(?P<pk>\d+)/delete$', 'rpki.gui.app.views.repository_delete'),
    (r'^resource_holder/$', 'rpki.gui.app.views.resource_holder_list'),
    (r'^resource_holder/create$', 'rpki.gui.app.views.resource_holder_create'),
    (r'^resource_holder/(?P<pk>\d+)/delete$', 'rpki.gui.app.views.resource_holder_delete'),
    (r'^resource_holder/(?P<pk>\d+)/edit$', 'rpki.gui.app.views.resource_holder_edit'),
    (r'^roa/(?P<pk>\d+)/$', 'rpki.gui.app.views.roa_detail'),
    (r'^roa/create$', 'rpki.gui.app.views.roa_create'),
    (r'^roa/create_multi$', 'rpki.gui.app.views.roa_create_multi'),
    (r'^roa/confirm$', 'rpki.gui.app.views.roa_create_confirm'),
    (r'^roa/confirm_multi$', 'rpki.gui.app.views.roa_create_multi_confirm'),
    url(r'^roa/export$', views.roa_export, name='roa-export'),
    url(r'^roa/import$', views.roa_import, name='roa-import'),
    (r'^roa/(?P<pk>\d+)/delete$', 'rpki.gui.app.views.roa_delete'),
    url(r'^roa/(?P<pk>\d+)/clone$', views.roa_clone, name="roa-clone"),
    (r'^route/$', 'rpki.gui.app.views.route_view'),
    (r'^route/(?P<pk>\d+)/$', 'rpki.gui.app.views.route_detail'),
    url(r'^route/suggest$', views.route_suggest, name="suggest-roas"),
    url(r'^router/$', views.RouterListView.as_view(), name='router-list'),
    url(r'^router/import$', views.RouterImportView.as_view(), name='router-import'),
    url(r'^router/(?P<pk>\d+)$', views.RouterDetailView.as_view(), name='router-detail'),
    url(r'^router/(?P<pk>\d+)/delete$', views.RouterDeleteView.as_view(), name='router-delete'),
    (r'^user/$', 'rpki.gui.app.views.user_list'),
    (r'^user/create$', 'rpki.gui.app.views.user_create'),
    (r'^user/(?P<pk>\d+)/delete$', 'rpki.gui.app.views.user_delete'),
    (r'^user/(?P<pk>\d+)/edit$', 'rpki.gui.app.views.user_edit'),

    url(r'^user/password/reset/$',
        'django.contrib.auth.views.password_reset',
        #{'post_reset_redirect' : '/user/password/reset/done/'},
        {'extra_context': {'form_title': 'Password Reset'}},
        name="password_reset"),
    url(r'^user/password/reset/done/$',
        'django.contrib.auth.views.password_reset_done',
        name='password_reset_done'),
    url(r'^user/password/reset/(?P<uidb36>[0-9A-Za-z]+)-(?P<token>.+)/$',
        'django.contrib.auth.views.password_reset_confirm',
        #{'post_reset_redirect' : '/user/password/done/'},
        name="password_reset_confirm"),
    url(r'^user/password/done/$',
        'django.contrib.auth.views.password_reset_complete',
        name='password_reset_complete'),
)
