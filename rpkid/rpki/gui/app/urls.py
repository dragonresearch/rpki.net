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

urlpatterns = patterns('',
    (r'^$', views.dashboard),
    (r'^conf/export$', views.conf_export),
    (r'^conf/list$', views.conf_list),
    (r'^conf/select$', views.conf_select),
    (r'^parent/$', views.parent_list),
    (r'^parent/import$', views.parent_import),
    (r'^parent/(?P<pk>\d+)$', views.parent_detail),
    (r'^parent/(?P<pk>\d+)/delete$', views.parent_delete),
    (r'^parent/(?P<pk>\d+)/export$', views.parent_export),
    (r'^child/$', views.child_list),
    (r'^child/import$', views.child_import),
    (r'^child/(?P<pk>\d+)$', views.child_view),
    (r'^child/(?P<pk>\d+)/add_asn/$', views.child_add_asn),
    (r'^child/(?P<pk>\d+)/add_address/$', views.child_add_address),
    (r'^child/(?P<pk>\d+)/delete$', views.child_delete),
    (r'^child/(?P<pk>\d+)/edit$', views.child_edit),
    (r'^child/(?P<pk>\d+)/export$', views.child_response),
    (r'^child/(?P<pk>\d+)/destroy$', views.destroy_handle),
    (r'^gbr/$', views.ghostbuster_list),
    (r'^gbr/create$', views.ghostbuster_create),
    (r'^gbr/(?P<pk>\d+)$', views.ghostbuster_view),
    (r'^gbr/(?P<pk>\d+)/edit$', views.ghostbuster_edit),
    (r'^gbr/(?P<pk>\d+)/delete$', views.ghostbuster_delete),
    (r'^refresh$', views.refresh),
    (r'^client/$', views.client_list),
    (r'^client/import$', views.client_import),
    (r'^client/(?P<pk>\d+)$', views.client_detail),
    (r'^client/(?P<pk>\d+)/delete$', views.client_delete),
    (r'^client/(?P<pk>\d+)/export$', views.client_export),
    (r'^repo/$', views.repository_list),
    (r'^repo/import$', views.repository_import),
    (r'^repo/(?P<pk>\d+)$', views.repository_detail),
    (r'^repo/(?P<pk>\d+)/delete$', views.repository_delete),
    (r'^roa/$', views.roa_list),
    (r'^roa/create$', views.roa_create),
    (r'^roa/confirm$', views.roa_create_confirm),
    (r'^roa/(?P<pk>\d+)$', views.roa_detail),
    (r'^roa/(?P<pk>\d+)/delete$', views.roa_delete),
    (r'^routes/$', views.route_view),
    (r'^update_bpki', views.update_bpki),
    (r'^user/$', views.user_list),
    (r'^user/create$', views.user_create),
    (r'^user/(?P<pk>\d+)$', views.user_detail),
    (r'^user/(?P<pk>\d+)/delete$', views.user_delete),
    (r'^user/(?P<pk>\d+)/edit$', views.user_edit),
)
