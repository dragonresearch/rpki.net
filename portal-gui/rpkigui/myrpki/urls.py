from django.conf.urls.defaults import *
from django.views.generic.list_detail import object_list
import views

urlpatterns = patterns('',
#    (r'^cert/$', views.cert_list ),
#    (r'^cert/add/$', views.cert_add ),
#    (r'^cert/(?P<id>\d+)/$', views.cert_view ),
#    (r'^cert/(?P<id>\d+)/edit/$', views.cert_edit ),
#    (r'^cert/(?P<id>\d+)/delete/$', views.cert_delete ),
    (r'^$', views.dashboard),
#    (r'^conf/add$', views.conf_add),
    (r'^conf/export$', views.conf_export),
    (r'^conf/list$', views.conf_list),
    (r'^conf/select$', views.conf_select),
    (r'^import/parent$', views.parent_import),
    (r'^import/child$', views.child_import),
    (r'^parent/(?P<parent_handle>[^/]+)$', views.parent_view),
#    (r'^parent/(?P<parent_handle>[^/]+)/address$', views.parent_address),
#    (r'^parent/(?P<parent_handle>[^/]+)/asn$', views.parent_asn),
    (r'^address/(?P<pk>\d+)$', views.address_view),
    (r'^asn/(?P<pk>\d+)$', views.asn_view),
    (r'^roa/$', views.roa_edit ),
    (r'^roa/(?P<pk>\d+)$', views.roa_edit ),
)
