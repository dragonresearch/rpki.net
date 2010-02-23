from django.conf.urls.defaults import *
from django.views.generic.list_detail import object_list
import views

urlpatterns = patterns('',
    (r'^cert/$', views.cert_list ),
    (r'^cert/add/$', views.cert_add ),
    (r'^cert/(?P<id>\d+)/$', views.cert_view ),
    (r'^cert/(?P<id>\d+)/edit/$', views.cert_edit ),
    (r'^cert/(?P<id>\d+)/delete/$', views.cert_delete ),
)
