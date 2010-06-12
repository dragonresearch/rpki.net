from django.views.generic.create_update import create_object, update_object, \
						delete_object
from django.views.generic.list_detail import object_detail, object_list
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render_to_response
from django.utils.http import urlquote
from django.template import RequestContext
from django import http
from functools import update_wrapper
import models
import forms


# For each type of object, we have a detail view, a create view and
# an update view.  We heavily leverage the generic views, only
# adding our own idea of authorization.

class handle_required(object):
    '''A decorator to require picking a configuration.  __call__ is
    decorated with login_required so that we can be sure that the
    request has a user.

    We don't support picking the configuration yet -- if multiple
    configurations match, we redirect to handle_picker, which should
    allow a staff member to pick any handle.
    '''

    def __init__(self, f):
        self.f = f
	update_wrapper( self, f )

    @login_required
    def __call__(self, request, *args, **kwargs):
	if 'handle' not in request.session:
	    conf = models.Conf.objects.all().filter(
					owner__in=request.user.groups.all() )
	    if conf.count() == 1:
		handle = conf[ 0 ]
	    else:
		# Should reverse the view for this instead of hardcoding
		# the URL.
		return http.HttpResponseRedirect( '/handle_picker/?next=%s' %
				urlquote(request.get_full_path()) )
	    request.session[ 'handle' ] = handle
        return self.f(request, *args, **kwargs)

def render( template, context, request ):
    return render_to_response( template, context,
			       context_instance=RequestContext(request) )

@handle_required
def dashboard( request ):
    '''The user's dashboard.'''
    handle = request.session[ 'handle' ]
    # ... pick out data for the dashboard and return it
    # my parents
    # the resources that my parents have given me
    # the reousrces that I have accepted from my parents
    # my children
    # the resources that I have given my children
    # my roas
    return render( 'myrpki/dashboard.html', { 'conf': handle }, request )

@handle_required
def cert_add( request ):
    return create_object( request, form_class=forms.ConfCertForm( request ),
                          post_save_redirect='/myrpki/cert/' )

@handle_required
def cert_view( request, id ):
    handle = request.session[ 'handle' ]
    queryset = models.Cert.objects.filter( conf=handle )
    return object_detail( request, queryset=queryset, object_id=id,
    				   template_object_name='cert' )

@handle_required
def cert_list( request ):
    handle = request.session[ 'handle' ]
    queryset = models.Cert.objects.filter( conf=handle )
    return object_list( request, queryset=queryset,
    				 template_object_name='cert' )

@handle_required
def cert_edit( request, id ):
    handle = request.session[ 'handle' ]
    cert = get_object_or_404( models.Cert, pk=id, conf=handle )
    return update_object( request, form_class=forms.ConfCertForm( request ),
			  object_id=id,
                          post_save_redirect='/myrpki/cert/' )

@handle_required
def cert_delete( request, id ):
    handle = request.session[ 'handle' ]
    cert = get_object_or_404( models.Cert, pk=id, conf=handle )
    return delete_object( request, model=models.Cert, object_id=id,
			  post_delete_redirect='/dashboard/' )
