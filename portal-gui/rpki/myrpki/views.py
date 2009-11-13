from django.views.generic.create_update import create_object, update_object,
						delete_object
from django.views.generic.list_detail import object_detail
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render_to_response
import models
import forms


# For each type of object, we have a detail view, a create view and
# an update view.  We heavily leverage the generic views, only
# adding our own idea of authorization.

def handle( request ):
    '''If the session has a handle, return the config.  If the user only has
    one config that he can access, return that one; else return None.'''
    if 'handle' in request.session:
	return Conf.objects.get( handle=request.session[ 'handle' ] )
    conf = Conf.objects.all().filter( owner__in=request.user.groups )
    if conf.count() == 1:
	return conf[ 0 ]
    return None

def choose_handle( request ):
    '''The logged-in user can access multiple (or no) handles.
    Ask them to pick which one(s) they want to access.'''
    raise NotImplementedError

@login_required
def dashboard( request ):
    '''The user's dashboard.  If the handle is not specified,
    see what the user has access to based on his groups.  If
    multiple, give him a selector and store the result in the
    session.'''
    handle = handle( request )
    if handle is None:
	return choose_handle( request )
    # ... pick out data for the dashboard and return it
    return render_to_response( 'myrpki/dashboard.html', context={ 'conf': handle } )

@login_required
def cert_add( request ):
    return create_object( request, form_class=forms.CertForm )

@login_required
def cert_edit( request, id ):
    cert = get_object_or_404( models.Cert, pk=id )
    # make sure it is owned by the current handle
    return update_object( request, form_class=forms.CertForm, object_id=id )

@login_required
def cert_delete( request, id ):
    cert = get_object_or_404( models.Cert, pk=id )
    # make sure it is owned by the current handle
    return delete_object( request, model=models.Cert, object_id=id,
			  post_delete_redirect='/dashboard/' )
