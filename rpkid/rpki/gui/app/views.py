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

from __future__ import with_statement

import email.message, email.utils, mailbox
import os, os.path
import sys, tempfile

from django.contrib.auth.decorators import login_required
from django.contrib import auth
from django.shortcuts import get_object_or_404, render_to_response
from django.utils.http import urlquote
from django.template import RequestContext
from django import http
from django.views.generic.list_detail import object_list, object_detail
from django.views.generic.create_update import delete_object, update_object, create_object
from django.core.urlresolvers import reverse

from rpki.gui.app import models, forms, glue, settings, range_list
from rpki import resource_set
import rpki.irdb
import rpki.exceptions

import rpki.gui.cacheview.models
import rpki.gui.routeview.models

debug = False

def my_login_required(f):
    """
    A version of django.contrib.auth.decorators.login_required
    that will fail instead of redirecting to the login page when
    the user is not logged in.

    For use with the rpkidemo service URLs where we want to detect
    failure to log in.  Otherwise django will return code 200 with
    the login form, and fools rpkidemo.
    """
    def wrapped(request, *args, **kwargs):
        if  not request.user.is_authenticated():
            return http.HttpResponseForbidden()
        return f(request, *args, **kwargs)

    return wrapped

def superuser_required(f):
    "Decorator which returns HttpResponseForbidden if the user does not have superuser permissions."
    @login_required
    def _wrapped(request, *args, **kwargs):
        if not request.user.is_superuser:
            raise http.HttpResponseForbidden()
        return f(request, *args, **kwargs)
    return _wrapped

# For each type of object, we have a detail view, a create view and
# an update view.  We heavily leverage the generic views, only
# adding our own idea of authorization.

def handle_required(f):
    @login_required
    def wrapped_fn(request, *args, **kwargs):
        if 'handle' not in request.session:
            if request.user.is_superuser:
                conf = models.Conf.objects.all()
            else:
                conf = models.Conf.objects.filter(handle=request.user.username)

            if conf.count() == 1:
                request.session['handle'] = conf[0]
            elif conf.count() == 0:
                return render('app/conf_empty.html', {}, request)
            else:
                # Should reverse the view for this instead of hardcoding
                # the URL.
                return http.HttpResponseRedirect(
                        reverse(conf_list) + '?next=' + urlquote(request.get_full_path()))
        return f(request, *args, **kwargs)
    return wrapped_fn

def render(template, context, request):
    return render_to_response(template, context,
            context_instance=RequestContext(request))

@handle_required
def dashboard(request, template_name='app/dashboard.html'):

    conf = request.session['handle']

    used_asns = range_list.RangeList()

    # asns used in my roas
    roa_asns = set((obj.asn for obj in models.ROARequest.objects.filter(issuer=conf)))
    used_asns.extend((resource_set.resource_range_as(asn, asn) for asn in roa_asns))

    # asns given to my children
    child_asns = rpki.irdb.models.ChildASN.objects.filter(child__in=conf.children.all())
    used_asns.extend((resource_set.resource_range_as(obj.start_as, obj.end_as) for obj in child_asns))

    # my received asns
    asns = models.ResourceRangeAS.objects.filter(cert__parent__issuer=conf)
    my_asns = range_list.RangeList([resource_set.resource_range_as(obj.min, obj.max) for obj in asns])

    unused_asns = my_asns.difference(used_asns)

    used_prefixes = range_list.RangeList()
    used_prefixes_v6 = range_list.RangeList()

    # prefixes used in my roas
    for obj in models.ROARequestPrefix.objects.filter(roa_request__issuer=conf, version='IPv4'):
        used_prefixes.append(obj.as_resource_range())

    for obj in models.ROARequestPrefix.objects.filter(roa_request__issuer=conf, version='IPv6'):
        used_prefixes_v6.append(obj.as_resource_range())

    # prefixes given to my children
    for obj in rpki.irdb.models.ChildNet.objects.filter(child__in=conf.children.all(), version='IPv4'):
        used_prefixes.append(obj.as_resource_range())

    for obj in rpki.irdb.models.ChildNet.objects.filter(child__in=conf.children.all(), version='IPv6'):
        used_prefixes_v6.append(obj.as_resource_range())

    # my received prefixes
    prefixes = models.ResourceRangeAddressV4.objects.filter(cert__parent__issuer=conf)
    prefixes_v6 = models.ResourceRangeAddressV6.objects.filter(cert__parent__issuer=conf)
    my_prefixes = range_list.RangeList([obj.as_resource_range() for obj in prefixes])
    my_prefixes_v6 = range_list.RangeList([obj.as_resource_range() for obj in prefixes_v6])

    unused_prefixes = my_prefixes.difference(used_prefixes)
    unused_prefixes_v6 = my_prefixes_v6.difference(used_prefixes_v6)

    return render(template_name, {
        'conf': conf,
        'unused_asns': unused_asns,
        'unused_prefixes': unused_prefixes,
        'unused_prefixes_v6': unused_prefixes_v6,
        'asns': asns,
        'prefixes': prefixes,
        'prefixes_v6': prefixes }, request)

@superuser_required
def conf_list(request):
    """Allow the user to select a handle."""
    queryset = models.Conf.objects.all()
    return object_list(request, queryset,
            template_name='app/conf_list.html', template_object_name='conf', extra_context={ 'select_url' : reverse(conf_select) })

@superuser_required
def conf_select(request):
    '''Change the handle for the current session.'''
    if not 'handle' in request.GET:
        return http.HttpResponseRedirect('/myrpki/conf/select')
    handle = request.GET['handle']
    next_url = request.GET.get('next', reverse(dashboard))
    if next_url == '':
        next_url = reverse(dashboard)
    request.session['handle'] = get_object_or_404(models.Conf, handle=handle)
    return http.HttpResponseRedirect(next_url)

def serve_xml(content, basename):
    resp = http.HttpResponse(content , mimetype='application/xml')
    resp['Content-Disposition'] = 'attachment; filename=%s.xml' % (basename, )
    return resp

@handle_required
def conf_export(request):
    """Return the identity.xml for the current handle."""
    handle = request.session['handle']
    return serve_xml(glue.read_identity(handle.handle), 'identity')

@handle_required
def parent_list(request):
    """List view for parent objects."""
    conf = request.session['handle']
    return object_list(request, queryset=conf.parents.all(), template_name='app/parent_list.html',
            extra_context = { 'page_title': 'Parents' })

@handle_required
def child_list(request):
    """List view for child objects."""
    conf = request.session['handle']
    return object_list(request, queryset=conf.children.all(),
            template_name = 'app/child_list.html',
            extra_context = { 'page_title': 'Children' })

@handle_required
def child_add_resource(request, pk, form_class, unused_list, callback, template_name='app/child_add_resource_form.html'):
    conf = request.session['handle']
    child = models.Child.objects.filter(issuer=conf, pk=pk)
    if request.method == 'POST':
        form = form_class(request.POST, request.FILES)
        if form.is_valid():
            callback(child, form)
            return http.HttpResponseRedirect(child.get_absolute_url())
    else:
        form = form_class()

    return render(template_name, { 'object': child, 'form': form, 'unused': unused_list }, request)

def add_asn_callback(child, form):
    r = resource_set.resource_range_as.parse_str(form.as_range)
    child.asns.create(min=r.min, max=r.max)

def child_add_asn(request, pk):
    return child_add_resource(request, pk, form_class=forms.AddASNForm, callback=add_asn_callback)

def add_address_callback(child, form):
    try:
        r = resource_set.resource_range_ipv4.parse_str(form.prefix)
        family = 4
    except rpki.exceptions.BadIPResource:
        r = resource_set.resource_range_ipv6.parse_str(form.prefix)
        family = 6
    child.address_ranges.create(min=str(r.min), max=str(r.max), family=family)

def child_add_address(request, pk):
    return child_add_resource(request, pk, form_class=forms.AddAddressForm, callback=add_address_callback)

@handle_required
def parent_view(request, pk):
    """Detail view for a particular parent."""
    handle = request.session['handle']
    parent = get_object_or_404(handle.parents.all(), pk=pk)
    return render('app/parent_view.html', { 'parent': parent }, request)

@handle_required
def child_view(request, pk):
    '''Detail view of child for the currently selected handle.'''
    handle = request.session['handle']
    child = get_object_or_404(handle.children.all(), pk=pk)
    return render('app/child_view.html', { 'child': child }, request)

@handle_required
def child_edit(request, pk):
    """Edit the end validity date for a resource handle's child."""
    handle = request.session['handle']
    child = get_object_or_404(handle.children.all(), pk=pk)

    if request.method == 'POST':
        form = forms.ChildForm(request.POST, request.FILES, instance=child)
        if form.is_valid():
            form.save()
            glue.configure_resources(request.META['wsgi.errors'], handle)
            return http.HttpResponseRedirect(child.get_absolute_url())
    else:
        form = forms.ChildForm(instance=child)
        
    return render('app/child_form.html', { 'child': child, 'form': form }, request)

# this is similar to handle_required, except that the handle is given in URL
def handle_or_404(request, handle):
    "ensure the requested handle is available to this user"
    if request.user.is_superuser:
        conf_set = models.Conf.objects.filter(handle=handle)
    else:
        conf_set = models.Conf.objects.filter(owner=request.user, handle=handle)
    if not conf_set:
        raise http.Http404, 'resource handle not found'
    return conf_set[0]

def serve_file(handle, fname, content_type, error_code=404):
    content, mtime = glue.read_file_from_handle(handle, fname)
    resp = http.HttpResponse(content , mimetype=content_type)
    resp['Content-Disposition'] = 'attachment; filename=%s' % (os.path.basename(fname), )
    resp['Last-Modified'] = email.utils.formatdate(mtime, usegmt=True)
    return resp

@my_login_required
def download_csv(request, self_handle, fname):
    conf = handle_or_404(request, self_handle)
    return serve_file(conf.handle, fname + '.csv', 'text/csv')

def download_asns(request, self_handle):
    return download_csv(request, self_handle, 'asns')

def download_roas(request, self_handle):
    return download_csv(request, self_handle, 'roas')

def download_prefixes(request, self_handle):
    return download_csv(request, self_handle, 'prefixes')

def login(request):
    """
    A version of django.contrib.auth.views.login that will return an
    error response when the user/password is bad.  This is needed for
    use with rpkidemo to properly detect errors.  The django login
    view will return 200 with the login page when the login fails,
    which is not desirable when using rpkidemo.
    """
    log = request.META['wsgi.errors']

    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        print >>log, 'login request for user %s' % username
        user = auth.authenticate(username=username, password=password)
        if user is not None and user.is_active:
            auth.login(request, user)
            return http.HttpResponse('<p>login succeeded</p>')
        print >>log, 'failed login attempt for user %s\n' % username
        return http.HttpResponseForbidden('<p>bad username or password</p>')
    else:
        return http.HttpResponse('<p>This should never been seen by a human</p>')

@handle_required
def roa_list(request):
    "Displays a list of ROARequestPrefix objects for the current resource handle."
    log = request.META['wsgi.errors']
    conf = request.session['handle']
    return object_list(request, queryset=models.ROARequestPrefix.objects.filter(roa_request__issuer=conf),
        template_name='app/roa_request_list.html',
        extra_context = { 'page_title': 'ROA Requests' })

@handle_required
def roa_detail(request, pk):
    """Not implemented.  This is a placeholder so that models.ROARequestPrefix.get_absolute_url
    works.  The only reason it exist is so that the /delete URL works."""
    pass

@handle_required
def roa_delete(request, pk):
    """Handles deletion of a single ROARequestPrefix object.

    Uses a form for double confirmation, displaying how the route
    validation status may change as a result."""

    log = request.META['wsgi.errors']
    conf = request.session['handle']
    obj = get_object_or_404(models.ROARequestPrefix.objects, roa_request__issuer=conf, pk=pk)

    if request.method == 'POST':
        roa = obj.roa_request
        obj.delete()
        # if this was the last prefix on the ROA, delete the ROA request
        if not roa.prefixes.exists():
            roa.delete()
        return http.HttpResponseRedirect(reverse(roa_request_list))

    ### Process GET ###

    match = roa_match(obj.as_resource_range())

    roa_pfx = obj.as_roa_prefix()

    pfx = 'prefixes' if isinstance(roa_pfx, resource_set.roa_prefix_ipv4) else 'prefixes_v6'
    args = { '%s__prefix_min' % pfx : roa_pfx.min(),
             '%s__prefix_max' % pfx : roa_pfx.max(),
             '%s__max_length' % pfx : roa_pfx.max_prefixlen }

    # exclude ROAs which seem to match this request and display the result
    routes = []
    for route, roas in match:
        qs = roas.exclude(asid=obj.roa.asn, **args)
        validate_route(route, qs)
        routes.append(route)

    return render('app/roa_request_confirm_delete.html', { 'object': obj,
        'routes': routes }, request)

@handle_required
def ghostbusters_list(request):
    """
    Display a list of all ghostbuster requests for the current Conf.
    """
    conf = request.session['handle']
    qs = models.Ghostbuster.filter(irdb__issuer=conf)

    return object_list(request, queryset=qs,
            template_name='app/ghostbuster_list.html',
            extra_context = { 'page_title': 'Ghostbusters' })

@handle_required
def ghostbuster_view(request, pk):
    """
    Display an individual ghostbuster request.
    """
    conf = request.session['handle']
    qs = models.Ghostbuster.filter(irdb__issuer=conf)

    return object_detail(request, queryset=qs, object_id=pk, template_name='app/ghostbuster_detail.html')

@handle_required
def ghostbuster_delete(request, pk):
    conf = request.session['handle']

    # verify that the object is owned by this conf
    obj = get_object_or_404(models.Ghostbuster, pk=pk, irdb__issuer=conf)

    # modeled loosely on the generic delete_object() view.
    if request.method == 'POST':
        obj.irdb.delete() # should cause a cascade delete of 'obj'
        return http.HttpResponseRedirect(reverse(ghostbusters_list))

    return render('app/ghostbuster_confirm_delete.html', { 'object': obj }, request)

def _ghostbuster_edit(request, obj=None):
    """
    Common code for create/edit.
    """
    conf = request.session['handle']
    form_class = forms.GhostbusterForm(conf.parents.all())
    if request.method == 'POST':
        form = form_class(request.POST, request.FILES, instance=obj)
        if form.is_valid():
            # use commit=False for the creation case, otherwise form.save()
            # will fail due to schema constraint violation because conf is
            # NULL
            obj = form.save(commit=False)
            obj.conf = conf
            obj.save()
            glue.configure_resources(request.META['wsgi.errors'], conf)
            return http.HttpResponseRedirect(obj.get_absolute_url())
    else:
        form = form_class(instance=obj)
    return render('app/ghostbuster_form.html', { 'form': form, 'object': obj }, request)

@handle_required
def ghostbuster_edit(request, pk):
    conf = request.session['handle']

    # verify that the object is owned by this conf
    obj = get_object_or_404(models.Ghostbuster, pk=pk, conf=conf)

    return _ghostbuster_edit(request, obj)

@handle_required
def ghostbuster_create(request):
    return _ghostbuster_edit(request)

@handle_required
def refresh(request):
    "Query rpkid, update the db, and redirect back to the dashboard."
    glue.list_received_resources(request.META['wsgi.errors'], request.session['handle'])
    return http.HttpResponseRedirect(reverse(dashboard))

@handle_required
def import_parent(request):
    conf = request.session['handle']
    log = request.META['wsgi.errors']

    if request.method == 'POST':
        form = forms.ImportParentForm(conf, request.POST, request.FILES)
        if form.is_valid():
            tmpf = tempfile.NamedTemporaryFile(prefix='parent', suffix='.xml', delete=False)
            f = tmpf.name
            tmpf.write(form.cleaned_data['xml'].read())
            tmpf.close()
         
            glue.import_parent(log, conf, form.cleaned_data['handle'], f)

            os.remove(tmpf.name)

            return http.HttpResponseRedirect(reverse(dashboard))
    else:
        form = forms.ImportParentForm(conf)

    return render('app/import_parent_form.html', { 'form': form }, request)

@handle_required
def import_repository(request):
    conf = request.session['handle']
    log = request.META['wsgi.errors']

    if request.method == 'POST':
        form = forms.ImportRepositoryForm(request.POST, request.FILES)
        if form.is_valid():
            tmpf = tempfile.NamedTemporaryFile(prefix='repository', suffix='.xml', delete=False)
            f = tmpf.name
            tmpf.write(form.cleaned_data['xml'].read())
            tmpf.close()
         
            glue.import_repository(log, conf, f)

            os.remove(tmpf.name)

            return http.HttpResponseRedirect(reverse(dashboard))
    else:
        form = forms.ImportRepositoryForm()

    return render('app/import_repository_form.html', { 'form': form }, request)

@handle_required
def import_pubclient(request):
    conf = request.session['handle']
    log = request.META['wsgi.errors']

    if request.method == 'POST':
        form = forms.ImportPubClientForm(request.POST, request.FILES)
        if form.is_valid():
            tmpf = tempfile.NamedTemporaryFile(prefix='pubclient', suffix='.xml', delete=False)
            f = tmpf.name
            tmpf.write(form.cleaned_data['xml'].read())
            tmpf.close()
         
            glue.import_pubclient(log, conf, f)

            os.remove(tmpf.name)

            return http.HttpResponseRedirect(reverse(dashboard))
    else:
        form = forms.ImportPubClientForm()

    return render('app/import_pubclient_form.html', { 'form': form }, request)

@handle_required
def import_child(request):
    """
    Import a repository response.
    """
    conf = request.session['handle']
    log = request.META['wsgi.errors']

    if request.method == 'POST':
        form = forms.ImportChildForm(conf, request.POST, request.FILES)
        if form.is_valid():
            tmpf = tempfile.NamedTemporaryFile(prefix='identity', suffix='.xml', delete=False)
            f = tmpf.name
            tmpf.write(form.cleaned_data['xml'].read())
            tmpf.close()
         
            glue.import_child(log, conf, form.cleaned_data['handle'], f)

            os.remove(tmpf.name)

            return http.HttpResponseRedirect(reverse(dashboard))
    else:
        form = forms.ImportChildForm(conf)

    return render('app/import_child_form.html', { 'form': form }, request)

@login_required
def initialize(request):
    """
    Initialize a new user account.
    """
    if request.method == 'POST':
        form = forms.GenericConfirmationForm(request.POST)
        if form.is_valid():
            glue.initialize_handle(request.META['wsgi.errors'], handle=request.user.username, owner=request.user)
            return http.HttpResponseRedirect(reverse(dashboard))
    else:
        form = forms.GenericConfirmationForm()

    return render('app/initialize_form.html', { 'form': form }, request)

@handle_required
def child_wizard(request):
    """
    Wizard mode to create a new locally hosted child.
    """
    conf = request.session['handle']
    log = request.META['wsgi.errors']
    if not request.user.is_superuser:
        return http.HttpResponseForbidden()

    if request.method == 'POST':
        form = forms.ChildWizardForm(conf, request.POST)
        if form.is_valid():
            glue.create_child(log, conf, form.cleaned_data['handle'])
            return http.HttpResponseRedirect(reverse(dashboard))
    else:
        form = forms.ChildWizardForm(conf)

    return render('app/child_wizard_form.html', { 'form': form }, request)

@handle_required
def export_child_response(request, child_handle):
    """
    Export the XML file containing the output of the configure_child
    to send back to the client.
    """
    conf = request.session['handle']
    log = request.META['wsgi.errors']
    return serve_xml(glue.read_child_response(log, conf, child_handle), child_handle)

@handle_required
def export_child_repo_response(request, child_handle):
    """
    Export the XML file containing the output of the configure_child
    to send back to the client.
    """
    conf = request.session['handle']
    log = request.META['wsgi.errors']
    return serve_xml(glue.read_child_repo_response(log, conf, child_handle), child_handle)

@handle_required
def update_bpki(request):
    conf = request.session['handle']
    log = request.META['wsgi.errors']

    if request.method == 'POST':
        form = forms.GenericConfirmationForm(request.POST, request.FILES)
        if form.is_valid():
            glue.update_bpki(log, conf)
            return http.HttpResponseRedirect(reverse(dashboard))
    else:
        form = forms.GenericConfirmationForm()

    return render('app/update_bpki_form.html', { 'form': form }, request)

@handle_required
def child_delete(request, child_handle):
    conf = request.session['handle']
    log = request.META['wsgi.errors']
    child = get_object_or_404(conf.children, handle__exact=child_handle)

    if request.method == 'POST':
        form = forms.GenericConfirmationForm(request.POST, request.FILES)
        if form.is_valid():
            glue.delete_child(log, conf, child_handle)
            child.delete()
            return http.HttpResponseRedirect(reverse(dashboard))
    else:
        form = forms.GenericConfirmationForm()

    return render('app/child_delete_form.html', { 'form': form , 'object': child }, request)

@handle_required
def parent_delete(request, parent_handle):
    conf = request.session['handle']
    log = request.META['wsgi.errors']
    parent = get_object_or_404(conf.parents, handle__exact=parent_handle)

    if request.method == 'POST':
        form = forms.GenericConfirmationForm(request.POST, request.FILES)
        if form.is_valid():
            glue.delete_parent(log, conf, parent_handle)
            parent.delete()
            return http.HttpResponseRedirect(reverse(dashboard))
    else:
        form = forms.GenericConfirmationForm()

    return render('app/parent_view.html', { 'form': form ,
        'parent': parent, 'submit_label': 'Delete' }, request)

@login_required
def destroy_handle(request, handle):
    """
    Completely remove a hosted resource handle.
    """

    log = request.META['wsgi.errors']

    if not request.user.is_superuser:
        return http.HttpResponseForbidden()

    conf = get_object_or_404(models.Conf, handle=handle)

    if request.method == 'POST':
        form = forms.GenericConfirmationForm(request.POST, request.FILES)
        if form.is_valid():
            glue.destroy_handle(log, handle)
            return render('app/generic_result.html',
                    { 'operation': 'Destroy ' + handle,
                      'result': 'Succeeded' }, request)
    else:
        form = forms.GenericConfirmationForm()

    return render('app/destroy_handle_form.html', { 'form': form ,
        'handle': handle }, request)

def roa_match(rng):
    "Return a list of tuples of matching routes and roas."
    object_accepted = rpki.gui.cacheview.models.ValidationLabel.objects.get(label='object_accepted')

    if isinstance(rng, rpki.resource_set.resource_range_ipv6):
        route_manager = rpki.gui.routeview.models.RouteOriginV6.objects
        pfx = 'prefixes_v6'
    else:
        route_manager = rpki.gui.routeview.models.RouteOrigin.objects
        pfx = 'prefixes'

    rv = []
    for obj in route_manager.filter(prefix_min__gte=rng.min, prefix_max__lte=rng.max):
        # This is a bit of a gross hack, since the foreign keys for v4 and v6
        # prefixes have different names.
        args = { '%s__prefix_min__lte' % pfx: obj.prefix_min,
                 '%s__prefix_max__gte' % pfx: obj.prefix_max }
        roas = rpki.gui.cacheview.models.ROA.objects.filter(
                statuses__status=object_accepted,
                **args)
        rv.append((obj, roas))

    return rv

def validate_route(route, roas):
    """Annotate the route object with its validation status.

    `roas` is a queryset containing ROAs which cover `route`.  """
    pfx = 'prefixes' if isinstance(route, rpki.gui.routeview.models.RouteOrigin) else 'prefixes_v6'
    args = { 'asid': route.asn,
             '%s__prefix_min__lte' % pfx: route.prefix_min,
             '%s__prefix_max__gte' % pfx: route.prefix_max,
             '%s__max_length__gte' % pfx: route.prefixlen() }

    # 2. if the candidate ROA set is empty, end with unknown
    if not roas.exists():
        route.status = 'unknown'
        route.status_label = 'warning'
    # 3. if any candidate roa matches the origin AS and max_length, end with valid
    #
    # AS0 is always invalid.
    elif route.asn != 0 and roas.filter(**args).exists():
        route.status_label = 'success'
        route.status = 'valid'
    # 4. otherwise the route is invalid
    else:
        route.status_label = 'important'
        route.status = 'invalid'

    return route

@handle_required
def route_view(request):
    """
    Display a list of global routing table entries which match resources listed
    in received certificates.
    """

    handle = request.session['handle']
    log = request.META['wsgi.errors']

    # cache the 'object_accepted' value since it will be the same for all ROAs
    object_accepted = rpki.gui.cacheview.models.ValidationLabel.objects.get(label='object_accepted')

    routes = []
    for p in models.AddressRange.objects.filter(from_cert__parent__in=handle.parents.all()):
        r = p.as_resource_range()
        print >>log, 'querying for routes matching %s' % r
        routes.extend([validate_route(*x) for x in roa_match(r)])

    ts = dict((attr['name'], attr['ts']) for attr in models.Timestamp.objects.values())
    return render('app/routes_view.html', { 'routes': routes, 'timestamp': ts }, request)

# vim:sw=4 ts=8 expandtab
