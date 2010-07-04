# $Id$

import os
import tempfile
from django.views.generic.create_update import create_object, update_object, \
						delete_object
from django.views.generic.list_detail import object_detail, object_list
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render_to_response
from django.utils.http import urlquote
from django.template import RequestContext
from django.db import IntegrityError
from django import http
from functools import update_wrapper
import models
import forms
import glue
from asnset import asnset

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
                conf = models.Conf.objects.filter(owner=request.user)
            if conf.count() == 1:
                handle = conf[0]
            elif conf.count() == 0:
                return http.HttpResponseRedirect('/myrpki/conf/add')
            else:
                # Should reverse the view for this instead of hardcoding
                # the URL.
                return http.HttpResponseRedirect(
                        '/myrpki/conf/list?next=%s' %
                        urlquote(request.get_full_path()))
            request.session[ 'handle' ] = handle
        return f(request, *args, **kwargs)
    return wrapped_fn

#class handle_required(object):
#    '''A decorator to require picking a configuration.  __call__ is
#    decorated with login_required so that we can be sure that the
#    request has a user.
#
#    We don't support picking the configuration yet -- if multiple
#    configurations match, we redirect to handle_picker, which should
#    allow a staff member to pick any handle.
#    '''
#
#    def __init__(self, f):
#        self.f = f
#        update_wrapper( self, f )
#
#    @login_required
#    def __call__(self, request, *args, **kwargs):
#        if 'handle' not in request.session:
#            conf = models.Conf.objects.all().filter(
#                    owner__in=request.user.groups.all())
#            if conf.count() == 1:
#                handle = conf[ 0 ]
#            elif conf.count() == 0:
#                return http.HttpResponseRedirect('/myrpki/conf/add')
#            else:
#                # Should reverse the view for this instead of hardcoding
#                # the URL.
#                return http.HttpResponseRedirect(
#                        '/myrpki/conf/select?next=%s' %
#                        urlquote(request.get_full_path()))
#            request.session[ 'handle' ] = handle
#        return self.f(request, *args, **kwargs)

def render(template, context, request):
    return render_to_response(template, context,
            context_instance=RequestContext(request))

@handle_required
def dashboard(request):
    '''The user's dashboard.'''
    handle = request.session[ 'handle' ]
    # ... pick out data for the dashboard and return it
    # my parents
    # the resources that my parents have given me
    # the resources that I have accepted from my parents
    # my children
    # the resources that I have given my children
    # my roas

    # get list of ASNs used in my ROAs
    roa_asns = [r.asn for r in handle.roas.all()]
    # get list of unallocated asns
    asns = [o for p in handle.parents.all()
            for c in p.resources.all()
            for o in c.asn.filter(parent__isnull=True, allocated__isnull=True).exclude(lo__in=roa_asns)
            if (o.hi == o.lo)]

    # get list of address ranges included in ROAs
    roa_addrs = [p for r in handle.roas.all() for p in r.prefix.all()]
    # get list of unallocated address ranges
    ars = [o for p in handle.parents.all()
            for c in p.resources.all()
            for o in c.address_range.filter(parent__isnull=True, allocated__isnull=True)
            if (not o in roa_addrs)]

    return render('myrpki/dashboard.html', { 'conf': handle, 'asns': asns,
        'ars': ars }, request)

#@handle_required
#def cert_add( request ):
#    return create_object( request, form_class=forms.ConfCertForm( request ),
#                          post_save_redirect='/myrpki/cert/' )

#@handle_required
#def cert_view( request, id ):
#    handle = request.session[ 'handle' ]
#    queryset = models.Cert.objects.filter( conf=handle )
#    return object_detail( request, queryset=queryset, object_id=id,
#    				   template_object_name='cert' )
#
#@handle_required
#def cert_list( request ):
#    handle = request.session[ 'handle' ]
#    queryset = models.Cert.objects.filter( conf=handle )
#    return object_list( request, queryset=queryset,
#    				 template_object_name='cert' )
#
#@handle_required
#def cert_edit( request, id ):
#    handle = request.session[ 'handle' ]
#    cert = get_object_or_404( models.Cert, pk=id, conf=handle )
#    return update_object( request, form_class=forms.ConfCertForm( request ),
#			  object_id=id,
#                          post_save_redirect='/myrpki/cert/' )
#
#@handle_required
#def cert_delete( request, id ):
#    handle = request.session[ 'handle' ]
#    cert = get_object_or_404( models.Cert, pk=id, conf=handle )
#    return delete_object( request, model=models.Cert, object_id=id,
#			  post_delete_redirect='/dashboard/' )

#@login_required
#def conf_add(request):
#    '''Allow the user to create a new configuration.'''
#    errors = []
#    if request.method == 'POST':
#        form = forms.AddConfForm(request.POST)
#        if form.is_valid():
#            try:
#                handle = form.cleaned_data['handle']
#                # ensure this user is in the group for this handle
#                grps = request.user.groups.filter(name=handle)
#                if len(grps) == 0:
#                    errors.append(
#                            'You are not in the proper group for that handle.')
#                else:
#                    conf = models.Conf.objects.create(
#                            handle=form.cleaned_data['handle'], owner=grps[0])
#                    conf.save()
#                    glue.form_to_conf(form.cleaned_data)
#                    return http.HttpResponseRedirect('/myrpki/')
#            # data model will ensure the handle is unique
#            except IntegrityError, e:
#                print e
#                errors.append('That handle already exists.')
#        else:
#            errors.append("The form wasn't valid.")
#    else:
#        form = forms.AddConfForm()
#    return render_to_response('myrpki/add_conf.html',
#            { 'form': form, 'errors': errors })

@login_required
def conf_list(request):
    """Allow the user to select a handle."""
    if request.user.is_superuser:
        queryset = models.Conf.objects.all()
    else:
        queryset = models.Conf.objects.filter(owner__in=request.user.groups.all())
    return object_list(request, queryset,
            template_name='myrpki/conf_list.html', template_object_name='conf')

@login_required
def conf_select(request):
    '''Change the handle for the current session.'''
    if not 'handle' in request.GET:
        return http.HttpResponseRedirect('/myrpki/conf/select')
    handle = request.GET['handle']
    next_url = request.GET.get('next', '/myrpki/')
    if next_url == '':
        next_url = '/myrpki/'

    if request.user.is_superuser:
        conf = models.Conf.objects.filter(handle=handle)
    else:
        # since the handle is passed in as a parameter, need to verify that
        # the user is actually in the group
        conf = models.Conf.objects.filter(handle=handle,
                owner__in=request.user.groups.all())
    if conf:
        request.session['handle'] = conf[0]
        return http.HttpResponseRedirect(next_url)

    return http.HttpResponseRedirect('/myrpki/conf/list?next=' + next_url)

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
def parent_import(request):
    handle = request.session['handle'].handle
    errs = []
    if request.method == 'POST':
        form = forms.ImportForm(request.POST, request.FILES)
        if form.is_valid():
            input_file = tempfile.NamedTemporaryFile(delete=False)
            try:
                parent_handle = form.cleaned_data['handle']
                parent = models.Parent(
                        conf=request.session['handle'], handle=parent_handle)
                parent.save()

                input_file.write(request.FILES['xml'].read())
                input_file.close()

                args = ['configure_parent', '--parent_handle=' + parent_handle,
                        input_file.name]
                glue.invoke_rpki(handle, args)

                return http.HttpResponseRedirect('/myrpki/')
            except IntegrityError, e:
                print e
                errs.append('A parent with that handle already exists.')
            finally:
                os.remove(input_file.name)
        else:
            print 'invalid form'
            errs.append('The form was invalid.')
    else:
        form = forms.ImportForm()
    return render('myrpki/xml_import.html', { 'form': form,
        'kind': 'parent', 'post_url': '/myrpki/import/parent',
        'errors': errs }, request)

@handle_required
def parent_view(request, parent_handle):
    """Detail view for a particular parent."""
    handle = request.session['handle']
    parent = get_object_or_404(handle.parents.all(),
            handle__exact=parent_handle)
    return render('myrpki/parent_view.html', { 'parent': parent }, request)

#def parent_resource(request, parent_handle, obj_type, form_type):
#    """Add an resource range to a parent."""
#    handle = request.session['handle']
#    parent = get_object_or_404(handle.parents.all(),
#            handle__exact=parent_handle)
#    if request.method == 'POST':
#        form = form_type(request.POST)
#        if form.is_valid():
#            obj = obj_type(parent).create(
#                    lo=form.cleaned_data['lo'], hi=form.cleaned_data['hi'])
#
#            glue.configure_resources(handle)
#
#            return http.HttpResponseRedirect('/myrpki/parent/' + parent_handle)
#    else:
#        form = form_type()
#    return render('myrpki/parent_resource.html',
#            { 'parent': parent, 'form': form }, request)

#@handle_required
#def parent_address(request, parent_handle):
#    return parent_resource(request, parent_handle,
#            lambda p: p.address_range, forms.AddressRangeForm)

#@handle_required
#def parent_asn(request, parent_handle):
#    return parent_resource(request, parent_handle,
#            lambda p: p.asn, forms.AsnRangeForm)

@handle_required
def child_import(request):
    handle = request.session['handle'].handle
    if request.method == 'POST':
        form = forms.ChildImportForm(request.POST, request.FILES)
        if form.is_valid():
            input_file = tempfile.NamedTemporaryFile(delete=False)
            try:
                child_handle = form.cleaned_data['handle']
                child = models.Child(
                        conf=request.session['handle'], handle=child_handle,
                        validity=form.cleaned_data['validity'])
                child.save()

                input_file.write(request.FILES['xml'].read())
                input_file.close()
                args = ['configure_child', '--child_handle=' + child_handle,
                        input_file.name]
                glue.invoke_rpki(handle, args)

                # send response back to user
                return serve_xml(
                        glue.read_child_response(handle, child_handle),
                        child_handle)
            finally:
                os.remove(input_file.name)
        else:
            print 'invalid form'
    else:
        form = forms.ChildImportForm()
    return render('myrpki/xml_import.html',
            { 'form': form, 'kind': 'child',
                'post_url': '/myrpki/import/child'}, request)

def get_parents_or_404(handle, obj):
    '''Return the Parent object(s) that the given address range derives
    from, or raise a 404 error.'''
    while obj.parent: obj = obj.parent

    cert_set = obj.from_cert.filter(parent__in=handle.parents.all())
    if cert_set.count() == 0:
        raise http.Http404

    return handle.parents.filter(pk__in=[c.parent.pk for c in cert_set])

#def resource_view(request, object_type, form_type, pk, resource_type):
#    '''view/subdivide an address range.'''
#    handle = request.session['handle']
#    obj = get_object_or_404(object_type, pk=pk)
#    # ensure this resource range belongs to a parent of the current conf
#    parent_set = get_parents_or_404(handle, obj)
#    
#    if request.method == 'POST':
#        form = form_type(handle, obj, request.POST)
#        if form.is_valid():
#            if form.cleaned_data['child'] is None:
#                hi = form.cleaned_data['hi']
#                lo = form.cleaned_data['lo']
#                print hi, lo
#                # if a range is given, create a new object
#                if hi and lo:
#                    subobj = object_type.objects.create(
#                        lo=lo, hi=hi, parent=obj, allocated=None)
#                    subobj.save()
#                if obj.allocated:
#                    obj.allocated = None
#                    obj.save()
#            else:
#                obj.allocated = form.cleaned_data['child']
#                obj.save()
#
#            glue.configure_resources(handle)
#    else:
#        form = form_type(handle, obj)
#    return render('myrpki/resource_view.html', { 'addr': obj, 'form': form,
#        'parent': parent_set, 'resource_type': resource_type }, request)

@handle_required
def address_view(request, pk):
    handle = request.session['handle']
    obj = get_object_or_404(models.AddressRange.objects.all(), pk=pk)
    # ensure this resource range belongs to a parent of the current conf
    parent_set = get_parents_or_404(handle, obj)
    
    return render('myrpki/prefix_view.html',
            { 'addr': obj, 'parent': parent_set }, request)

@handle_required
def asn_view(request, pk):
    '''view/subdivide an asn range.'''
    handle = request.session['handle']
    obj = get_object_or_404(models.Asn.objects, pk=pk)
    # ensure this resource range belongs to a parent of the current conf
    parent_set = get_parents_or_404(handle, obj)
    
    return render('myrpki/asn_view.html',
            { 'asn': obj, 'parent': parent_set }, request)

#@handle_required
#def roa_edit(request, pk=None):
#    '''Create or edit a ROA.'''
#
#    handle = request.session['handle']
#
#    if not pk is None:
#        obj = get_object_or_404(models.Roa, pk=pk)
#        if obj.conf != handle:
#            raise http.Http404
#    else:
#        obj = None
#
#    if request.method == 'POST':
#        form = forms.RoaForm(handle, None, None, None, request.POST)
#        if form.is_valid():
#            if not obj:
#                obj = models.Roa(conf=handle, asn=form.cleaned_data['asn'],
#                        comments=form.cleaned_data['comments'], max_len=0)
#            else:
#                obj.asn = form.cleaned_data['asn']
#                obj.comments = form.cleaned_data['comments']
#            obj.save()
#            obj.prefix.clear()
#            obj.prefix.add(*form.cleaned_data['prefix'])
#
#            glue.configure_resources(handle)
#
#            return http.HttpResponseRedirect('/myrpki/')
#    else:
#        asn = obj.asn if obj else None
#        comments = obj.comments if obj else None
#        prefix = [o.pk for o in obj.prefix.all()] if obj else []
#        form = forms.RoaForm(handle, asn, comments, prefix)
#    return render('myrpki/roaform.html', { 'form': form }, request)

@handle_required
def child_view(request, child_handle):
    '''Detail view of child for the currently selected handle.'''
    handle = request.session['handle']
    child = get_object_or_404(handle.children.all(), handle__exact=child_handle)

    return render('myrpki/child_view.html', { 'child': child }, request)

@handle_required
def prefix_split_view(request, pk):
    handle = request.session['handle']
    prefix = get_object_or_404(models.AddressRange.objects, pk=pk)
    # ensure this resource range belongs to a parent of the current conf
    parent_set = get_parents_or_404(handle, prefix)

    if request.method == 'POST':
        form = forms.PrefixSplitForm(prefix, request.POST)
        if form.is_valid():
            obj = models.AddressRange(form.cleaned_data['lo'], form.cleaned_data['hi'], parent=parent)
            obj.save()
            return http.HttpResponseRedirect(obj.get_absolute_url())
    else:
        form = forms.PrefixSplitForm(prefix)

    return render('myrpki/prefix_view.html', { 'form': form,
        'addr': prefix, 'form': form, 'parent': parent_set }, request)

@handle_required
def prefix_allocate_view(request, pk):
    handle = request.session['handle']
    prefix = get_object_or_404(models.AddressRange.objects, pk=pk)
    # ensure this resource range belongs to a parent of the current conf
    parent_set = get_parents_or_404(handle, prefix)

    if request.method == 'POST':
        form = forms.PrefixAllocateForm(None, handle.children.all(), request.POST)
        if form.is_valid():
            prefix.allocated = form.cleaned_data['child']
            prefix.save()
            glue.configure_resources(handle)
            return http.HttpResponseRedirect(prefix.get_absolute_url())
    else:
        form = forms.PrefixAllocateForm(prefix.allocated.pk if prefix.allocated else None,
                handle.children.all())

    return render('myrpki/prefix_view.html', { 'form': form,
        'addr': prefix, 'form': form, 'parent': parent_set }, request)

def common_cert(prefix, prefix_set):
    '''Return true if prefix is derived from the same resource cert
    as all the addresses in prefix_set.'''
    # list of certs for the target prefix
    certs = prefix.from_cert.all()
    # all prefixes will have the same cert, so just check the first one
    prefix_certs = prefix_set[0].from_cert.all()
    # all we need is one match
    for c in certs:
        if c in prefix_certs:
            return True
    return False
       
def update_roas(handle, prefix):
    '''Recompute the required ROAs for the prefix that was changed.'''
    # generate the list of ASNs
    asns = list(asnset(prefix.asns))

    print 'updating roas for %s: asns=%r' % (prefix, asns)

    # remove this prefix from any roa not on the updated list
    for roa in prefix.from_roa.exclude(asn__in=asns):
        print 'removing %s from roa for asn %d' % (prefix, roa.asn)
        roa.prefix.remove(prefix)
        # if the roa is empty, delete it now
        if roa.prefix.all().count() == 0:
            print 'deleting roa for asn %d because it is empty' % (roa.asn,)
            roa.delete()

    for asid in asns:
        for roa in handle.roas.filter(asn=asid):
            # determine if this roa includes prefixes from the same
            # resource cert as the prefix we just changed
            if common_cert(prefix, roa.prefix.all()):
                roa.prefix.add(prefix)
                break
        else:
            # no roa is present for this ASN, create a new one
            print 'creating new roa for asn %d with %s' % (asid, prefix)
            roa = models.Roa.objects.create(asn=asid, conf=handle, active=False)
            roa.save()
            roa.prefix.add(prefix)

@handle_required
def prefix_roa_view(request, pk):
    handle = request.session['handle']
    obj = get_object_or_404(models.AddressRange.objects, pk=pk)
    # ensure this resource range belongs to a parent of the current conf
    parent_set = get_parents_or_404(handle, obj)

    if request.method == 'POST':
        form = forms.PrefixRoaForm(request.POST)
        if form.is_valid():
            obj.asns = form.cleaned_data['asns']
            obj.save()
            update_roas(handle, obj)
            glue.configure_resources(handle)
            return http.HttpResponseRedirect(obj.get_absolute_url())
    else:
        form = forms.PrefixRoaForm(initial={ 'asns': obj.asns })

    return render('myrpki/prefix_view.html', { 'form': form,
        'addr': obj, 'form': form, 'parent': parent_set }, request)

@handle_required
def asn_allocate_view(request, pk):
    handle = request.session['handle']
    obj = get_object_or_404(models.Asn.objects, pk=pk)
    # ensure this resource range belongs to a parent of the current conf
    parent_set = get_parents_or_404(handle, obj)

    if request.method == 'POST':
        form = forms.PrefixAllocateForm(None, handle.children.all(), request.POST)
        if form.is_valid():
            obj.allocated = form.cleaned_data['child']
            obj.save()
            glue.configure_resources(handle)
            return http.HttpResponseRedirect(obj.get_absolute_url())
    else:
        form = forms.PrefixAllocateForm(obj.allocated.pk if obj.allocated else None,
                handle.children.all())

    return render('myrpki/asn_view.html', { 'form': form,
        'asn': obj, 'form': form, 'parent': parent_set }, request)

# vim:sw=4 ts=8 expandtab
