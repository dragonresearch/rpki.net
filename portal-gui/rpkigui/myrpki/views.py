# $Id$

import os
import tempfile

from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render_to_response
from django.utils.http import urlquote
from django.template import RequestContext
from django.db import IntegrityError
from django import http
from django.views.generic.list_detail import object_list

from rpkigui.myrpki import models
from rpkigui.myrpki import forms
from rpkigui.myrpki import glue
from rpkigui.myrpki.misc import str_to_range
from rpkigui.myrpki.asnset import asnset

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

def render(template, context, request):
    return render_to_response(template, context,
            context_instance=RequestContext(request))

def unallocated_resources(handle, roa_asns, roa_prefixes, asns, prefixes):
    child_asns = []
    for a in asns:
        child_asns.extend(o for o in a.children.filter(allocated__isnull=True).exclude(lo__in=roa_asns) if o.hi == o.lo)

    child_prefixes = []
    for p in prefixes:
        child_prefixes.extend(o for o in p.children.filter(allocated__isnull=True, roa_requests__isnull=True))

    if child_asns or child_prefixes:
        x, y = unallocated_resources(handle, roa_asns, roa_prefixes,
                child_asns, child_prefixes)
        return asns + x, prefixes + y
    else:
        return asns, prefixes

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
    # get list of address ranges included in ROAs
    roa_addrs = [p.prefix for r in handle.roas.all() 
                          for p in r.from_roa_request.all()]

    asns=[]
    prefixes=[]
    for p in handle.parents.all():
        for c in p.resources.all():
            asns.extend(c.asn.filter(allocated__isnull=True).exclude(lo__in=roa_asns))
            prefixes.extend(c.address_range.filter(allocated__isnull=True,
                roa_requests__isnull=True))
    asns, prefixes = unallocated_resources(handle, roa_asns, roa_addrs, asns,
            prefixes)

    prefixes.sort(key=lambda x: str_to_range(x.lo, x.hi).min)

    return render('myrpki/dashboard.html', { 'conf': handle, 'asns': asns,
        'ars': prefixes }, request)

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

@handle_required
def child_import(request):
    handle = request.session['handle'].handle
    if request.method == 'POST':
        form = forms.ImportForm(request.POST, request.FILES)
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
        form = forms.ImportForm()
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
            obj = models.AddressRange(lo=form.cleaned_data['lo'],
                    hi=form.cleaned_data['hi'], parent=prefix)
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
        form = forms.PrefixAllocateForm(
                prefix.allocated.pk if prefix.allocated else None,
                handle.children.all())

    return render('myrpki/prefix_view.html', { 'form': form,
        'addr': prefix, 'form': form, 'parent': parent_set }, request)

def add_roa_requests(handle, prefix, asns, max_length):
    for asid in asns:
        req_set = prefix.roa_requests.filter(roa__asn=asid,
                                             max_length=max_length)
        if not req_set:
            # no req is present for this (ASN, prefix, max_length).

            # find all roas with prefixes from the same resource cert
            roa_set = handle.roas.filter(asn=asid,
                from_roa_request__prefix__from_cert__in=prefix.from_cert.all())
            if roa_set:
                roa = roa_set[0]
            else:
                # no roa is present for this ASN, create a new one
                print 'creating new roa for asn %d' % (asid,)
                roa = models.Roa.objects.create(asn=asid, conf=handle,
                        active=False)
                roa.save()

            req = models.RoaRequest.objects.create(prefix=prefix, roa=roa,
                    max_length=max_length)
            req.save()

@handle_required
def prefix_roa_view(request, pk):
    handle = request.session['handle']
    obj = get_object_or_404(models.AddressRange.objects, pk=pk)
    # ensure this resource range belongs to a parent of the current conf
    parent_set = get_parents_or_404(handle, obj)

    if request.method == 'POST':
        form = forms.PrefixRoaForm(obj, request.POST)
        if form.is_valid():
            asns = asnset(form.cleaned_data['asns'])
            add_roa_requests(handle, obj, asns,
                             form.cleaned_data['max_length'])
            glue.configure_resources(handle)
            return http.HttpResponseRedirect(obj.get_absolute_url())
    else:
        form = forms.PrefixRoaForm(obj)

    return render('myrpki/prefix_view.html', { 'form': form,
        'addr': obj, 'form': form, 'parent': parent_set }, request)

@handle_required
def prefix_delete_view(request, pk):
    handle = request.session['handle']
    obj = get_object_or_404(models.AddressRange.objects, pk=pk)
    # ensure this resource range belongs to a parent of the current conf
    parent_set = get_parents_or_404(handle, obj)

    if request.method == 'POST':
        form = forms.PrefixDeleteForm(obj, request.POST)
        if form.is_valid():
            if form.cleaned_data['delete']:
                obj.delete()
                return http.HttpResponseRedirect('/myrpki/')
    else:
        form = forms.PrefixDeleteForm(obj)

    return render('myrpki/prefix_view.html', { 'form': form,
        'addr': obj, 'form': form, 'parent': parent_set }, request)

@handle_required
def roa_request_delete_view(request, pk):
    '''Remove a roa request from a particular prefix.'''
    handle = request.session['handle']
    obj = get_object_or_404(models.RoaRequest.objects, pk=pk)
    prefix = obj.prefix
    # ensure this resource range belongs to a parent of the current conf
    parent_set = get_parents_or_404(handle, prefix)

    roa = obj.roa
    obj.delete()
    if not roa.from_roa_request.all():
        print 'removing empty roa for asn %d' % (roa.asn,)
        roa.delete()

    return http.HttpResponseRedirect(prefix.get_absolute_url())

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
