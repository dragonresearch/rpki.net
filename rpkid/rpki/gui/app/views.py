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

"""
This module contains the view functions implementing the web portal
interface.

"""

__version__ = '$Id$'

import os
import os.path
from tempfile import NamedTemporaryFile

from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render_to_response
from django.utils.http import urlquote
from django.template import RequestContext
from django import http
from django.views.generic.list_detail import object_list, object_detail
from django.views.generic.create_update import delete_object
from django.core.urlresolvers import reverse
from django.contrib.auth.models import User

from rpki.irdb import Zookeeper, ChildASN, ChildNet
from rpki.gui.app import models, forms, glue, range_list
from rpki.resource_set import (resource_range_as, resource_range_ipv4,
                               resource_range_ipv6, roa_prefix_ipv4)
from rpki.exceptions import BadIPResource
from rpki import sundial

import rpki.gui.cacheview.models
import rpki.gui.routeview.models


def superuser_required(f):
    """Decorator which returns HttpResponseForbidden if the user does
    not have superuser permissions.

    """
    @login_required
    def _wrapped(request, *args, **kwargs):
        if not request.user.is_superuser:
            raise http.HttpResponseForbidden()
        return f(request, *args, **kwargs)
    return _wrapped


# FIXME  This method is included in Django 1.3 and can be removed when Django
# 1.2 is out of its support window.
def render(request, template, context):
    """
    https://docs.djangoproject.com/en/1.3/topics/http/shortcuts/#render

    """
    return render_to_response(template, context,
            context_instance=RequestContext(request))


def handle_required(f):
    """Decorator for view functions which require the user to be logged in and
    a resource handle selected for the session.

    """
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
                return render(request, 'app/conf_empty.html', {})
            else:
                # Should reverse the view for this instead of hardcoding
                # the URL.
                url = '%s?next=%s' % (reverse(conf_list),
                        urlquote(request.get_full_path()))
                return http.HttpResponseRedirect(url)

        return f(request, *args, **kwargs)
    return wrapped_fn


@handle_required
def generic_import(request, queryset, configure, form_class=None,
                   template_name=None, post_import_redirect=None):
    """
    Generic view function for importing XML files used in the setup
    process.

    queryset
        queryset containing all objects of the type being imported

    configure
        method on Zookeeper to invoke with the imported XML file

    form_class
        specifies the form to use for import.  If None, uses the generic
        forms.ImportForm.

    template_name
        path to the html template to use to render the form.  If None, defaults
        to "app/<model>_import_form.html", where <model> is introspected from
        the "queryset" argument.

    post_import_redirect
        if None (default), the user will be redirected to the detail page for
        the imported object.  Otherwise, the user will be redirected to the
        specified URL.

    """
    conf = request.session['handle']
    if template_name is None:
        template_name = 'app/%s_import_form.html' % queryset.model.__name__.lower()
    if form_class is None:
        form_class = forms.ImportForm
    if request.method == 'POST':
        form = form_class(request.POST, request.FILES)
        if form.is_valid():
            tmpf = NamedTemporaryFile(prefix='import', suffix='.xml',
                                      delete=False)
            tmpf.write(form.cleaned_data['xml'].read())
            tmpf.close()
            z = Zookeeper(handle=conf.handle)
            handle = form.cleaned_data.get('handle')
            # CharField uses an empty string for the empty value, rather than
            # None.  Convert to none in this case, since configure_child/parent
            # expects it.
            if handle == '':
                handle = None
            # configure_repository returns None, so can't use tuple expansion
            # here.  Unpack the tuple below if post_import_redirect is None.
            r = configure(z, tmpf.name, handle)
            # force rpkid run now
            z.synchronize(conf.handle)
            os.remove(tmpf.name)
            if post_import_redirect:
                url = post_import_redirect
            else:
                _, handle = r
                url = queryset.get(issuer=conf,
                                   handle=handle).get_absolute_url()
            return http.HttpResponseRedirect(url)
    else:
        form = form_class()

    return render(request, template_name, {'form': form})


@handle_required
def dashboard(request):
    conf = request.session['handle']

    used_asns = range_list.RangeList()

    # asns used in my roas
    qs = models.ROARequest.objects.filter(issuer=conf)
    roa_asns = set((obj.asn for obj in qs))
    used_asns.extend((resource_range_as(asn, asn) for asn in roa_asns))

    # asns given to my children
    child_asns = ChildASN.objects.filter(child__in=conf.children.all())
    used_asns.extend((resource_range_as(obj.start_as, obj.end_as) for obj in child_asns))

    # my received asns
    asns = models.ResourceRangeAS.objects.filter(cert__parent__issuer=conf)
    my_asns = range_list.RangeList([resource_range_as(obj.min, obj.max) for obj in asns])

    unused_asns = my_asns.difference(used_asns)

    used_prefixes = range_list.RangeList()
    used_prefixes_v6 = range_list.RangeList()

    # prefixes used in my roas
    for obj in models.ROARequestPrefix.objects.filter(roa_request__issuer=conf,
                                                      version='IPv4'):
        used_prefixes.append(obj.as_resource_range())

    for obj in models.ROARequestPrefix.objects.filter(roa_request__issuer=conf,
                                                      version='IPv6'):
        used_prefixes_v6.append(obj.as_resource_range())

    # prefixes given to my children
    for obj in ChildNet.objects.filter(child__in=conf.children.all(),
                                       version='IPv4'):
        used_prefixes.append(obj.as_resource_range())

    for obj in ChildNet.objects.filter(child__in=conf.children.all(),
                                       version='IPv6'):
        used_prefixes_v6.append(obj.as_resource_range())

    # my received prefixes
    prefixes = models.ResourceRangeAddressV4.objects.filter(cert__parent__issuer=conf)
    prefixes_v6 = models.ResourceRangeAddressV6.objects.filter(cert__parent__issuer=conf)
    my_prefixes = range_list.RangeList([obj.as_resource_range() for obj in prefixes])
    my_prefixes_v6 = range_list.RangeList([obj.as_resource_range() for obj in prefixes_v6])

    unused_prefixes = my_prefixes.difference(used_prefixes)
    unused_prefixes_v6 = my_prefixes_v6.difference(used_prefixes_v6)

    return render(request, 'app/dashboard.html', {
        'conf': conf,
        'unused_asns': unused_asns,
        'unused_prefixes': unused_prefixes,
        'unused_prefixes_v6': unused_prefixes_v6,
        'asns': asns,
        'prefixes': prefixes,
        'prefixes_v6': prefixes})


@superuser_required
def conf_list(request):
    """Allow the user to select a handle.

    """
    queryset = models.Conf.objects.all()
    return object_list(request, queryset,
            template_name='app/conf_list.html', template_object_name='conf',
            extra_context={'select_url': reverse(conf_select)})


@superuser_required
def conf_select(request):
    """Change the handle for the current session.

    """
    if not 'handle' in request.GET:
        return http.HttpResponseRedirect('/myrpki/conf/select')
    handle = request.GET['handle']
    next_url = request.GET.get('next', reverse(dashboard))
    if next_url == '':
        next_url = reverse(dashboard)
    request.session['handle'] = get_object_or_404(models.Conf, handle=handle)
    return http.HttpResponseRedirect(next_url)


def serve_xml(content, basename):
    """
    Generate a HttpResponse object with the content type set to XML.

    `content` is a string.

    `basename` is the prefix to specify for the XML filename.

    """
    resp = http.HttpResponse(content, mimetype='application/xml')
    resp['Content-Disposition'] = 'attachment; filename=%s.xml' % (basename, )
    return resp


@handle_required
def conf_export(request):
    """Return the identity.xml for the current handle."""

    conf = request.session['handle']
    z = Zookeeper(handle=conf.handle)
    xml = z.generate_identity()
    return serve_xml(str(xml), '%s.identity' % conf.handle)


@handle_required
def parent_import(request):
    conf = request.session['handle']
    return generic_import(request, conf.parents, Zookeeper.configure_parent)


@handle_required
def parent_list(request):
    """List view for parent objects."""
    conf = request.session['handle']
    return object_list(request, queryset=conf.parents.all(),
                       extra_context={'create_url': reverse(parent_import),
                                      'create_label': 'Import'})


@handle_required
def parent_detail(request, pk):
    """Detail view for a particular parent."""
    conf = request.session['handle']
    return object_detail(request, conf.parents.all(), object_id=pk)


@handle_required
def parent_delete(request, pk):
    conf = request.session['handle']
    get_object_or_404(conf.parents, pk=pk)  # confirm permission
    return delete_object(request, model=models.Parent, object_id=pk,
                         post_delete_redirect=reverse(parent_list),
                         template_name='app/parent_detail.html',
                         extra_context={'confirm_delete': True})


@handle_required
def parent_export(request, pk):
    """Export XML repository request for a given parent."""
    conf = request.session['handle']
    parent = get_object_or_404(conf.parents, pk=pk)
    z = Zookeeper(handle=conf.handle)
    xml = z.generate_repository_request(parent)
    return serve_xml(str(xml), '%s.repository' % parent.handle)


@handle_required
def child_import(request):
    conf = request.session['handle']
    return generic_import(request, conf.children, Zookeeper.configure_child)


@handle_required
def child_list(request):
    """List of children for current user."""
    conf = request.session['handle']
    return object_list(request, queryset=conf.children.all(),
            template_name='app/child_list.html',
            extra_context={
                'create_url': reverse(child_import),
                'create_label': 'Import'})


@handle_required
def child_add_resource(request, pk, form_class, unused_list, callback,
                       template_name='app/child_add_resource_form.html'):
    conf = request.session['handle']
    child = models.Child.objects.get(issuer=conf, pk=pk)
    if request.method == 'POST':
        form = form_class(request.POST, request.FILES)
        if form.is_valid():
            callback(child, form)
            # force rpkid run now
            Zookeeper().synchronize(conf.handle)
            return http.HttpResponseRedirect(child.get_absolute_url())
    else:
        form = form_class()

    return render(request, template_name, {'object': child, 'form': form,
        'unused': unused_list})


def add_asn_callback(child, form):
    asns = form.cleaned_data.get('asns')
    r = resource_range_as.parse_str(asns)
    child.asns.create(start_as=r.min, end_as=r.max)


def child_add_asn(request, pk):
    conf = request.session['handle']
    get_object_or_404(models.Child, issuer=conf, pk=pk)
    qs = models.ResourceRangeAS.objects.filter(cert__parent__issuer=conf)
    return child_add_resource(request, pk, forms.AddASNForm(qs), [],
                              add_asn_callback)


def add_address_callback(child, form):
    address_range = form.cleaned_data.get('address_range')
    try:
        r = resource_range_ipv4.parse_str(address_range)
        version = 'IPv4'
    except BadIPResource:
        r = resource_range_ipv6.parse_str(address_range)
        version = 'IPv6'
    child.address_ranges.create(start_ip=str(r.min), end_ip=str(r.max),
                                version=version)


def child_add_address(request, pk):
    conf = request.session['handle']
    get_object_or_404(models.Child, issuer=conf, pk=pk)
    qsv4 = models.ResourceRangeAddressV4.objects.filter(cert__parent__issuer=conf)
    qsv6 = models.ResourceRangeAddressV6.objects.filter(cert__parent__issuer=conf)
    return child_add_resource(request, pk,
                              forms.AddNetForm(qsv4, qsv6),
                              [],
                              callback=add_address_callback)


@handle_required
def child_view(request, pk):
    """Detail view of child for the currently selected handle."""
    conf = request.session['handle']
    child = get_object_or_404(conf.children.all(), pk=pk)
    return render(request, 'app/child_detail.html',
                  {'object': child, 'can_edit': True})


@handle_required
def child_edit(request, pk):
    """Edit the end validity date for a resource handle's child."""
    conf = request.session['handle']
    child = get_object_or_404(conf.children.all(), pk=pk)
    form_class = forms.ChildForm(child)
    if request.method == 'POST':
        form = form_class(request.POST, request.FILES)
        if form.is_valid():
            child.valid_until = sundial.datetime.fromdatetime(form.cleaned_data.get('valid_until'))
            child.save()
            # remove AS & prefixes that are not selected in the form
            models.ChildASN.objects.filter(child=child).exclude(pk__in=form.cleaned_data.get('as_ranges')).delete()
            models.ChildNet.objects.filter(child=child).exclude(pk__in=form.cleaned_data.get('address_ranges')).delete()
            return http.HttpResponseRedirect(child.get_absolute_url())
    else:
        form = form_class(initial={
            'as_ranges': child.asns.all(),
            'address_ranges': child.address_ranges.all()})

    return render(request, 'app/child_form.html',
                    {'object': child, 'form': form})


@handle_required
def roa_create(request):
    """Present the user with a form to create a ROA.

    Doesn't use the generic create_object() form because we need to
    create both the ROARequest and ROARequestPrefix objects.

    """

    if request.method == 'POST':
        form = forms.ROARequest(request.POST, request.FILES)
        if form.is_valid():
            asn = form.cleaned_data.get('asn')
            conf = request.session['handle']
            rng = form._as_resource_range()  # FIXME calling "private" method
            max_prefixlen = int(form.cleaned_data.get('max_prefixlen'))

            # find list of matching routes
            routes = []
            match = roa_match(rng)
            for route, roas in match:
                validate_route(route, roas)
                # tweak the validation status due to the presence of the
                # new ROA.  Don't need to check the prefix bounds here
                # because all the matches routes will be covered by this
                # new ROA
                if route.status == 'unknown':
                    # if the route was previously unknown (no covering
                    # ROAs), then:
                    # if the AS matches, it is valid, otherwise invalid
                    if (route.asn != 0 and route.asn == asn and route.prefixlen() <= max_prefixlen):
                        route.status = 'valid'
                        route.status_label = 'success'
                    else:
                        route.status = 'invalid'
                        route.status_label = 'important'
                elif route.status == 'invalid':
                    # if the route was previously invalid, but this new ROA
                    # matches the ASN, it is now valid
                    if route.asn != 0 and route.asn == asn and route.prefixlen() <= max_prefixlen:
                        route.status = 'valid'
                        route.status_label = 'success'

                routes.append(route)

            prefix = str(rng)
            form = forms.ROARequestConfirm(initial={'asn': asn,
                                                    'prefix': prefix,
                                                    'max_prefixlen': max_prefixlen})
            return render(request, 'app/roarequest_confirm_form.html',
                          {'form': form,
                           'asn': asn,
                           'prefix': prefix,
                           'max_prefixlen': max_prefixlen,
                           'routes': routes})
    else:
        form = forms.ROARequest()

    return render(request, 'app/roarequest_form.html', {'form': form})


@handle_required
def roa_create_confirm(request):
    conf = request.session['handle']

    if request.method == 'POST':
        form = forms.ROARequestConfirm(request.POST, request.FILES)
        if form.is_valid():
            asn = form.cleaned_data.get('asn')
            prefix = form.cleaned_data.get('prefix')
            rng = glue.str_to_resource_range(prefix)
            max_prefixlen = form.cleaned_data.get('max_prefixlen')

            roarequests = models.ROARequest.objects.filter(issuer=conf,
                                                           asn=asn)
            if roarequests:
                # FIXME need to handle the case where there are
                # multiple ROAs for the same AS due to prefixes
                # delegated from different resource certs.
                roa = roarequests[0]
            else:
                roa = models.ROARequest.objects.create(issuer=conf,
                                                        asn=asn)
            v = 'IPv4' if isinstance(rng, resource_range_ipv4) else 'IPv6'
            roa.prefixes.create(version=v, prefix=str(rng.min),
                                prefixlen=rng.prefixlen(),
                                max_prefixlen=max_prefixlen)
            # force rpkid run now
            Zookeeper().synchronize(conf.handle)
            return http.HttpResponseRedirect(reverse(roa_list))
    else:
        return http.HttpResponseRedirect(reverse(roa_create))


@handle_required
def roa_list(request):
    """
    Display a list of ROARequestPrefix objects for the current resource
    handle.

    """

    conf = request.session['handle']
    qs = models.ROARequestPrefix.objects.filter(roa_request__issuer=conf)
    return object_list(request, queryset=qs,
            template_name='app/roa_request_list.html',
            extra_context={'create_url': reverse(roa_create)})


@handle_required
def roa_detail(request, pk):
    """Not implemented.

    This is a placeholder so that
    models.ROARequestPrefix.get_absolute_url works.  The only reason it
    exist is so that the /delete URL works.

    """
    pass


@handle_required
def roa_delete(request, pk):
    """Handles deletion of a single ROARequestPrefix object.

    Uses a form for double confirmation, displaying how the route
    validation status may change as a result.

    """

    conf = request.session['handle']
    obj = get_object_or_404(models.ROARequestPrefix.objects,
                            roa_request__issuer=conf, pk=pk)

    if request.method == 'POST':
        roa = obj.roa_request
        obj.delete()
        # if this was the last prefix on the ROA, delete the ROA request
        if not roa.prefixes.exists():
            roa.delete()
        # force rpkid run now
        Zookeeper().synchronize(conf.handle)
        return http.HttpResponseRedirect(reverse(roa_list))

    ### Process GET ###

    match = roa_match(obj.as_resource_range())

    roa_pfx = obj.as_roa_prefix()

    pfx = 'prefixes' if isinstance(roa_pfx, roa_prefix_ipv4) else 'prefixes_v6'
    args = {'%s__prefix_min' % pfx: roa_pfx.min(),
            '%s__prefix_max' % pfx: roa_pfx.max(),
            '%s__max_length' % pfx: roa_pfx.max_prefixlen}

    # exclude ROAs which seem to match this request and display the result
    routes = []
    for route, roas in match:
        qs = roas.exclude(asid=obj.roa_request.asn, **args)
        validate_route(route, qs)
        routes.append(route)

    return render(request, 'app/roa_request_confirm_delete.html',
                  {'object': obj, 'routes': routes})


@handle_required
def ghostbuster_list(request):
    """
    Display a list of all ghostbuster requests for the current Conf.

    """
    conf = request.session['handle']
    qs = models.GhostbusterRequest.objects.filter(issuer=conf)
    return object_list(request, queryset=qs)


@handle_required
def ghostbuster_view(request, pk):
    """
    Display an individual ghostbuster request.

    """
    conf = request.session['handle']
    qs = models.GhostbusterRequest.objects.filter(issuer=conf)
    return object_detail(request, queryset=qs, object_id=pk,
            extra_context={'can_edit': True})


@handle_required
def ghostbuster_delete(request, pk):
    """
    Handle deletion of a GhostbusterRequest object.

    """
    conf = request.session['handle']

    # Ensure the GhosbusterRequest object belongs to the current user.
    get_object_or_404(models.GhostbusterRequest, issuer=conf, pk=pk)

    return delete_object(request, model=models.GhostbusterRequest,
                         object_id=pk,
                         post_delete_redirect=reverse(ghostbuster_list),
                         template_name='app/ghostbusterrequest_detail.html',
                         extra_context={'confirm_delete': True})


def _ghostbuster_edit(request, obj=None):
    """
    Common code for create/edit.

    """
    conf = request.session['handle']
    form_class = forms.GhostbusterRequestForm
    if request.method == 'POST':
        form = form_class(conf, request.POST, request.FILES, instance=obj)
        if form.is_valid():
            # use commit=False for the creation case, otherwise form.save()
            # will fail due to schema constraint violation because conf is
            # NULL
            obj = form.save(commit=False)
            obj.issuer = conf
            obj.vcard = glue.ghostbuster_to_vcard(obj)
            obj.save()
            return http.HttpResponseRedirect(obj.get_absolute_url())
    else:
        form = form_class(conf, instance=obj)
    return render(request, 'app/ghostbuster_form.html',
                  {'form': form, 'object': obj})


@handle_required
def ghostbuster_edit(request, pk):
    conf = request.session['handle']

    # verify that the object is owned by this conf
    obj = get_object_or_404(models.GhostbusterRequest, pk=pk, issuer=conf)

    return _ghostbuster_edit(request, obj)


@handle_required
def ghostbuster_create(request):
    return _ghostbuster_edit(request)


@handle_required
def refresh(request):
    """
    Query rpkid, update the db, and redirect back to the dashboard.

    """
    glue.list_received_resources(request.META['wsgi.errors'],
                                 request.session['handle'])
    return http.HttpResponseRedirect(reverse(dashboard))


@handle_required
def child_wizard(request):
    """
    Wizard mode to create a new locally hosted child.

    """
    if not request.user.is_superuser:
        return http.HttpResponseForbidden()

    if request.method == 'POST':
        form = forms.ChildWizardForm(request.POST, request.FILES)
        if form.is_valid():
            handle = form.cleaned_data.get('handle')
            pw = form.cleaned_data.get('password')
            email = form.cleaned_data.get('email')

            User.objects.create_user(handle, email, pw)

            # FIXME etree_wrapper should allow us to deal with file objects
            t = NamedTemporaryFile(delete=False)
            t.close()

            zk_child = Zookeeper(handle=handle)
            identity_xml = zk_child.initialize()
            identity_xml.save(t.name)
            parent = form.cleaned_data.get('parent')
            zk_parent = Zookeeper(handle=parent.handle)
            parent_response, _ = zk_parent.configure_child(t.name)
            parent_response.save(t.name)
            repo_req, _ = zk_child.configure_parent(t.name)
            repo_req.save(t.name)
            repo_resp, _ = zk_parent.configure_publication_client(t.name)
            repo_resp.save(t.name)
            zk_child.configure_repository(t.name)
            os.remove(t.name)
            # force rpkid run for both parent and child
            zk_child.synchronize(parent.handle, handle)

            return http.HttpResponseRedirect(reverse(dashboard))
    else:
        form = forms.ChildWizardForm()

    return render(request, 'app/child_wizard_form.html', {'form': form})


@handle_required
def child_response(request, pk):
    """
    Export the XML file containing the output of the configure_child
    to send back to the client.

    """
    conf = request.session['handle']
    child = get_object_or_404(models.Child, issuer=conf, pk=pk)
    z = Zookeeper(handle=conf.handle)
    xml = z.generate_parental_response(child)
    resp = serve_xml(str(xml), child.handle)
    return resp


@handle_required
def update_bpki(request):
    conf = request.session['handle']

    if request.method == 'POST':
        form = forms.GenericConfirmationForm(request.POST, request.FILES)
        if form.is_valid():
            Zookeeper(handle=conf.handle).update_bpki()
            return http.HttpResponseRedirect(reverse(dashboard))
    else:
        form = forms.GenericConfirmationForm()

    return render(request, 'app/update_bpki_form.html', {'form': form})


@handle_required
def child_delete(request, pk):
    conf = request.session['handle']
    # verify this child belongs to the current user
    get_object_or_404(conf.children, pk=pk)
    return delete_object(request, model=models.Child, object_id=pk,
                         post_delete_redirect=reverse(child_list),
                         template_name='app/child_detail.html',
                         extra_context={'confirm_delete': True})


@login_required
def destroy_handle(request, handle):
    """
    Completely remove a hosted resource handle.

    """
    log = request.META['wsgi.errors']

    if not request.user.is_superuser:
        return http.HttpResponseForbidden()

    get_object_or_404(models.Conf, handle=handle)

    if request.method == 'POST':
        form = forms.GenericConfirmationForm(request.POST, request.FILES)
        if form.is_valid():
            glue.destroy_handle(log, handle)
            return render(request, 'app/generic_result.html',
                    {'operation': 'Destroy ' + handle,
                     'result': 'Succeeded'})
    else:
        form = forms.GenericConfirmationForm()

    return render(request, 'app/destroy_handle_form.html',
                  {'form': form, 'handle': handle})


def roa_match(rng):
    """
    Return a list of tuples of matching routes and roas.

    """
    object_accepted = rpki.gui.cacheview.models.ValidationLabel.objects.get(label='object_accepted')

    if isinstance(rng, resource_range_ipv6):
        route_manager = rpki.gui.routeview.models.RouteOriginV6.objects
        pfx = 'prefixes_v6'
    else:
        route_manager = rpki.gui.routeview.models.RouteOrigin.objects
        pfx = 'prefixes'

    rv = []
    for obj in route_manager.filter(prefix_min__gte=rng.min, prefix_max__lte=rng.max):
        # This is a bit of a gross hack, since the foreign keys for v4 and v6
        # prefixes have different names.
        args = {'%s__prefix_min__lte' % pfx: obj.prefix_min,
                '%s__prefix_max__gte' % pfx: obj.prefix_max}
        roas = rpki.gui.cacheview.models.ROA.objects.filter(
                statuses__status=object_accepted,
                **args)
        rv.append((obj, roas))

    return rv


def validate_route(route, roas):
    """Annotate the route object with its validation status.

    `roas` is a queryset containing ROAs which cover `route`.

    """
    pfx = 'prefixes' if isinstance(route, rpki.gui.routeview.models.RouteOrigin) else 'prefixes_v6'
    args = {'asid': route.asn,
            '%s__prefix_min__lte' % pfx: route.prefix_min,
            '%s__prefix_max__gte' % pfx: route.prefix_max,
            '%s__max_length__gte' % pfx: route.prefixlen()}

    # 2. if the candidate ROA set is empty, end with unknown
    if not roas.exists():
        route.status = 'unknown'
        route.status_label = 'warning'
    # 3. if any candidate roa matches the origin AS and max_length, end with
    # valid
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
    Display a list of global routing table entries which match resources
    listed in received certificates.

    """
    conf = request.session['handle']
    log = request.META['wsgi.errors']

    routes = []
    for p in models.ResourceRangeAddressV4.objects.filter(cert__parent__in=conf.parents.all()):
        r = p.as_resource_range()
        print >>log, 'querying for routes matching %s' % r
        routes.extend([validate_route(*x) for x in roa_match(r)])
    for p in models.ResourceRangeAddressV6.objects.filter(cert__parent__in=conf.parents.all()):
        r = p.as_resource_range()
        print >>log, 'querying for routes matching %s' % r
        routes.extend([validate_route(*x) for x in roa_match(r)])

    ts = dict((attr['name'], attr['ts']) for attr in models.Timestamp.objects.values())
    return render(request, 'app/routes_view.html',
                  {'routes': routes, 'timestamp': ts})


@handle_required
def repository_list(request):
    conf = request.session['handle']
    qs = models.Repository.objects.filter(issuer=conf)
    return object_list(request, queryset=qs,
                       template_name='app/repository_list.html',
                       extra_context={
                           'create_url': reverse(repository_import),
                           'create_label': u'Import'})


@handle_required
def repository_detail(request, pk):
    conf = request.session['handle']
    qs = models.Repository.objects.filter(issuer=conf)
    return object_detail(request, queryset=qs, object_id=pk,
                         template_name='app/repository_detail.html')


@handle_required
def repository_delete(request, pk):
    conf = request.session['handle']
    # Ensure the repository being deleted belongs to the current user.
    get_object_or_404(models.Repository, issuer=conf, pk=pk)
    return delete_object(request, model=models.Repository, object_id=pk,
            post_delete_redirect=reverse(repository_list),
            template_name='app/repository_detail.html',
            extra_context={'confirm_delete': True})


@handle_required
def repository_import(request):
    """Import XML response file from repository operator."""
    return generic_import(request,
                          models.Repository.objects,
                          Zookeeper.configure_repository,
                          form_class=forms.ImportRepositoryForm,
                          post_import_redirect=reverse(repository_list))


@superuser_required
def client_list(request):
    return object_list(request, queryset=models.Client.objects.all(),
            extra_context={
                'create_url': reverse(client_import),
                'create_label': u'Import'})


@superuser_required
def client_detail(request, pk):
    return object_detail(request, queryset=models.Client.objects, object_id=pk)


@superuser_required
def client_delete(request, pk):
    return delete_object(request, model=models.Client, object_id=pk,
                         post_delete_redirect=reverse(client_list),
                         template_name='app/client_detail.html',
                         extra_context={'confirm_delete': True})


@superuser_required
def client_import(request):
    return generic_import(request, models.Client.objects,
                          Zookeeper.configure_publication_client,
                          form_class=forms.ImportClientForm,
                          post_import_redirect=reverse(client_list))


@superuser_required
def client_export(request, pk):
    """Return the XML file resulting from a configure_publication_client
    request.

    """
    client = get_object_or_404(models.Client, pk=pk)
    z = Zookeeper()
    xml = z.generate_repository_response(client)
    return serve_xml(str(xml), '%s.repo' % z.handle)
