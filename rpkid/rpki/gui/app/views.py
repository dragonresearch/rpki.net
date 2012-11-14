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
from django.core.urlresolvers import reverse
from django.contrib.auth.models import User
from django.contrib.formtools.preview import FormPreview

from rpki.irdb import Zookeeper, ChildASN, ChildNet
from rpki.gui.app import models, forms, glue, range_list
from rpki.resource_set import (resource_range_as, resource_range_ipv4,
                               resource_range_ipv6, roa_prefix_ipv4)
from rpki import sundial

from rpki.gui.cacheview.models import ROAPrefixV4, ROAPrefixV6, ROA


def superuser_required(f):
    """Decorator which returns HttpResponseForbidden if the user does
    not have superuser permissions.

    """
    @login_required
    def _wrapped(request, *args, **kwargs):
        if not request.user.is_superuser:
            return http.HttpResponseForbidden()
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
    log = request.META['wsgi.errors']
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
    asns = models.ResourceRangeAS.objects.filter(cert__conf=conf)
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
    prefixes = models.ResourceRangeAddressV4.objects.filter(cert__conf=conf).all()
    prefixes_v6 = models.ResourceRangeAddressV6.objects.filter(cert__conf=conf).all()
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
        'prefixes_v6': prefixes_v6})


@superuser_required
def conf_list(request):
    """Allow the user to select a handle."""
    queryset = models.Conf.objects.all()
    return object_list(request, queryset,
                       template_name='app/conf_list.html',
                       template_object_name='conf',
                       extra_context={'select_url': reverse(conf_select)})


@superuser_required
def conf_select(request):
    """Change the handle for the current session."""
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
    resp['Content-Disposition'] = 'attachment; filename=%s.xml' % (basename,)
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
    obj = get_object_or_404(conf.parents, pk=pk)  # confirm permission
    log = request.META['wsgi.errors']
    form_class = forms.UserDeleteForm
    if request.method == 'POST':
        form = form_class(request.POST, request.FILES)
        if form.is_valid():
            z = Zookeeper(handle=conf.handle, logstream=log)
            z.delete_parent(obj.handle)
            z.synchronize()
            return http.HttpResponseRedirect(reverse(parent_list))
    else:
        form = form_class()
    return render(request, 'app/parent_detail.html',
                  {'object': obj, 'form': form, 'confirm_delete': True})


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


class ChildAddResourcePreview(FormPreview):
    """
    Base class for handling preview of AS/Prefix additions to a child.
    Subclasses implement the 'done' method to perform actual work on IRDB.

    """

    form_template = 'app/child_detail.html'
    preview_template = 'app/child_detail.html'

    def __init__(self, *args, **kwargs):
        """
        The docstring for FormPreview says we should not redefine this method, but
        I don't see how we can set extra information in this class otherwise.

        """
        self.child = kwargs.pop('child')
        self.logstream = kwargs.pop('logstream')
        super(ChildAddResourcePreview, self).__init__(*args, **kwargs)

    def get_context(self, *args, **kwargs):
        """"
        Override the superclass method to add context variables needed by the
        form template.

        """
        d = super(ChildAddResourcePreview, self).get_context(*args, **kwargs)
        d['object'] = self.child
        d['form_label'] = 'Add Resource'
        return d

    def process_preview(self, request, form, context):
        # set a boolean flag so that the template knows this is a preview
        context['is_preview'] = True


class ChildAddPrefixPreview(ChildAddResourcePreview):
    def done(self, request, cleaned_data):
        address_range = cleaned_data.get('address_range')
        if ':' in address_range:
            r = resource_range_ipv6.parse_str(address_range)
            version = 'IPv6'
        else:
            r = resource_range_ipv4.parse_str(address_range)
            version = 'IPv4'
        self.child.address_ranges.create(start_ip=str(r.min), end_ip=str(r.max),
                                         version=version)
        Zookeeper(handle=self.child.issuer.handle, logstream=self.logstream).run_rpkid_now()
        return http.HttpResponseRedirect(self.child.get_absolute_url())

@handle_required
def child_add_address(request, pk):
    logstream = request.META['wsgi.errors']
    conf = request.session['handle']
    child = get_object_or_404(models.Child, issuer=conf, pk=pk)
    form = forms.AddNetForm(child)
    preview = ChildAddPrefixPreview(form, child=child, logstream=logstream)
    return preview(request)

class ChildAddASNPreview(ChildAddResourcePreview):
    def done(self, request, cleaned_data):
        asns = cleaned_data.get('asns')
        r = resource_range_as.parse_str(asns)
        self.child.asns.create(start_as=r.min, end_as=r.max)
        Zookeeper(handle=self.child.issuer.handle, logstream=self.logstream).run_rpkid_now()
        return http.HttpResponseRedirect(self.child.get_absolute_url())

@handle_required
def child_add_asn(request, pk):
    logstream = request.META['wsgi.errors']
    conf = request.session['handle']
    child = get_object_or_404(models.Child, issuer=conf, pk=pk)
    form = forms.AddASNForm(child)
    preview = ChildAddASNPreview(form, child=child, logstream=logstream)
    return preview(request)

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
    log = request.META['wsgi.errors']
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
            Zookeeper(handle=conf.handle, logstream=log).run_rpkid_now()
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

    conf = request.session['handle']
    if request.method == 'POST':
        form = forms.ROARequest(request.POST, request.FILES, conf=conf)
        if form.is_valid():
            asn = form.cleaned_data.get('asn')
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
    log = request.META['wsgi.errors']

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
            Zookeeper(handle=conf.handle, logstream=log).run_rpkid_now()
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
    qs = models.ROARequestPrefix.objects.filter(roa_request__issuer=conf).order_by('prefix')
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
        Zookeeper(handle=conf.handle).run_rpkid_now()
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
    log = request.META['wsgi.errors']
    form_class = forms.UserDeleteForm  # FIXME
    # Ensure the GhosbusterRequest object belongs to the current user.
    obj = get_object_or_404(models.GhostbusterRequest, issuer=conf, pk=pk)
    if request.method == 'POST':
        form = form_class(request.POST, request.FILES)
        if form.is_valid():
            obj.delete()
            Zookeeper(handle=conf.handle, logstream=log).run_rpkid_now()
            return http.HttpResponseRedirect(reverse(ghostbuster_list))
    else:
        form = form_class()
    return render(request, 'app/ghostbusterrequest_detail.html',
                  {'object': obj, 'form': form, 'confirm_delete': True})


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
            Zookeeper(handle=conf.handle).run_rpkid_now()
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
def child_delete(request, pk):
    conf = request.session['handle']
    # verify this child belongs to the current user
    obj = get_object_or_404(conf.children, pk=pk)
    form_class = forms.UserDeleteForm  # FIXME
    if request.method == 'POST':
        form = form_class(request.POST, request.FILES)
        if form.is_valid():
            z = Zookeeper(handle=conf.handle)
            z.delete_child(obj.handle)
            z.synchronize()
            return http.HttpResponseRedirect(reverse(child_list))
    else:
        form = form_class()
    return render(request, 'app/child_detail.html',
                  {'object': obj, 'form': form, 'confirm_delete': True})


def roa_match(rng):
    """Return a list of tuples of matching routes and roas."""
    if isinstance(rng, resource_range_ipv6):
        route_manager = models.RouteOriginV6.objects
        pfx = 'prefixes_v6'
    else:
        route_manager = models.RouteOrigin.objects
        pfx = 'prefixes'

    rv = []
    for obj in route_manager.filter(prefix_min__gte=rng.min, prefix_max__lte=rng.max):
        # This is a bit of a gross hack, since the foreign keys for v4 and v6
        # prefixes have different names.
        args = {'%s__prefix_min__lte' % pfx: obj.prefix_min,
                '%s__prefix_max__gte' % pfx: obj.prefix_max}
        roas = ROA.objects.filter(**args)
        rv.append((obj, roas))

    return rv


def validate_route(route, roas):
    """Annotate the route object with its validation status.

    `roas` is a queryset containing ROAs which cover `route`.

    """
    pfx = 'prefixes' if isinstance(route, models.RouteOrigin) else 'prefixes_v6'
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
    for p in models.ResourceRangeAddressV4.objects.filter(cert__conf=conf):
        r = p.as_resource_range()
        print >>log, 'querying for routes matching %s' % r
        routes.extend([validate_route(*x) for x in roa_match(r)])
    for p in models.ResourceRangeAddressV6.objects.filter(cert__conf=conf):
        r = p.as_resource_range()
        print >>log, 'querying for routes matching %s' % r
        routes.extend([validate_route(*x) for x in roa_match(r)])

    ts = dict((attr['name'], attr['ts']) for attr in models.Timestamp.objects.values())
    return render(request, 'app/routes_view.html',
                  {'routes': routes, 'timestamp': ts})


def route_detail(request, pk):
    pass


def route_roa_list(request, pk):
    """Show a list of ROAs that match a given route."""
    object = get_object_or_404(models.RouteOrigin, pk=pk)
    # select accepted ROAs which cover this route
    qs = ROAPrefixV4.objects.filter(prefix_min__lte=object.prefix_min,
                                    prefix_max__gte=object.prefix_max).select_related()
    return object_list(request, qs, template_name='app/route_roa_list.html')


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
    log = request.META['wsgi.errors']
    conf = request.session['handle']
    # Ensure the repository being deleted belongs to the current user.
    obj = get_object_or_404(models.Repository, issuer=conf, pk=pk)
    if request.method == 'POST':
        form = form_class(request.POST, request.FILES)
        if form.is_valid():
            z = Zookeeper(handle=conf.handle, logstream=log)
            z.delete_repository(obj.handle)
            z.synchronize()
            return http.HttpResponseRedirect(reverse(repository_list))
    else:
        form = form_class()
    return render(request, 'app/repository_detail.html',
                  {'object': obj, 'form': form, 'confirm_delete': True})


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
    log = request.META['wsgi.errors']
    obj = get_object_or_404(models.Client, pk=pk)
    form_class = forms.UserDeleteForm  # FIXME
    if request.method == 'POST':
        form = form_class(request.POST, request.FILES)
        if form.is_valid():
            z = Zookeeper(logstream=log)
            z.delete_publication_client(obj.handle)
            z.synchronize()
            return http.HttpResponseRedirect(reverse(client_list))
    else:
        form = form_class()
    return render(request, 'app/client_detail.html',
                  {'object': obj, 'form': form, 'confirm_delete': True})


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


@superuser_required
def user_list(request):
    """Display a list of all the RPKI handles managed by this server."""
    # create a list of tuples of (Conf, User)
    users = []
    for conf in models.Conf.objects.all():
        try:
            u = User.objects.get(username=conf.handle)
        except User.DoesNotExist:
            u = None
        users.append((conf, u))
    return render(request, 'app/user_list.html', {'users': users})


@superuser_required
def user_detail(request):
    """Placeholder for Conf.get_absolute_url()."""
    pass


@superuser_required
def user_delete(request, pk):
    conf = models.Conf.objects.get(pk=pk)
    log = request.META['wsgi.errors']
    if request.method == 'POST':
        form = forms.UserDeleteForm(request.POST)
        if form.is_valid():
            User.objects.filter(username=conf.handle).delete()
            z = Zookeeper(handle=conf.handle, logstream=log)
            z.delete_self()
            z.synchronize()
            return http.HttpResponseRedirect(reverse(user_list))
    else:
        form = forms.UserDeleteForm()
    return render(request, 'app/user_confirm_delete.html',
                  {'object': conf, 'form': form})


@superuser_required
def user_edit(request, pk):
    conf = get_object_or_404(models.Conf, pk=pk)
    # in the old model, there may be users with a different name, so create a
    # new user object if it is missing.
    try:
        user = User.objects.get(username=conf.handle)
    except User.DoesNotExist:
        user = User(username=conf.handle)

    if request.method == 'POST':
        form = forms.UserEditForm(request.POST)
        if form.is_valid():
            pw = form.cleaned_data.get('pw')
            if pw:
                user.set_password(pw)
            user.email = form.cleaned_data.get('email')
            user.save()
            return http.HttpResponseRedirect(reverse(user_list))
    else:
        form = forms.UserEditForm(initial={'email': user.email})
    return render(request, 'app/user_edit_form.html',
                  {'object': user, 'form': form})


@handle_required
def user_create(request):
    """
    Wizard mode to create a new locally hosted child.

    """
    if not request.user.is_superuser:
        return http.HttpResponseForbidden()

    log = request.META['wsgi.errors']
    if request.method == 'POST':
        form = forms.UserCreateForm(request.POST, request.FILES)
        if form.is_valid():
            handle = form.cleaned_data.get('handle')
            pw = form.cleaned_data.get('password')
            email = form.cleaned_data.get('email')
            parent = form.cleaned_data.get('parent')

            User.objects.create_user(handle, email, pw)

            zk_child = Zookeeper(handle=handle, logstream=log)
            identity_xml = zk_child.initialize()
            if parent:
                # FIXME etree_wrapper should allow us to deal with file objects
                t = NamedTemporaryFile(delete=False)
                t.close()

                identity_xml.save(t.name)
                zk_parent = Zookeeper(handle=parent.handle, logstream=log)
                parent_response, _ = zk_parent.configure_child(t.name)
                parent_response.save(t.name)
                repo_req, _ = zk_child.configure_parent(t.name)
                repo_req.save(t.name)
                repo_resp, _ = zk_parent.configure_publication_client(t.name)
                repo_resp.save(t.name)
                zk_child.configure_repository(t.name)
                os.remove(t.name)
            zk_child.synchronize()

            return http.HttpResponseRedirect(reverse(dashboard))
    else:
        conf = request.session['handle']
        form = forms.UserCreateForm(initial={'parent': conf})

    return render(request, 'app/user_create_form.html', {'form': form})
