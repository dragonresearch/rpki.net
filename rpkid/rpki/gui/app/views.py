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
import cStringIO
import csv
import logging

from django.utils.decorators import method_decorator
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, render, redirect
from django.utils.http import urlquote
from django import http
from django.core.urlresolvers import reverse, reverse_lazy
from django.contrib.auth.models import User
from django.views.generic import DetailView, ListView, DeleteView
from django.core.paginator import Paginator, InvalidPage
from django.forms.formsets import formset_factory, BaseFormSet
import django.db.models
from django.contrib import messages

from rpki.irdb import Zookeeper, ChildASN, ChildNet, ROARequestPrefix
from rpki.gui.app import models, forms, glue, range_list
from rpki.resource_set import (resource_range_as, resource_range_ip,
                               roa_prefix_ipv4)
from rpki import sundial
import rpki.exceptions

from rpki.gui.cacheview.models import ROA
from rpki.gui.routeview.models import RouteOrigin
from rpki.gui.decorators import tls_required

logger = logging.getLogger(__name__)


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


def handle_required(f):
    """Decorator for view functions which require the user to be logged in and
    a resource handle selected for the session.

    """
    @login_required
    @tls_required
    def wrapped_fn(request, *args, **kwargs):
        if 'handle' not in request.session:
            if request.user.is_superuser:
                conf = models.Conf.objects.all()
            else:
                conf = models.Conf.objects.filter(confacl__user=request.user)

            if conf.count() == 1:
                request.session['handle'] = conf[0]
            elif conf.count() == 0:
                return render(request, 'app/conf_empty.html', {})
            else:
                url = '%s?next=%s' % (reverse(conf_list),
                                      urlquote(request.get_full_path()))
                return http.HttpResponseRedirect(url)

        return f(request, *args, **kwargs)
    return wrapped_fn


@handle_required
def generic_import(request, queryset, configure, form_class=None,
                   post_import_redirect=None):
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

    post_import_redirect
        if None (default), the user will be redirected to the detail page for
        the imported object.  Otherwise, the user will be redirected to the
        specified URL.

    """
    conf = request.session['handle']
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
            z.synchronize_ca(poke=True)
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

    return render(request, 'app/app_form.html', {
        'form': form,
        'form_title': 'Import ' + queryset.model._meta.verbose_name.capitalize(),
    })


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
    # monkey-patch each object with a boolean value indicating whether or not
    # it is a prefix.  We have to do this here because in the template there is
    # no way to catch the MustBePrefix exception.
    for x in unused_prefixes:
        try:
            x.prefixlen()
            x.is_prefix = True
        except rpki.exceptions.MustBePrefix:
            x.is_prefix = False

    unused_prefixes_v6 = my_prefixes_v6.difference(used_prefixes_v6)
    for x in unused_prefixes_v6:
        try:
            x.prefixlen()
            x.is_prefix = True
        except rpki.exceptions.MustBePrefix:
            x.is_prefix = False

    clients = models.Client.objects.all() if request.user.is_superuser else None

    return render(request, 'app/dashboard.html', {
        'conf': conf,
        'unused_asns': unused_asns,
        'unused_prefixes': unused_prefixes,
        'unused_prefixes_v6': unused_prefixes_v6,
        'asns': asns,
        'prefixes': prefixes,
        'prefixes_v6': prefixes_v6,
        'clients': clients,
    })


@login_required
def conf_list(request, **kwargs):
    """Allow the user to select a handle."""
    log = request.META['wsgi.errors']
    next_url = request.GET.get('next', reverse(dashboard))
    if request.user.is_superuser:
        qs = models.Conf.objects.all()
    else:
        qs = models.Conf.objects.filter(confacl__user=request.user)
    return render(request, 'app/conf_list.html', {
        'conf_list': qs,
        'next_url': next_url
    })


@login_required
def conf_select(request):
    """Change the handle for the current session."""
    if not 'handle' in request.GET:
        return redirect(conf_list)
    handle = request.GET['handle']
    next_url = request.GET.get('next', reverse(dashboard))
    if request.user.is_superuser:
        request.session['handle'] = get_object_or_404(models.Conf, handle=handle)
    else:
        request.session['handle'] = get_object_or_404(
            models.Conf, confacl__user=request.user, handle=handle
        )
    return http.HttpResponseRedirect(next_url)


def serve_xml(content, basename, ext='xml'):
    """
    Generate a HttpResponse object with the content type set to XML.

    `content` is a string.

    `basename` is the prefix to specify for the XML filename.

    `csv` is the type (default: xml)

    """
    resp = http.HttpResponse(content, mimetype='application/%s' % ext)
    resp['Content-Disposition'] = 'attachment; filename=%s.%s' % (basename, ext)
    return resp


@handle_required
def conf_export(request):
    """Return the identity.xml for the current handle."""
    conf = request.session['handle']
    z = Zookeeper(handle=conf.handle)
    xml = z.generate_identity()
    return serve_xml(str(xml), '%s.identity' % conf.handle)


@handle_required
def export_asns(request):
    """Export CSV file containing ASN allocations to children."""
    conf = request.session['handle']
    s = cStringIO.StringIO()
    csv_writer = csv.writer(s, delimiter=' ')
    for childasn in ChildASN.objects.filter(child__issuer=conf):
        csv_writer.writerow([childasn.child.handle, str(childasn.as_resource_range())])
    return serve_xml(s.getvalue(), '%s.asns' % conf.handle, ext='csv')


@handle_required
def import_asns(request):
    conf = request.session['handle']
    if request.method == 'POST':
        form = forms.ImportCSVForm(request.POST, request.FILES)
        if form.is_valid():
            f = NamedTemporaryFile(prefix='asns', suffix='.csv', delete=False)
            f.write(request.FILES['csv'].read())
            f.close()
            z = Zookeeper(handle=conf.handle)
            z.load_asns(f.name)
            z.run_rpkid_now()
            os.unlink(f.name)
            messages.success(request, 'Successfully imported AS delgations from CSV file.')
            return redirect(dashboard)
    else:
        form = forms.ImportCSVForm()
    return render(request, 'app/import_resource_form.html', {
        'form_title': 'Import CSV containing ASN delegations',
        'form': form,
        'cancel_url': reverse(dashboard)
    })


@handle_required
def export_prefixes(request):
    """Export CSV file containing ASN allocations to children."""
    conf = request.session['handle']
    s = cStringIO.StringIO()
    csv_writer = csv.writer(s, delimiter=' ')
    for childnet in ChildNet.objects.filter(child__issuer=conf):
        csv_writer.writerow([childnet.child.handle, str(childnet.as_resource_range())])
    return serve_xml(s.getvalue(), '%s.prefixes' % conf.handle, ext='csv')


@handle_required
def import_prefixes(request):
    conf = request.session['handle']
    if request.method == 'POST':
        form = forms.ImportCSVForm(request.POST, request.FILES)
        if form.is_valid():
            f = NamedTemporaryFile(prefix='prefixes', suffix='.csv', delete=False)
            f.write(request.FILES['csv'].read())
            f.close()
            z = Zookeeper(handle=conf.handle)
            z.load_prefixes(f.name)
            z.run_rpkid_now()
            os.unlink(f.name)
            messages.success(request, 'Successfully imported prefix delegations from CSV file.')
            return redirect(dashboard)
    else:
        form = forms.ImportCSVForm()
    return render(request, 'app/import_resource_form.html', {
        'form_title': 'Import CSV containing Prefix delegations',
        'form': form,
        'cancel_url': reverse(dashboard)
    })


@handle_required
def parent_import(request):
    conf = request.session['handle']
    return generic_import(request, conf.parents, Zookeeper.configure_parent)


@handle_required
def parent_detail(request, pk):
    return render(request, 'app/parent_detail.html', {
        'object': get_object_or_404(request.session['handle'].parents, pk=pk)})


@handle_required
def parent_delete(request, pk):
    conf = request.session['handle']
    obj = get_object_or_404(conf.parents, pk=pk)  # confirm permission
    log = request.META['wsgi.errors']
    if request.method == 'POST':
        form = forms.Empty(request.POST, request.FILES)
        if form.is_valid():
            z = Zookeeper(handle=conf.handle, logstream=log)
            z.delete_parent(obj.handle)
            z.synchronize_ca()
            return http.HttpResponseRedirect(reverse(dashboard))
    else:
        form = forms.Empty()
    return render(request, 'app/object_confirm_delete.html', {
        'object': obj,
        'form': form,
        'parent_template': 'app/parent_detail.html'
    })


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
def child_add_prefix(request, pk):
    logstream = request.META['wsgi.errors']
    conf = request.session['handle']
    child = get_object_or_404(conf.children, pk=pk)
    if request.method == 'POST':
        form = forms.AddNetForm(request.POST, child=child)
        if form.is_valid():
            address_range = form.cleaned_data.get('address_range')
            r = resource_range_ip.parse_str(address_range)
            version = 'IPv%d' % r.version
            child.address_ranges.create(start_ip=str(r.min), end_ip=str(r.max),
                                        version=version)
            Zookeeper(handle=conf.handle, logstream=logstream).run_rpkid_now()
            return http.HttpResponseRedirect(child.get_absolute_url())
    else:
        form = forms.AddNetForm(child=child)
    return render(request, 'app/app_form.html',
                  {'object': child, 'form': form, 'form_title': 'Add Prefix'})


@handle_required
def child_add_asn(request, pk):
    logstream = request.META['wsgi.errors']
    conf = request.session['handle']
    child = get_object_or_404(conf.children, pk=pk)
    if request.method == 'POST':
        form = forms.AddASNForm(request.POST, child=child)
        if form.is_valid():
            asns = form.cleaned_data.get('asns')
            r = resource_range_as.parse_str(asns)
            child.asns.create(start_as=r.min, end_as=r.max)
            Zookeeper(handle=conf.handle, logstream=logstream).run_rpkid_now()
            return http.HttpResponseRedirect(child.get_absolute_url())
    else:
        form = forms.AddASNForm(child=child)
    return render(request, 'app/app_form.html',
                  {'object': child, 'form': form, 'form_title': 'Add ASN'})


@handle_required
def child_detail(request, pk):
    child = get_object_or_404(request.session['handle'].children, pk=pk)
    return render(request, 'app/child_detail.html', {'object': child})


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
            child.valid_until = sundial.datetime.from_datetime(form.cleaned_data.get('valid_until'))
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

    return render(request, 'app/app_form.html', {
        'object': child,
        'form': form,
        'form_title': 'Edit Child: ' + child.handle,
    })


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
    logstream = request.META['wsgi.errors']
    conf = request.session['handle']
    child = get_object_or_404(conf.children, pk=pk)
    if request.method == 'POST':
        form = forms.Empty(request.POST)
        if form.is_valid():
            z = Zookeeper(handle=conf.handle, logstream=logstream)
            z.delete_child(child.handle)
            z.synchronize_ca()
            return http.HttpResponseRedirect(reverse(dashboard))
    else:
        form = forms.Empty()
    return render(request, 'app/object_confirm_delete.html', {
        'object': child,
        'form': form,
        'parent_template': 'app/child_detail.html'
    })


@handle_required
def roa_detail(request, pk):
    conf = request.session['handle']
    obj = get_object_or_404(conf.roas, pk=pk)
    return render(request, 'app/roa_detail.html', {'object': obj})


def get_covered_routes(rng, max_prefixlen, asn):
    """Returns a list of routeview.models.RouteOrigin objects which would
    change validation status if a ROA were created with the parameters to this
    function.

    A "newstatus" attribute is monkey-patched on the RouteOrigin objects which
    can be used in the template.  "status" remains the current validation
    status of the object.

    """

    # find all routes that match or are completed covered by the proposed new roa
    qs = RouteOrigin.objects.filter(
        prefix_min__gte=rng.min,
        prefix_max__lte=rng.max
    )
    routes = []
    for route in qs:
        status = route.status
        # tweak the validation status due to the presence of the
        # new ROA.  Don't need to check the prefix bounds here
        # because all the matches routes will be covered by this
        # new ROA
        if status == 'unknown':
            # if the route was previously unknown (no covering
            # ROAs), then:
            # if the AS matches, it is valid, otherwise invalid
            if (route.asn != 0 and route.asn == asn and route.prefixlen <= max_prefixlen):
                route.newstatus = 'valid'
            else:
                route.newstatus = 'invalid'
            routes.append(route)
        elif status == 'invalid':
            # if the route was previously invalid, but this new ROA
            # matches the ASN, it is now valid
            if route.asn != 0 and route.asn == asn and route.prefixlen <= max_prefixlen:
                route.newstatus = 'valid'
                routes.append(route)

    return routes


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

            routes = get_covered_routes(rng, max_prefixlen, asn)

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
        # pull initial values from query parameters
        d = {}
        for s in ('asn', 'prefix'):
            if s in request.GET:
                d[s] = request.GET[s]
        form = forms.ROARequest(initial=d)

    return render(request, 'app/roarequest_form.html', {'form': form})


class ROARequestFormSet(BaseFormSet):
    """There is no way to pass arbitrary keyword arguments to the form
    constructor, so we have to override BaseFormSet to allow it.

    """
    def __init__(self, *args, **kwargs):
        self.conf = kwargs.pop('conf')
        super(ROARequestFormSet, self).__init__(*args, **kwargs)

    def _construct_forms(self):
        self.forms = []
        for i in xrange(self.total_form_count()):
            self.forms.append(self._construct_form(i, conf=self.conf))


def split_with_default(s):
    xs = s.split(',')
    if len(xs) == 1:
        return xs[0], None
    return xs


@handle_required
def roa_create_multi(request):
    """version of roa_create that uses a formset to allow entry of multiple
    roas on a single page.

    ROAs can be specified in the GET query string, as such:

        ?roa=prefix,asn

    Mulitple ROAs may be specified:

        ?roa=prefix,asn+roa=prefix2,asn2

    If an IP range is specified, it will be automatically split into multiple
    prefixes:

        ?roa=1.1.1.1-2.2.2.2,42

    The ASN may optionally be omitted.

    """

    conf = request.session['handle']
    if request.method == 'GET':
        init = []
        for x in request.GET.getlist('roa'):
            rng, asn = split_with_default(x)
            rng = resource_range_ip.parse_str(rng)
            if rng.can_be_prefix:
                init.append({'asn': asn, 'prefix': str(rng)})
            else:
                v = []
                rng.chop_into_prefixes(v)
                init.extend([{'asn': asn, 'prefix': str(p)} for p in v])
        formset = formset_factory(forms.ROARequest, formset=ROARequestFormSet,
                                 can_delete=True)(initial=init, conf=conf)
    elif request.method == 'POST':
        formset = formset_factory(forms.ROARequest, formset=ROARequestFormSet,
                                  extra=0, can_delete=True)(request.POST, request.FILES, conf=conf)
        if formset.is_valid():
            routes = []
            v = []
            # as of Django 1.4.5 we still can't use formset.cleaned_data
            # because deleted forms are not excluded, which causes an
            # AttributeError to be raised.
            for form in formset:
                if hasattr(form, 'cleaned_data') and form.cleaned_data:  # exclude empty forms
                    asn = form.cleaned_data.get('asn')
                    rng = resource_range_ip.parse_str(form.cleaned_data.get('prefix'))
                    max_prefixlen = int(form.cleaned_data.get('max_prefixlen'))
                    # FIXME: This won't do the right thing in the event that a
                    # route is covered by multiple ROAs created in the form.
                    # You will see duplicate entries, each with a potentially
                    # different validation status.
                    routes.extend(get_covered_routes(rng, max_prefixlen, asn))
                    v.append({'prefix': str(rng), 'max_prefixlen': max_prefixlen,
                              'asn': asn})
            # if there were no rows, skip the confirmation step
            if v:
                formset = formset_factory(forms.ROARequestConfirm, extra=0)(initial=v)
                return render(request, 'app/roarequest_confirm_multi_form.html',
                            {'routes': routes, 'formset': formset, 'roas': v})
    return render(request, 'app/roarequest_multi_form.html',
                  {'formset': formset})


@handle_required
def roa_create_confirm(request):
    """This function is called when the user confirms the creation of a ROA
    request.  It is responsible for updating the IRDB.

    """
    conf = request.session['handle']
    log = request.META['wsgi.errors']
    if request.method == 'POST':
        form = forms.ROARequestConfirm(request.POST, request.FILES)
        if form.is_valid():
            asn = form.cleaned_data.get('asn')
            prefix = form.cleaned_data.get('prefix')
            rng = resource_range_ip.parse_str(prefix)
            max_prefixlen = form.cleaned_data.get('max_prefixlen')
            # Always create ROA requests with a single prefix.
            # https://trac.rpki.net/ticket/32
            roa = models.ROARequest.objects.create(issuer=conf, asn=asn)
            v = 'IPv%d' % rng.version
            roa.prefixes.create(version=v, prefix=str(rng.min),
                                prefixlen=rng.prefixlen(),
                                max_prefixlen=max_prefixlen)
            Zookeeper(handle=conf.handle, logstream=log).run_rpkid_now()
            return http.HttpResponseRedirect(reverse(dashboard))
        # What should happen when the submission form isn't valid?  For now
        # just fall through and redirect back to the ROA creation form
    return http.HttpResponseRedirect(reverse(roa_create))


@handle_required
def roa_create_multi_confirm(request):
    """This function is called when the user confirms the creation of a ROA
    request.  It is responsible for updating the IRDB.

    """
    conf = request.session['handle']
    log = request.META['wsgi.errors']
    if request.method == 'POST':
        formset = formset_factory(forms.ROARequestConfirm, extra=0)(request.POST, request.FILES)
        if formset.is_valid():
            for cleaned_data in formset.cleaned_data:
                asn = cleaned_data.get('asn')
                prefix = cleaned_data.get('prefix')
                rng = resource_range_ip.parse_str(prefix)
                max_prefixlen = cleaned_data.get('max_prefixlen')
                # Always create ROA requests with a single prefix.
                # https://trac.rpki.net/ticket/32
                roa = models.ROARequest.objects.create(issuer=conf, asn=asn)
                v = 'IPv%d' % rng.version
                roa.prefixes.create(version=v, prefix=str(rng.min),
                                    prefixlen=rng.prefixlen(),
                                    max_prefixlen=max_prefixlen)
            Zookeeper(handle=conf.handle, logstream=log).run_rpkid_now()
            return redirect(dashboard)
        # What should happen when the submission form isn't valid?  For now
        # just fall through and redirect back to the ROA creation form
    return http.HttpResponseRedirect(reverse(roa_create_multi))


@handle_required
def roa_delete(request, pk):
    """Handles deletion of a single ROARequest object.

    Uses a form for double confirmation, displaying how the route
    validation status may change as a result.

    """

    conf = request.session['handle']
    roa = get_object_or_404(conf.roas, pk=pk)
    if request.method == 'POST':
        roa.delete()
        Zookeeper(handle=conf.handle).run_rpkid_now()
        return redirect(reverse(dashboard))

    ### Process GET ###

    # note: assumes we only generate one prefix per ROA
    roa_prefix = roa.prefixes.all()[0]
    rng = roa_prefix.as_resource_range()

    routes = []
    for route in roa.routes:
        # select all roas which cover this route
        # excluding the current roa
        # note: we can't identify the exact ROA here, because we only know what
        # was requested to rpkid
        roas = route.roas.exclude(
            asid=roa.asn,
            prefixes__prefix_min=rng.min,
            prefixes__prefix_max=rng.max,
            prefixes__max_length=roa_prefix.max_prefixlen
        )

        # subselect exact match
        if route.asn != 0 and roas.filter(asid=route.asn,
                                          prefixes__max_length__gte=route.prefixlen).exists():
            route.newstatus = 'valid'
        elif roas.exists():
            route.newstatus = 'invalid'
        else:
            route.newstatus = 'unknown'
        # we may want to ignore routes for which there is no status change,
        # but the user may want to see that nothing has changed explicitly
        routes.append(route)

    return render(request, 'app/roarequest_confirm_delete.html',
                  {'object': roa, 'routes': routes})


@handle_required
def roa_clone(request, pk):
    conf = request.session['handle']
    roa = get_object_or_404(conf.roas, pk=pk)
    return redirect(
        reverse(roa_create_multi) + "?roa=" + str(roa.prefixes.all()[0].as_roa_prefix())
    )


@handle_required
def roa_import(request):
    """Import CSV containing ROA declarations."""
    if request.method == 'POST':
        form = forms.ImportCSVForm(request.POST, request.FILES)
        if form.is_valid():
            import tempfile
            tmp = tempfile.NamedTemporaryFile(suffix='.csv', prefix='roas', delete=False)
            tmp.write(request.FILES['csv'].read())
            tmp.close()
            z = Zookeeper(handle=request.session['handle'])
            z.load_roa_requests(tmp.name)
            z.run_rpkid_now()
            os.unlink(tmp.name)
            messages.success(request, 'Successfully imported ROAs.')
            return redirect(dashboard)
    else:
        form = forms.ImportCSVForm()
    return render(request, 'app/import_resource_form.html', {
        'form_title': 'Import ROAs from CSV',
        'form': form,
        'cancel_url': reverse(dashboard)
    })


@handle_required
def roa_export(request):
    """Export CSV containing ROA declarations."""
    # FIXME: remove when Zookeeper can do this
    f = cStringIO.StringIO()
    csv_writer = csv.writer(f, delimiter=' ')
    conf = request.session['handle']
    # each roa prefix gets a unique group so rpkid will issue separate roas
    for group, roapfx in enumerate(ROARequestPrefix.objects.filter(roa_request__issuer=conf)):
        csv_writer.writerow([str(roapfx.as_roa_prefix()), roapfx.roa_request.asn, '%s-%d' % (conf.handle, group)])
    resp = http.HttpResponse(f.getvalue(), mimetype='application/csv')
    resp['Content-Disposition'] = 'attachment; filename=roas.csv'
    return resp


class GhostbusterDetailView(DetailView):
    def get_queryset(self):
        return self.request.session['handle'].ghostbusters


@handle_required
def ghostbuster_delete(request, pk):
    conf = request.session['handle']
    logstream = request.META['wsgi.errors']
    obj = get_object_or_404(conf.ghostbusters, pk=pk)
    if request.method == 'POST':
        form = forms.Empty(request.POST, request.FILES)
        if form.is_valid():
            obj.delete()
            Zookeeper(handle=conf.handle, logstream=logstream).run_rpkid_now()
            return http.HttpResponseRedirect(reverse(dashboard))
    else:
        form = forms.Empty(request.POST, request.FILES)
    return render(request, 'app/object_confirm_delete.html', {
        'object': obj,
        'form': form,
        'parent_template': 'app/ghostbusterrequest_detail.html'
    })


@handle_required
def ghostbuster_create(request):
    conf = request.session['handle']
    logstream = request.META['wsgi.errors']
    if request.method == 'POST':
        form = forms.GhostbusterRequestForm(request.POST, request.FILES,
                                            conf=conf)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.vcard = glue.ghostbuster_to_vcard(obj)
            obj.save()
            Zookeeper(handle=conf.handle, logstream=logstream).run_rpkid_now()
            return http.HttpResponseRedirect(reverse(dashboard))
    else:
        form = forms.GhostbusterRequestForm(conf=conf)
    return render(request, 'app/app_form.html',
                  {'form': form, 'form_title': 'New Ghostbuster Request'})


@handle_required
def ghostbuster_edit(request, pk):
    conf = request.session['handle']
    obj = get_object_or_404(conf.ghostbusters, pk=pk)
    logstream = request.META['wsgi.errors']
    if request.method == 'POST':
        form = forms.GhostbusterRequestForm(request.POST, request.FILES,
                                            conf=conf, instance=obj)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.vcard = glue.ghostbuster_to_vcard(obj)
            obj.save()
            Zookeeper(handle=conf.handle, logstream=logstream).run_rpkid_now()
            return http.HttpResponseRedirect(reverse(dashboard))
    else:
        form = forms.GhostbusterRequestForm(conf=conf, instance=obj)
    return render(request, 'app/app_form.html',
                  {'form': form, 'form_title': 'Edit Ghostbuster Request'})


@handle_required
def refresh(request):
    """
    Query rpkid, update the db, and redirect back to the dashboard.

    """
    glue.list_received_resources(request.META['wsgi.errors'],
                                 request.session['handle'])
    return http.HttpResponseRedirect(reverse(dashboard))


@handle_required
def route_view(request):
    """
    Display a list of global routing table entries which match resources
    listed in received certificates.

    """
    conf = request.session['handle']
    count = request.GET.get('count', 25)
    page = request.GET.get('page', 1)

    paginator = Paginator(conf.routes, count)
    try:
        routes = paginator.page(page)
    except InvalidPage:
        # page was empty, or page number was invalid
        routes = []
    ts = dict((attr['name'], attr['ts']) for attr in models.Timestamp.objects.values())
    return render(request, 'app/routes_view.html',
                  {'routes': routes, 'timestamp': ts})


def route_detail(request, pk):
    """Show a list of ROAs that match a given IPv4 route."""
    route = get_object_or_404(models.RouteOrigin, pk=pk)
    # when running rootd, viewing the 0.0.0.0/0 route will cause a fetch of all
    # roas, so we paginate here, even though in the general case the number of
    # objects will be small enough to fit a single page
    count = request.GET.get('count', 25)
    page = request.GET.get('page', 1)
    paginator = Paginator(route.roa_prefixes.all(), count)
    return render(request, 'app/route_detail.html', {
        'object': route,
        'roa_prefixes': paginator.page(page),
    })


def route_suggest(request):
    """Handles POSTs from the route view and redirects to the ROA creation
    page based on selected route objects.  The form should contain elements of
    the form "pk-NUM" where NUM is the RouteOrigin object id.

    """
    if request.method == 'POST':
        routes = []
        for pk in request.POST.iterkeys():
            logger.debug(pk)
            if pk.startswith("pk-"):
                n = int(pk[3:])
                routes.append(n)
        qs = RouteOrigin.objects.filter(pk__in=routes)
        s = []
        for r in qs:
            s.append('roa=%s/%d,%d' % (str(r.prefix_min), r.prefixlen, r.asn))
        p = '&'.join(s)
        return redirect(reverse(roa_create_multi) + '?' + p)


@handle_required
def repository_detail(request, pk):
    conf = request.session['handle']
    return render(request,
                  'app/repository_detail.html',
                  {'object': get_object_or_404(conf.repositories, pk=pk)})


@handle_required
def repository_delete(request, pk):
    log = request.META['wsgi.errors']
    conf = request.session['handle']
    # Ensure the repository being deleted belongs to the current user.
    obj = get_object_or_404(models.Repository, issuer=conf, pk=pk)
    if request.method == 'POST':
        form = forms.Empty(request.POST, request.FILES)
        if form.is_valid():
            z = Zookeeper(handle=conf.handle, logstream=log)
            z.delete_repository(obj.handle)
            z.synchronize_ca()
            return http.HttpResponseRedirect(reverse(dashboard))
    else:
        form = forms.Empty()
    return render(request, 'app/object_confirm_delete.html', {
        'object': obj,
        'form': form,
        'parent_template':
        'app/repository_detail.html',
    })


@handle_required
def repository_import(request):
    """Import XML response file from repository operator."""
    return generic_import(request,
                          models.Repository.objects,
                          Zookeeper.configure_repository,
                          form_class=forms.ImportRepositoryForm,
                          post_import_redirect=reverse(dashboard))


@superuser_required
def client_list(request):
    """display a list of all repository client (irdb.models.Client)"""

    return render(request, 'app/client_list.html', {
        'object_list': models.Client.objects.all()
    })


@superuser_required
def client_detail(request, pk):
    return render(request, 'app/client_detail.html',
                  {'object': get_object_or_404(models.Client, pk=pk)})


@superuser_required
def client_delete(request, pk):
    log = request.META['wsgi.errors']
    obj = get_object_or_404(models.Client, pk=pk)
    if request.method == 'POST':
        form = forms.Empty(request.POST, request.FILES)
        if form.is_valid():
            z = Zookeeper(logstream=log)
            z.delete_publication_client(obj.handle)
            z.synchronize_pubd()
            return http.HttpResponseRedirect(reverse(dashboard))
    else:
        form = forms.Empty()
    return render(request, 'app/object_confirm_delete.html', {
        'object': obj,
        'form': form,
        'parent_template': 'app/client_detail.html'
    })


@superuser_required
def client_import(request):
    return generic_import(request, models.Client.objects,
                          Zookeeper.configure_publication_client,
                          form_class=forms.ImportClientForm,
                          post_import_redirect=reverse(dashboard))


@superuser_required
def client_export(request, pk):
    """Return the XML file resulting from a configure_publication_client
    request.

    """
    client = get_object_or_404(models.Client, pk=pk)
    z = Zookeeper()
    xml = z.generate_repository_response(client)
    return serve_xml(str(xml), '%s.repo' % z.handle)


### Routines for managing resource handles serviced by this server

@superuser_required
def resource_holder_list(request):
    """Display a list of all the RPKI handles managed by this server."""
    return render(request, 'app/resource_holder_list.html', {
        'object_list': models.Conf.objects.all()
    })


@superuser_required
def resource_holder_edit(request, pk):
    """Display a list of all the RPKI handles managed by this server."""
    conf = get_object_or_404(models.Conf, pk=pk)
    if request.method == 'POST':
        form = forms.ResourceHolderForm(request.POST, request.FILES)
        if form.is_valid():
            models.ConfACL.objects.filter(conf=conf).delete()
            for user in form.cleaned_data.get('users'):
                models.ConfACL.objects.create(user=user, conf=conf)
            return redirect(resource_holder_list)
    else:
        users = [acl.user for acl in models.ConfACL.objects.filter(conf=conf).all()]
        form = forms.ResourceHolderForm(initial={
            'users': users
        })
    return render(request, 'app/app_form.html', {
        'form_title': "Edit Resource Holder: " + conf.handle,
        'form': form,
        'cancel_url': reverse(resource_holder_list)
    })


@superuser_required
def resource_holder_delete(request, pk):
    conf = get_object_or_404(models.Conf, pk=pk)
    log = request.META['wsgi.errors']
    if request.method == 'POST':
        form = forms.Empty(request.POST)
        if form.is_valid():
            z = Zookeeper(handle=conf.handle, logstream=log)
            z.delete_self()
            z.synchronize_deleted_ca()
            return redirect(resource_holder_list)
    else:
        form = forms.Empty()
    return render(request, 'app/app_confirm_delete.html', {
        'form_title': 'Delete Resource Holder: ' + conf.handle,
        'form': form,
        'cancel_url': reverse(resource_holder_list)
    })


@superuser_required
def resource_holder_create(request):
    log = request.META['wsgi.errors']
    if request.method == 'POST':
        form = forms.ResourceHolderCreateForm(request.POST, request.FILES)
        if form.is_valid():
            handle = form.cleaned_data.get('handle')
            parent = form.cleaned_data.get('parent')

            zk_child = Zookeeper(handle=handle, logstream=log)
            identity_xml = zk_child.initialize_resource_bpki()
            if parent:
                # FIXME etree_wrapper should allow us to deal with file objects
                t = NamedTemporaryFile(delete=False)
                t.close()

                identity_xml.save(t.name)
                zk_parent = Zookeeper(handle=parent.handle, logstream=log)
                parent_response, _ = zk_parent.configure_child(t.name)
                parent_response.save(t.name)
                zk_parent.synchronize_ca()
                repo_req, _ = zk_child.configure_parent(t.name)
                repo_req.save(t.name)
                repo_resp, _ = zk_parent.configure_publication_client(t.name)
                repo_resp.save(t.name)
                zk_parent.synchronize_pubd()
                zk_child.configure_repository(t.name)
                os.remove(t.name)
            zk_child.synchronize_ca()
            return redirect(resource_holder_list)
    else:
        form = forms.ResourceHolderCreateForm()
    return render(request, 'app/app_form.html', {
        'form': form,
        'form_title': 'Create Resource Holder',
        'cancel_url': reverse(resource_holder_list)
    })


### views for managing user logins to the web interface

@superuser_required
def user_create(request):
    if request.method == 'POST':
        form = forms.UserCreateForm(request.POST, request.FILES)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            pw = form.cleaned_data.get('password')
            email = form.cleaned_data.get('email')
            user = User.objects.create_user(username, email, pw)
            for conf in form.cleaned_data.get('resource_holders'):
                models.ConfACL.objects.create(user=user, conf=conf)
            return redirect(user_list)
    else:
        form = forms.UserCreateForm()

    return render(request, 'app/app_form.html', {
        'form': form,
        'form_title': 'Create User',
        'cancel_url': reverse(user_list),
    })


@superuser_required
def user_list(request):
    """Display a list of all the RPKI handles managed by this server."""
    return render(request, 'app/user_list.html', {
        'object_list': User.objects.all()
    })


@superuser_required
def user_delete(request, pk):
    user = get_object_or_404(User, pk=pk)
    if request.method == 'POST':
        form = forms.Empty(request.POST, request.FILES)
        if form.is_valid():
            user.delete()
            return redirect(user_list)
    else:
        form = forms.Empty()
    return render(request, 'app/app_confirm_delete.html', {
        'form_title': 'Delete User: ' + user.username,
        'form': form,
        'cancel_url': reverse(user_list)
    })


@superuser_required
def user_edit(request, pk):
    user = get_object_or_404(User, pk=pk)
    if request.method == 'POST':
        form = forms.UserEditForm(request.POST)
        if form.is_valid():
            pw = form.cleaned_data.get('pw')
            if pw:
                user.set_password(pw)
            user.email = form.cleaned_data.get('email')
            user.save()
            models.ConfACL.objects.filter(user=user).delete()
            handles = form.cleaned_data.get('resource_holders')
            for conf in handles:
                models.ConfACL.objects.create(user=user, conf=conf)
            return redirect(user_list)
    else:
        form = forms.UserEditForm(initial={
            'email': user.email,
            'resource_holders': models.Conf.objects.filter(confacl__user=user).all()
        })
    return render(request, 'app/app_form.html', {
        'form': form,
        'form_title': 'Edit User: ' + user.username,
        'cancel_url': reverse(user_list)
    })


class AlertListView(ListView):
    # this nonsense is required to decorate CBVs
    @method_decorator(handle_required)
    def dispatch(self, request, *args, **kwargs):
        return super(AlertListView, self).dispatch(request, *args, **kwargs)

    def get_queryset(self, **kwargs):
        conf = self.request.session['handle']
        return conf.alerts.all()


class AlertDetailView(DetailView):
    # this nonsense is required to decorate CBVs
    @method_decorator(handle_required)
    def dispatch(self, request, *args, **kwargs):
        return super(AlertDetailView, self).dispatch(request, *args, **kwargs)

    def get_queryset(self, **kwargs):
        conf = self.request.session['handle']
        return conf.alerts.all()

    def get_object(self, **kwargs):
        obj = super(AlertDetailView, self).get_object(**kwargs)
        # mark alert as read by the user
        obj.seen = True
        obj.save()
        return obj


class AlertDeleteView(DeleteView):
    success_url = reverse_lazy('alert-list')

    # this nonsense is required to decorate CBVs
    @method_decorator(handle_required)
    def dispatch(self, request, *args, **kwargs):
        return super(AlertDeleteView, self).dispatch(request, *args, **kwargs)

    def get_queryset(self, **kwargs):
        conf = self.request.session['handle']
        return conf.alerts.all()
