# Copyright (C) 2011  SPARTA, Inc. dba Cobham Analytic Solutions
# Copyright (C) 2013  SPARTA, Inc. a Parsons Company
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

__version__ = '$Id$'

from django.views.generic import DetailView
from django.shortcuts import render
from django.db.models import F

from rpki.gui.cacheview import models, forms, misc
from rpki.resource_set import resource_range_as, resource_range_ip
from rpki.POW import IPAddress
from rpki.exceptions import BadIPResource


def cert_chain(obj):
    """
    returns an iterator covering all certs from the root cert down to the EE.
    """
    chain = [obj]
    while obj != obj.issuer:
        obj = obj.issuer
        chain.append(obj)
    return zip(range(len(chain)), reversed(chain))


class SignedObjectDetailView(DetailView):
    def get_context_data(self, **kwargs):
        context = super(SignedObjectDetailView,
                        self).get_context_data(**kwargs)
        context['chain'] = cert_chain(self.object)
        return context


class RoaDetailView(SignedObjectDetailView):
    model = models.ROA


class CertDetailView(SignedObjectDetailView):
    model = models.Cert


class GhostbusterDetailView(SignedObjectDetailView):
    model = models.Ghostbuster


def search_view(request):
    certs = None
    roas = None

    if request.method == 'POST':
        form = forms.SearchForm2(request.POST, request.FILES)
        if form.is_valid():
            resource = form.cleaned_data.get('resource')
            # try to determine the type of input given
            try:
                r = resource_range_as.parse_str(resource)
                certs = models.Cert.objects.filter(asns__min__gte=r.min,
                                                   asns__max__lte=r.max)
                roas = models.ROA.objects.filter(asid__gte=r.min,
                                                 asid__lte=r.max)
            except:
                try:
                    r = resource_range_ip.parse_str(resource)
                    if r.version == 4:
                        certs = models.Cert.objects.filter(
                            addresses__prefix_min__lte=r.min,
                            addresses__prefix_max__gte=r.max)
                        roas = models.ROA.objects.filter(
                            prefixes__prefix_min__lte=r.min,
                            prefixes__prefix_max__gte=r.max)
                    else:
                        certs = models.Cert.objects.filter(
                            addresses_v6__prefix_min__lte=r.min,
                            addresses_v6__prefix_max__gte=r.max)
                        roas = models.ROA.objects.filter(
                            prefixes_v6__prefix_min__lte=r.min,
                            prefixes_v6__prefix_max__gte=r.max)
                except BadIPResource:
                    pass

    return render(request, 'cacheview/search_result.html',
                  {'resource': resource, 'certs': certs, 'roas': roas})


def cmp_prefix(x, y):
    r = cmp(x[0].family, y[0].family)
    if r == 0:
        r = cmp(x[2], y[2])  # integer address
        if r == 0:
            r = cmp(x[0].bits, y[0].bits)
            if r == 0:
                r = cmp(x[0].max_length, y[0].max_length)
                if r == 0:
                    r = cmp(x[1].asid, y[1].asid)
    return r


#def cmp_prefix(x,y):
#    for attr in ('family', 'prefix', 'bits', 'max_length'):
#        r = cmp(getattr(x[0], attr), getattr(y[0], attr))
#        if r:
#            return r
#    return cmp(x[1].asid, y[1].asid)


def query_view(request):
    """
    Allow the user to search for an AS or prefix, and show all published ROA
    information.
    """

    if request.method == 'POST':
        form = forms.SearchForm(request.POST, request.FILES)
        if form.is_valid():
            certs = None
            roas = None

            addr = form.cleaned_data.get('addr')
            asn = form.cleaned_data.get('asn')

            if addr:
                family, r = misc.parse_ipaddr(addr)
                prefixes = models.ROAPrefix.objects.filter(family=family, prefix=str(r.min))

                prefix_list = []
                for pfx in prefixes:
                    for roa in pfx.roas.all():
                        prefix_list.append((pfx, roa))
            elif asn:
                r = resource_range_as.parse_str(asn)
                roas = models.ROA.objects.filter(asid__gte=r.min, asid__lte=r.max)

                # display the results sorted by prefix
                prefix_list = []
                for roa in roas:
                    for pfx in roa.prefixes.all():
                        addr = IPAddress(pfx.prefix.encode())
                        prefix_list.append((pfx, roa, addr))
                prefix_list.sort(cmp=cmp_prefix)

            return render('cacheview/query_result.html',
                    {'object_list': prefix_list}, request)
    else:
        form = forms.SearchForm()

    return render('cacheview/search_form.html', {
        'form': form, 'search_type': 'ROA '}, request)


def global_summary(request):
    """Display a table summarizing the state of the global RPKI."""

    roots = models.Cert.objects.filter(issuer=F('pk'))  # self-signed

    return render(request, 'cacheview/global_summary.html', {
        'roots': roots
    })

# vim:sw=4 ts=8 expandtab
