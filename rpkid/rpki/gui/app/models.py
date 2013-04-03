# Copyright (C) 2010  SPARTA, Inc. dba Cobham Analytic Solutions
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

__version__ = '$Id$'

from django.db import models
from django.contrib.auth.models import User

import rpki.resource_set
import rpki.exceptions
import rpki.irdb.models
import rpki.gui.models
import rpki.gui.routeview.models
from south.modelsinspector import add_introspection_rules


class TelephoneField(models.CharField):
    def __init__(self, **kwargs):
        if 'max_length' not in kwargs:
            kwargs['max_length'] = 40
        models.CharField.__init__(self, **kwargs)

add_introspection_rules([], ['^rpki\.gui\.app\.models\.TelephoneField'])


class Parent(rpki.irdb.models.Parent):
    """proxy model for irdb Parent"""

    def __unicode__(self):
        return u"%s's parent %s" % (self.issuer.handle, self.handle)

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.app.views.parent_detail', [str(self.pk)])

    class Meta:
        proxy = True


class Child(rpki.irdb.models.Child):
    """proxy model for irdb Child"""

    def __unicode__(self):
        return u"%s's child %s" % (self.issuer.handle, self.handle)

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.app.views.child_detail', [str(self.pk)])

    class Meta:
        proxy = True
        verbose_name_plural = 'children'


class ChildASN(rpki.irdb.models.ChildASN):
    """Proxy model for irdb ChildASN."""

    class Meta:
        proxy = True

    def __unicode__(self):
        return u'AS%s' % self.as_resource_range()


class ChildNet(rpki.irdb.models.ChildNet):
    """Proxy model for irdb ChildNet."""

    class Meta:
        proxy = True

    def __unicode__(self):
        return u'%s' % self.as_resource_range()


class Conf(rpki.irdb.models.ResourceHolderCA):
    """This is the center of the universe, also known as a place to
    have a handle on a resource-holding entity.  It's the <self>
    in the rpkid schema.

    """
    @property
    def parents(self):
        """Simulates irdb.models.Parent.objects, but returns app.models.Parent
        proxy objects.

        """
        return Parent.objects.filter(issuer=self)

    @property
    def children(self):
        """Simulates irdb.models.Child.objects, but returns app.models.Child
        proxy objects.

        """
        return Child.objects.filter(issuer=self)

    @property
    def ghostbusters(self):
        return GhostbusterRequest.objects.filter(issuer=self)

    @property
    def repositories(self):
        return Repository.objects.filter(issuer=self)

    @property
    def roas(self):
        return ROARequest.objects.filter(issuer=self)

    @property
    def routes(self):
        """Return all IPv4 routes covered by RPKI certs issued to this resource
        holder.

        """
        # build a Q filter to select all RouteOrigin objects covered by
        # prefixes in the resource holder's certificates
        q = models.Q()
        for p in ResourceRangeAddressV4.objects.filter(cert__conf=self):
            q |= models.Q(prefix_min__gte=p.prefix_min,
                          prefix_max__lte=p.prefix_max)
        return RouteOrigin.objects.filter(q)

    @property
    def routes_v6(self):
        """Return all IPv6 routes covered by RPKI certs issued to this resource
        holder.

        """
        # build a Q filter to select all RouteOrigin objects covered by
        # prefixes in the resource holder's certificates
        q = models.Q()
        for p in ResourceRangeAddressV6.objects.filter(cert__conf=self):
            q |= models.Q(prefix_min__gte=p.prefix_min,
                          prefix_max__lte=p.prefix_max)
        return RouteOriginV6.objects.filter(q)

    class Meta:
        proxy = True


class ResourceCert(models.Model):
    """Represents a resource certificate.

    This model is used to cache the output of <list_received_resources/>.

    """

    # Handle to which this cert was issued
    conf = models.ForeignKey(Conf, related_name='certs')

    # The parent that issued the cert.  This field is marked null=True because
    # the root has no parent
    parent = models.ForeignKey(Parent, related_name='certs', null=True)

    # certificate validity period
    not_before = models.DateTimeField()
    not_after = models.DateTimeField()

    # Locator for this object.  Used to look up the validation status, expiry
    # of ancestor certs in cacheview
    uri = models.CharField(max_length=255)

    def __unicode__(self):
        if self.parent:
            return u"%s's cert from %s" % (self.conf.handle,
                                           self.parent.handle)
        else:
            return u"%s's root cert" % self.conf.handle

    def get_cert_chain(self):
        """Return a list containing the complete certificate chain for this
        certificate."""
        cert = self
        x = [cert]
        while cert.issuer:
            cert = cert.issuer
            x.append(cert)
        x.reverse()
        return x
    cert_chain = property(get_cert_chain)


class ResourceRangeAddressV4(rpki.gui.models.PrefixV4):
    cert = models.ForeignKey(ResourceCert, related_name='address_ranges')


class ResourceRangeAddressV6(rpki.gui.models.PrefixV6):
    cert = models.ForeignKey(ResourceCert, related_name='address_ranges_v6')


class ResourceRangeAS(rpki.gui.models.ASN):
    cert = models.ForeignKey(ResourceCert, related_name='asn_ranges')


class ROARequest(rpki.irdb.models.ROARequest):
    class Meta:
        proxy = True

    def __unicode__(self):
        return u"%s's ROA request for AS%d" % (self.issuer.handle, self.asn)

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.app.views.roa_detail', [str(self.pk)])

    @property
    def routes(self):
        "Return all IPv4 routes covered by this roa prefix."
        # this assumes one prefix per ROA
        rng = self.prefixes.filter(version=4)[0].as_resource_range()
        return rpki.gui.routeview.models.RouteOrigin.objects.filter(
            prefix_min__gte=rng.min,
            prefix_max__lte=rng.max
        )

    @property
    def routes_v6(self):
        "Return all IPv6 routes covered by this roa prefix."
        # this assumes one prefix per ROA
        rng = self.prefixes.filter(version=6)[0].as_resource_range()
        return rpki.gui.routeview.models.RouteOriginV6.objects.filter(
            prefix_min__gte=rng.min,
            prefix_max__lte=rng.max
        )


class ROARequestPrefix(rpki.irdb.models.ROARequestPrefix):
    class Meta:
        proxy = True

    def __unicode__(self):
        return u'ROA Request Prefix %s' % str(self.as_roa_prefix())


class GhostbusterRequest(rpki.irdb.models.GhostbusterRequest):
    """
    Stores the information require to fill out a vCard entry to
    populate a ghostbusters record.

    This model is inherited from the irdb GhostBusterRequest model so
    that the broken out fields can be included for ease of editing.
    """

    full_name = models.CharField(max_length=40)

    # components of the vCard N type
    family_name = models.CharField(max_length=20)
    given_name = models.CharField(max_length=20)
    additional_name = models.CharField(max_length=20, blank=True, null=True)
    honorific_prefix = models.CharField(max_length=10, blank=True, null=True)
    honorific_suffix = models.CharField(max_length=10, blank=True, null=True)

    email_address = models.EmailField(blank=True, null=True)
    organization = models.CharField(blank=True, null=True, max_length=255)
    telephone = TelephoneField(blank=True, null=True)

    # elements of the ADR type
    box = models.CharField(verbose_name='P.O. Box', blank=True, null=True,
                           max_length=40)
    extended = models.CharField(blank=True, null=True, max_length=255)
    street = models.CharField(blank=True, null=True, max_length=255)
    city = models.CharField(blank=True, null=True, max_length=40)
    region = models.CharField(blank=True, null=True, max_length=40,
                              help_text='state or province')
    code = models.CharField(verbose_name='Postal Code', blank=True, null=True,
                            max_length=40)
    country = models.CharField(blank=True, null=True, max_length=40)

    def __unicode__(self):
        return u"%s's GBR: %s" % (self.issuer.handle, self.full_name)

    @models.permalink
    def get_absolute_url(self):
        return ('gbr-detail', [str(self.pk)])

    class Meta:
        ordering = ('family_name', 'given_name')


class Timestamp(models.Model):
    """Model to hold metadata about the collection of external data.

    This model is a hash table mapping a timestamp name to the
    timestamp value.  All timestamps values are in UTC.

    The utility function rpki.gui.app.timestmap.update(name) should be used to
    set timestamps rather than updating this model directly."""

    name = models.CharField(max_length=30, primary_key=True)
    ts = models.DateTimeField(null=False)

    def __unicode__(self):
        return '%s: %s' % (self.name, self.ts)


class Repository(rpki.irdb.models.Repository):
    class Meta:
        proxy = True
        verbose_name = 'Repository'
        verbose_name_plural = 'Repositories'

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.app.views.repository_detail', [str(self.pk)])

    def __unicode__(self):
        return "%s's repository %s" % (self.issuer.handle, self.handle)


class Client(rpki.irdb.models.Client):
    "Proxy model for pubd clients."

    class Meta:
        proxy = True
        verbose_name = 'Client'

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.app.views.client_detail', [str(self.pk)])

    def __unicode__(self):
        return self.handle


class RouteOrigin(rpki.gui.routeview.models.RouteOrigin):
    class Meta:
        proxy = True

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.app.views.route_detail', [str(self.pk)])


class RouteOriginV6(rpki.gui.routeview.models.RouteOriginV6):
    class Meta:
        proxy = True

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.app.views.route_detail', [str(self.pk)])


class ConfACL(models.Model):
    """Stores access control for which users are allowed to manage a given
    resource handle.

    """

    conf = models.ForeignKey(Conf)
    user = models.ForeignKey(User)

    class Meta:
        unique_together = (('user', 'conf'))


class Alert(models.Model):
    """Stores alert messages intended to be consumed by the user."""

    INFO = 0
    WARNING = 1
    ERROR = 2

    SEVERITY_CHOICES = (
        (INFO, 'info'),
        (WARNING, 'warning'),
        (ERROR, 'error'),
    )

    conf = models.ForeignKey(Conf, related_name='alerts')
    severity = models.SmallIntegerField(choices=SEVERITY_CHOICES, default=INFO)
    when = models.DateTimeField(auto_now_add=True)
    seen = models.BooleanField(default=False)
    subject = models.CharField(max_length=66)
    text = models.TextField()

    @models.permalink
    def get_absolute_url(self):
        return ('alert-detail', [str(self.pk)])
