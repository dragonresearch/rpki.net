# Copyright (C) 2011  SPARTA, Inc. dba Cobham Analytic Solutions
# Copyright (C) 2012, 2016  SPARTA, Inc. a Parsons Company
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

__version__ = '$Id: $'

from django.db import models

import rpki.resource_set
import rpki.gui.models
import rpki.rcynicdb.models


class TelephoneField(models.CharField):
    def __init__(self, *args, **kwargs):
        kwargs['max_length'] = 255
        models.CharField.__init__(self, *args, **kwargs)


class AddressRange(rpki.gui.models.PrefixV4): pass


class AddressRangeV6(rpki.gui.models.PrefixV6): pass


class ASRange(rpki.gui.models.ASN): pass


class SignedObject(models.Model):
    """
    Abstract class to hold common metadata for all signed objects.
    The signing certificate is ommitted here in order to give a proper
    value for the 'related_name' attribute.
    """

    class Meta:
        abstract = True

    # Duplicate of rpki.rcynicdb.models.RPKIObject
    uri = models.TextField()

    # validity period from EE cert which signed object
    not_before = models.DateTimeField()
    not_after = models.DateTimeField()

    def __unicode__(self):
        return u'%s' % self.uri

    def __repr__(self):
        return u'<%s name=%s uri=%s>' % (self.__class__.__name__, self.uri)


class Cert(SignedObject):
    """
    Object representing a resource CA certificate.
    """
    # Duplicate of rpki.rcynicdb.models.RPKIObject
    ski = models.SlugField(max_length=40) # hex SHA-1

    addresses = models.ManyToManyField(AddressRange, related_name='certs')
    addresses_v6 = models.ManyToManyField(AddressRangeV6, related_name='certs')
    asns = models.ManyToManyField(ASRange, related_name='certs')

    issuer = models.ForeignKey('self', on_delete=models.CASCADE, null=True)

    def __repr__(self):
        return u'<Cert uri=%s ski=%s not_before=%s not_after=%s>' % (self.uri, self.ski, self.not_before, self.not_after)

    def __unicode__(self):
        return u'RPKI CA Cert %s' % (self.uri,)

    def get_cert_chain(self):
        """Return a list containing the complete certificate chain for this
        certificate."""

        cert = self
        x = [cert]
        while cert != cert.issuer:
            cert = cert.issuer
            x.append(cert)
        x.reverse()
        return x
    cert_chain = property(get_cert_chain)


class ROAPrefix(models.Model):
    "Abstract base class for ROA mixin."

    max_length = models.PositiveSmallIntegerField()

    class Meta:
        abstract = True

    def as_roa_prefix(self):
        "Return value as a rpki.resource_set.roa_prefix_ip object."
        rng = self.as_resource_range()
        return self.roa_cls(rng.min, rng.prefixlen(), self.max_length)

    def __unicode__(self):
        p = self.as_resource_range()
        if p.prefixlen() == self.max_length:
            return str(p)
        return '%s-%s' % (str(p), self.max_length)


# ROAPrefix is declared first, so subclass picks up __unicode__ from it.
class ROAPrefixV4(ROAPrefix, rpki.gui.models.PrefixV4):
    "One v4 prefix in a ROA."

    roa_cls = rpki.resource_set.roa_prefix_ipv4

    @property
    def routes(self):
        """return all routes covered by this roa prefix"""

        return RouteOrigin.objects.filter(prefix_min__gte=self.prefix_min,
                                          prefix_max__lte=self.prefix_max)

    class Meta:
        ordering = ('prefix_min',)


# ROAPrefix is declared first, so subclass picks up __unicode__ from it.
class ROAPrefixV6(ROAPrefix, rpki.gui.models.PrefixV6):
    "One v6 prefix in a ROA."

    roa_cls = rpki.resource_set.roa_prefix_ipv6

    class Meta:
        ordering = ('prefix_min',)


class ROA(SignedObject):
    asid = models.PositiveIntegerField()
    prefixes = models.ManyToManyField(ROAPrefixV4, related_name='roas')
    prefixes_v6 = models.ManyToManyField(ROAPrefixV6, related_name='roas')
    issuer = models.ForeignKey(Cert, on_delete=models.CASCADE, null=True, related_name='roas')

    class Meta:
        ordering = ('asid',)

    def __unicode__(self):
        return u'ROA for AS%d' % self.asid


class Ghostbuster(SignedObject):
    full_name = models.CharField(max_length=40)
    email_address = models.EmailField(blank=True, null=True)
    organization = models.CharField(blank=True, null=True, max_length=255)
    telephone = TelephoneField(blank=True, null=True)
    issuer = models.ForeignKey(Cert, on_delete=models.CASCADE, null=True, related_name='ghostbusters')

    def __unicode__(self):
        if self.full_name:
            return self.full_name
        if self.organization:
            return self.organization
        if self.email_address:
            return self.email_address
        return self.telephone


from rpki.gui.routeview.models import RouteOrigin
