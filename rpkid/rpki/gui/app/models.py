# $Id$
"""
Copyright (C) 2010  SPARTA, Inc. dba Cobham Analytic Solutions
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

import socket

from django.db import models
from django.contrib.auth.models import User

from rpki.gui.app.misc import str_to_range

import rpki.resource_set
import rpki.exceptions
import rpki.irdb.models

class TelephoneField(models.CharField):
    def __init__( self, **kwargs ):
        models.CharField.__init__(self, max_length=40, **kwargs)

class Parent(rpki.irdb.models.Parent):
    """proxy model for irdb Parent"""

    def __unicode__(self):
	return u"%s's parent %s" % (self.issuer.handle, self.handle)

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.app.views.parent_view', [str(self.pk)])

    class Meta:
        proxy = True

class Child(rpki.irdb.models.Child):
    """proxy model for irdb Child"""

    def __unicode__(self):
	return u"%s's child %s" % (self.issuer.handle, self.handle)

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.app.views.child_view', [str(self.pk)])

    class Meta:
        proxy = True

class Conf(rpki.irdb.models.ResourceHolderCA):
    '''This is the center of the universe, also known as a place to
    have a handle on a resource-holding entity.  It's the <self>
    in the rpkid schema.'''

    @property
    def parents(self):
        """Simulates irdb.models.Parent.objects, but returns app.models.Parent proxy objects."""
        return Parent.objects.filter(issuer=self)

    @property
    def children(self):
        """Simulates irdb.models.Child.objects, but returns app.models.Child proxy objects."""
        return Child.objects.filter(issuer=self)

    class Meta:
        proxy = True

class ResourceCert(models.Model):
    """Represents a resource certificate.

    This model is used to cache the output of <list_received_resources/>."""

    # pointer to the parent object in the irdb
    parent = models.ForeignKey(Parent, related_name='certs')

    # certificate validity period
    not_before = models.DateTimeField()
    not_after = models.DateTimeField()

    def __unicode__(self):
        return u"%s's resource cert from parent %s" % (self.parent.issuer.handle, self.parent.handle)

class ResourceRangeAddressV4(rpki.models.PrefixV4):
    cert = models.ForeignKey(ResourceCert, related_name='address_ranges')

class ResourceRangeAddressV6(rpki.models.PrefixV6):
    cert = models.ForeignKey(ResourceCert, related_name='address_ranges_v6')

class ResourceRangeAS(models.Model):
    min = models.PositiveIntegerField()
    max = models.PositiveIntegerField()
    cert = models.ForeignKey(ResourceCert, related_name='asn_ranges')

class RoaRequest(rpki.irdb.models.RoaRequest):
    class Meta:
        prefix = True

    def __unicode__(self):
        return u'roa request for asn %d' % self.asn

class RoaRequestPrefix(rpki.irdb.models.RoaRequestPrefix):
    class Meta:
        prefix = True

    def __unicode__(self):
        return u'roa request prefix %s/%d-%d for asn %d' % (self.prefix, self.prefixlen, self.max_prefixlen, self.roa_request.asn)

    def as_roa_prefix(self):
        if self.family == 4:
            r = resource_set.roa_prefix_ipv4(ipaddrs.v4addr(self.prefix), self.prefixlen, self.max_prefixlen)
        else:
            r = resource_set.roa_prefix_ipv6(ipaddrs.v6addr(self.prefix), self.prefixlen, self.max_prefixlen)
        return r

    def as_resource_range(self):
        if self.family == 4:
            r = resource_set.resource_range_ipv4.make_prefix(ipaddrs.v4addr(self.prefix), self.prefixlen)
        else:
            r = resource_set.resource_range_ipv6.make_prefix(ipaddrs.v6addr(self.prefix), self.prefixlen)
        return r

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.app.views.roa_detail', [str(self.pk)])

class Ghostbuster(models.Model):
    """
    Stores the information require to fill out a vCard entry to populate
    a ghostbusters record.
    """
    full_name = models.CharField(max_length=40)

    # components of the vCard N type
    family_name      = models.CharField(max_length=20)
    given_name       = models.CharField(max_length=20)
    additional_name  = models.CharField(max_length=20, blank=True, null=True)
    honorific_prefix = models.CharField(max_length=10, blank=True, null=True)
    honorific_suffix = models.CharField(max_length=10, blank=True, null=True)

    email_address  = models.EmailField(blank=True, null=True)
    organization   = models.CharField(blank=True, null=True, max_length=255)
    telephone      = TelephoneField(blank=True, null=True)

    # elements of the ADR type
    box      = models.CharField(verbose_name='P.O. Box', blank=True, null=True, max_length=40)
    extended = models.CharField(blank=True, null=True, max_length=255)
    street   = models.CharField(blank=True, null=True, max_length=255)
    city     = models.CharField(blank=True, null=True, max_length=40)
    region   = models.CharField(blank=True, null=True, max_length=40, help_text='state or province')
    code     = models.CharField(verbose_name='Postal Code', blank=True, null=True, max_length=40)
    country  = models.CharField(blank=True, null=True, max_length=40)

    # pointer to the IRDB object matching this ghostbuster request
    irdb = models.ForeignKey(rpki.irdb.models.Ghostbuster, related_name='app_ghostbuster')

    def __unicode__(self):
        return u"%s's GBR: %s" % (self.issuer.handle, self.full_name)

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.app.views.ghostbuster_view', [str(self.pk)])

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

# vim:sw=4 ts=8 expandtab
