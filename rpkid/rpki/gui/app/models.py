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

class IPAddressField(models.CharField):
    def __init__( self, **kwargs ):
        models.CharField.__init__(self, max_length=40, **kwargs)

class TelephoneField(models.CharField):
    def __init__( self, **kwargs ):
        models.CharField.__init__(self, max_length=40, **kwargs)

class Conf(rpki.irdb.models.ResourceHolderCA):
    '''This is the center of the universe, also known as a place to
    have a handle on a resource-holding entity.  It's the <self>
    in the rpkid schema.'''

    owner = models.ManyToManyField(User)

    def __unicode__(self):
	return self.handle

class Child(rpki.irdb.models.Child):
    irdb_child = models.OneToOneField('rpki.irdb.models.Child', parent_link=True, null=False, related_name='app_child')

    def __unicode__(self):
	return u"%s's child %s" % (self.issuer.handle, self.handle)

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.app.views.child_view', [str(self.pk)])

class AddressRange(models.Model):
    '''An address range/prefix.'''
    lo = IPAddressField(blank=False)
    hi = IPAddressField(blank=False)
    # parent address range
    parent = models.ForeignKey('AddressRange', related_name='children',
            blank=True, null=True)
    # child to which this resource is delegated
    allocated = models.ForeignKey(Child, related_name='address_range',
            blank=True, null=True)

    class Meta:
        ordering = ('lo', 'hi')

    def __unicode__(self):
        if self.lo == self.hi:
            return u"%s" % (self.lo,)

        try:
            # pretty print cidr
            return unicode(self.as_resource_range())
        except socket.error, err:
            print err
        # work around for bug when hi/lo get reversed
        except AssertionError, err:
            print err
        return u'%s - %s' % (self.lo, self.hi)

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.app.views.address_view', [str(self.pk)])

    def as_resource_range(self):
        '''Convert to rpki.resource_set.resource_range_ip.'''
        return str_to_range(self.lo, self.hi)

    def is_prefix(self):
        '''Returns True if this address range can be represented as a
        prefix.'''
        try:
            self.as_resource_range().prefixlen()
        except rpki.exceptions.MustBePrefix, err:
            return False
        return True

class Asn(models.Model):
    '''An ASN or range thereof.'''
    lo = models.IntegerField(blank=False)
    hi = models.IntegerField(blank=False)
    # parent asn range
    parent = models.ForeignKey('Asn', related_name='children',
            blank=True, null=True)
    # child to which this resource is delegated
    allocated = models.ForeignKey(Child, related_name='asn',
            blank=True, null=True)

    class Meta:
        ordering = ('lo', 'hi')

    def __unicode__(self):
	if self.lo == self.hi:
	    return u"ASN %d" % (self.lo,)
	else:
	    return u"ASNs %d - %d" % (self.lo, self.hi)

    #__unicode__.admin_order_field = 'lo'

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.app.views.asn_view', [str(self.pk)])

    def as_resource_range(self):
        # we force conversion to long() here because resource_range_as() wants
        # the type of both arguments to be identical, and models.IntegerField
        # will be a long when the value is large
        return rpki.resource_set.resource_range_as(long(self.lo), long(self.hi))

class Parent(rpki.irdb.models.Parent):
    """Represents a RPKI parent.

    This model uses multi-table inheritance from rpki.irdb.Parent
    such that information can be used.  This model exists solely as
    an adapter for purposes of the web portal."""

    irdb_parent = models.OneToOneField('rpki.irdb.models.Parent', parent_link=True, null=False, related_name='app_parent')

    def __unicode__(self):
	return u"%s's parent %s" % (self.issuer.handle, self.handle)

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.app.views.parent_view', [str(self.pk)])

class ResourceCert(models.Model):
    parent = models.ForeignKey(Parent, related_name='resources')

    # resources granted from my parent
    asn = models.ManyToManyField(Asn, related_name='from_cert', blank=True,
            null=True)
    address_range = models.ManyToManyField(AddressRange,
            related_name='from_cert', blank=True, null=True)

    # unique id for this resource certificate
    # FIXME: URLField(verify_exists=False) doesn't seem to work - the admin
    # editor won't accept a rsync:// scheme as valid
    uri = models.CharField(max_length=200)

    # certificate validity period
    not_before = models.DateTimeField()
    not_after = models.DateTimeField()

    def __unicode__(self):
        return u"%s's resource cert from parent %s" % (self.parent.conf.handle,
                self.parent.handle)

class Roa(models.Model):
    '''Maps an ASN to the set of prefixes it can originate routes for.
    This differs from a real ROA in that prefixes from multiple
    parents/resource certs can be selected.  The glue module contains
    code to split the ROAs into groups by common resource certs.'''

    conf = models.ForeignKey(Conf, related_name='roas')
    asn = models.IntegerField()
    active = models.BooleanField()

    # the resource cert from which all prefixes for this roa are derived
    cert = models.ForeignKey(ResourceCert, related_name='roas')

    def __unicode__(self):
	return u"%s's ROA for %d" % (self.conf, self.asn)

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.app.views.roa_view', [str(self.pk)])

class RoaRequest(models.Model):
    roa = models.ForeignKey(Roa, related_name='from_roa_request')
    max_length = models.IntegerField()
    prefix = models.ForeignKey(AddressRange, related_name='roa_requests')

    def __unicode__(self):
        return u'roa request for asn %d on %s-%d' % (self.roa.asn, self.prefix,
                self.max_length)

    def as_roa_prefix(self):
        '''Convert to a rpki.resouce_set.roa_prefix subclass.'''
        r = self.prefix.as_resource_range()
        if isinstance(r, rpki.resource_set.resource_range_ipv4):
            return rpki.resource_set.roa_prefix_ipv4(r.min, r.prefixlen(),
                    self.max_length)
        else:
            return rpki.resource_set.roa_prefix_ipv6(r.min, r.prefixlen(),
                    self.max_length)

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.app.views.roa_request_view', [str(self.pk)])

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

    conf   = models.ForeignKey(Conf, related_name='ghostbusters')
    # parent can be null when using the same record for all parents
    parent = models.ManyToManyField(Parent, related_name='ghostbusters',
            blank=True, null=True, help_text='use this record for a specific parent, or leave blank for all parents')

    def __unicode__(self):
        return u"%s's GBR: %s" % (self.conf, self.full_name)

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.app.views.ghostbuster_view', [str(self.pk)])

    class Meta:
        ordering = ( 'family_name', 'given_name' )

# vim:sw=4 ts=8 expandtab
