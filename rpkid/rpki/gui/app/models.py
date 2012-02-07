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

import rpki.resource_set
import rpki.exceptions
import rpki.irdb.models
import rpki.gui.models


class TelephoneField(models.CharField):
    def __init__(self, **kwargs):
        models.CharField.__init__(self, max_length=40, **kwargs)


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
        return ('rpki.gui.app.views.child_view', [str(self.pk)])

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

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.app.views.user_detail', [str(self.pk)])

    class Meta:
        proxy = True


class ResourceCert(models.Model):
    """Represents a resource certificate.

    This model is used to cache the output of <list_received_resources/>.

    """
    # pointer to the parent object in the irdb
    parent = models.ForeignKey(Parent, related_name='certs')

    # certificate validity period
    not_before = models.DateTimeField()
    not_after = models.DateTimeField()

    # Locator for this object.  Used to look up the validation status, expiry
    # of ancestor certs in cacheview
    uri = models.CharField(max_length=255)

    def __unicode__(self):
        return u"%s's cert from %s" % (self.parent.issuer.handle,
                                       self.parent.handle)


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


class ROARequestPrefix(rpki.irdb.models.ROARequestPrefix):
    class Meta:
        proxy = True
        verbose_name = 'roa'

    def __unicode__(self):
        return u'ROA request prefix %s for asn %d' % (str(self.as_roa_prefix()),
                                                      self.roa_request.asn)

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.app.views.roa_detail', [str(self.pk)])


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
        return ('rpki.gui.app.views.ghostbuster_view', [str(self.pk)])

    class Meta:
        ordering = ('family_name', 'given_name')
        verbose_name = 'ghostbuster'


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
        verbose_name_plural = 'repositories'

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.app.views.repository_detail', [str(self.pk)])

    def __unicode__(self):
        return "%s's repository %s" % (self.issuer.handle, self.handle)


class Client(rpki.irdb.models.Client):
    "Proxy model for pubd clients."

    class Meta:
        proxy = True

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.app.views.client_detail', [str(self.pk)])

    def __unicode__(self):
        return self.handle
