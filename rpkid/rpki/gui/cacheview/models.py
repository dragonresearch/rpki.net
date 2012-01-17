"""
Copyright (C) 2011  SPARTA, Inc. dba Cobham Analytic Solutions

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

from datetime import datetime
import time

from django.db import models

import rpki.ipaddrs
import rpki.resource_set

class TelephoneField(models.CharField):
    def __init__(self, *args, **kwargs):
        kwargs['max_length'] = 255
        models.CharField.__init__(self, *args, **kwargs)

class AddressRange(models.Model):
    """Represents an IP address range.

    The db backend doesn't support unsigned 64-bit integer, so store
    the /63 in the database, and have the display function regenerate
    the full value.  since nothing larger than a /48 should be
    announced globally, it should be ok to pad the lower 65 bits of
    `max` with 1s.  """

    family = models.PositiveSmallIntegerField(null=False)
    min = models.BigIntegerField(null=False)
    max = models.BigIntegerField(null=False)

    def get_min_display(self):
        "Return the min address value as an rpki.ipaddr object."
        return rpki.ipaddrs.v4addr(self.min) if self.family == 4 else rpki.ipaddrs.v6addr(self.min << 65)

    def get_max_display(self):
        "Return the max address value as an rpki.ipaddr object."
        # FIXME this may fail for an IPv6 /64 single block, since we
        # don't store the lower 65 bits in the database
        return rpki.ipaddrs.v4addr(self.max) if self.family == 4 else rpki.ipaddrs.v6addr((self.max << 65) | 0x1ffffffffffffffffL)

    class Meta:
        ordering = ('family', 'min', 'max')

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.cacheview.views.addressrange_detail', [str(self.pk)])

    def as_resource_range(self):
        cls = rpki.resource_set.resource_range_ipv4 if self.family == 4 else rpki.resource_set.resource_range_ipv6
        return cls(self.get_min_display(), self.get_max_display())

    def __unicode__(self):
        return u'%s' % self.as_resource_range()

class ASRange(models.Model):
    min = models.PositiveIntegerField(null=False)
    max = models.PositiveIntegerField(null=False)

    class Meta:
        ordering = ('min', 'max')

    def __unicode__(self):
        if self.min == self.max:
            return u'AS%d' % self.min
        else:
            return u'AS%s-%s' % (self.min, self.max)

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.cacheview.views.asrange_detail', [str(self.pk)])

kinds = list(enumerate(('good', 'warn', 'bad')))
kinds_dict = dict((v,k) for k,v in kinds)

class ValidationLabel(models.Model):
    """
    Represents a specific error condition defined in the rcynic XML
    output file.
    """
    label = models.CharField(max_length=79, db_index=True, unique=True)
    status = models.CharField(max_length=255, null=False)
    kind = models.PositiveSmallIntegerField(choices=kinds, null=False)

    def __unicode__(self):
        return self.label

    class Meta:
        verbose_name_plural = 'ValidationLabels'

generations = list(enumerate(('current', 'backup')))
generations_dict = dict((val, key) for (key, val) in generations)

class ValidationStatus(models.Model):
    timestamp  = models.DateTimeField(null=False)
    generation = models.PositiveSmallIntegerField(choices=generations, null=True)
    status     = models.ForeignKey('ValidationLabel', null=False)

    class Meta:
        abstract = True

class SignedObject(models.Model):
    """
    Abstract class to hold common metadata for all signed objects.
    The signing certificate is ommitted here in order to give a proper
    value for the 'related_name' attribute.
    """
    # attributes from rcynic's output XML file
    uri        = models.URLField(unique=True, db_index=True, null=False)

    # on-disk file modification time
    mtime      = models.PositiveIntegerField(default=0, null=False)

    # SubjectName
    name  = models.CharField(max_length=255, null=False)

    # value from the SKI extension
    keyid = models.CharField(max_length=60, db_index=True, null=False)

    # validity period from EE cert which signed object
    not_before = models.DateTimeField(null=False)
    not_after  = models.DateTimeField(null=False)

    class Meta:
        abstract = True

    def mtime_as_datetime(self):
        """
        convert the local timestamp to UTC and convert to a datetime object
        """
        return datetime.utcfromtimestamp(self.mtime + time.timezone)

    def is_valid(self):
        """
        Returns a boolean value indicating whether this object has passed
        validation checks.
        """
        return bool(self.statuses.filter(status=ValidationLabel.objects.get(label="object_accepted")))

    def status_id(self):
        """
        Returns a HTML class selector for the current object based on its validation status.
        The selector is chosen based on the current generation only.  If there is any bad status,
        return bad, else if there are any warn status, return warn, else return good.
        """
        for x in reversed(kinds):
            if self.statuses.filter(generation=generations_dict['current'], status__kind=x[0]):
                return x[1]
        return None # should not happen

    def __unicode__(self):
        return u'%s' % self.name

class Cert(SignedObject):
    """
    Object representing a resource certificate.
    """
    addresses = models.ManyToManyField(AddressRange, related_name='certs')
    asns      = models.ManyToManyField(ASRange, related_name='certs')
    issuer    = models.ForeignKey('Cert', related_name='children', null=True, blank=True)
    sia       = models.CharField(max_length=255, null=False)

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.cacheview.views.cert_detail', [str(self.pk)])

class ValidationStatus_Cert(ValidationStatus):
    cert = models.ForeignKey('Cert', related_name='statuses',
            null=False)

class ROAPrefix(models.Model):
    """One prefix in a ROA.

    See comment above in AddressRange about how IPv6 addresses are
    stored.

    The prefix is broken out into min and max values rather than min/bits in
    order to allow for searches using sql.  """

    family     = models.PositiveSmallIntegerField(null=False)
    prefix_min = models.BigIntegerField(null=False, db_index=True)
    prefix_max = models.BigIntegerField(null=False, db_index=True)
    max_length = models.PositiveSmallIntegerField(null=False)

    class Meta:
        ordering = ('prefix_min', 'prefix_max', 'max_length')
        verbose_name_plural = 'ROAPrefixes'

    def min(self):
        "Return the min prefix value as an rpki.ipaddrs.v?addr object."
        if self.family == 4:
            return rpki.ipaddrs.v4addr(self.prefix_min)
        return rpki.ipaddrs.v6addr(self.prefix_min << 65)

    def max(self):
        "Return the max prefix value as an rpki.ipaddrs.v?addr object."
        if self.family == 4:
            return rpki.ipaddrs.v4addr(self.prefix_max)
        return rpki.ipaddrs.v6addr((self.prefix_max << 65) | 0x1ffffffffffffffffL)

    def get_prefix_min_display(self):
        return str(self.min())

    def get_prefix_max_display(self):
        return str(self.max())

    def as_resource_range(self):
        "Return the prefix as a rpki.resource_set.resource_range_ip object."
        if self.family == 4:
            return rpki.resource_set.resource_range_ipv4(self.min(), self.max())
        else:
            return rpki.resource_set.resource_range_ipv6((self.min() << 65),
                    (self.max() << 65) | 0x1ffffffffffffffffL)

    def as_roa_prefix(self):
        "Return value as a rpki.resource_set.roa_prefix_ip object."
        rng = self.as_resource_range()
        cls = rpki.resource_set.roa_prefix_ipv4 if self.family == 4 else rpki.resource_set.roa_prefix_ipv6
        return cls(rng.min, rng.prefixlen(), self.max_length)

    def __unicode__(self):
        return u'%s' % str(self.as_roa_prefix())

class ROA(SignedObject):
    asid     = models.PositiveIntegerField(null=False)
    prefixes = models.ManyToManyField(ROAPrefix, related_name='roas')
    issuer   = models.ForeignKey('Cert', related_name='roas', null=False)

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.cacheview.views.roa_detail', [str(self.pk)])

    class Meta:
        ordering = ('asid',)

    def __unicode__(self):
        return u'ROA for AS%d' % self.asid

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.cacheview.views.roa_detail', [str(self.pk)])

class ValidationStatus_ROA(ValidationStatus):
    roa = models.ForeignKey('ROA', related_name='statuses', null=False)

class Ghostbuster(SignedObject):
    full_name = models.CharField(max_length=40)
    email_address = models.EmailField(blank=True, null=True)
    organization = models.CharField(blank=True, null=True, max_length=255)
    telephone = TelephoneField(blank=True, null=True)
    issuer = models.ForeignKey('Cert', related_name='ghostbusters', null=False)

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.cacheview.views.ghostbuster_detail', [str(self.pk)])

    def __unicode__(self):
        if self.full_name:
            return self.full_name
        if self.organization:
            return self.organization
        if self.email_address:
            return self.email_address
        return self.telephone

class ValidationStatus_Ghostbuster(ValidationStatus):
    gbr = models.ForeignKey('Ghostbuster', related_name='statuses', null=False)

# vim:sw=4 ts=8 expandtab
