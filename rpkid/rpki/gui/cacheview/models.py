# Copyright (C) 2011  SPARTA, Inc. dba Cobham Analytic Solutions
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

from datetime import datetime
import time

from django.db import models

import rpki.ipaddrs
import rpki.resource_set
import rpki.gui.models


class TelephoneField(models.CharField):
    def __init__(self, *args, **kwargs):
        kwargs['max_length'] = 255
        models.CharField.__init__(self, *args, **kwargs)


class AddressRange(rpki.gui.models.PrefixV4):
    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.cacheview.views.addressrange_detail', [str(self.pk)])


class AddressRangeV6(rpki.gui.models.PrefixV6):
    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.cacheview.views.addressrange_detail_v6',
                [str(self.pk)])


class ASRange(rpki.gui.models.ASN):
    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.cacheview.views.asrange_detail', [str(self.pk)])

kinds = list(enumerate(('good', 'warn', 'bad')))
kinds_dict = dict((v, k) for k,v in kinds)


class ValidationLabel(models.Model):
    """
    Represents a specific error condition defined in the rcynic XML
    output file.
    """
    label = models.CharField(max_length=79, db_index=True, unique=True, null=False)
    status = models.CharField(max_length=255, null=False)
    kind = models.PositiveSmallIntegerField(choices=kinds, null=False)

    def __unicode__(self):
        return self.label

generations = list(enumerate(('current', 'backup')))
generations_dict = dict((val, key) for (key, val) in generations)


class ValidationStatus(models.Model):
    timestamp = models.DateTimeField(null=False)
    generation = models.PositiveSmallIntegerField(choices=generations, null=True)
    status = models.ForeignKey('ValidationLabel', null=False)

    class Meta:
        abstract = True


class SignedObject(models.Model):
    """
    Abstract class to hold common metadata for all signed objects.
    The signing certificate is ommitted here in order to give a proper
    value for the 'related_name' attribute.
    """
    # attributes from rcynic's output XML file
    uri = models.URLField(unique=True, db_index=True, null=False)

    # on-disk file modification time
    mtime = models.PositiveIntegerField(default=0, null=False)

    # SubjectName
    name = models.CharField(max_length=255, null=False)

    # value from the SKI extension
    keyid = models.CharField(max_length=60, db_index=True, null=False)

    # validity period from EE cert which signed object
    not_before = models.DateTimeField(null=False)
    not_after = models.DateTimeField(null=False)

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
        return None  # should not happen

    def __unicode__(self):
        return u'%s' % self.name


class Cert(SignedObject):
    """
    Object representing a resource certificate.
    """
    addresses = models.ManyToManyField(AddressRange, related_name='certs')
    addresses_v6 = models.ManyToManyField(AddressRangeV6, related_name='certs')
    asns = models.ManyToManyField(ASRange, related_name='certs')
    issuer = models.ForeignKey('Cert', related_name='children', null=True, blank=True)
    sia = models.CharField(max_length=255, null=False)

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.cacheview.views.cert_detail', [str(self.pk)])


class ValidationStatus_Cert(ValidationStatus):
    cert = models.ForeignKey('Cert', related_name='statuses', null=False)


class ROAPrefix(models.Model):
    "Abstract base class for ROA mixin."

    max_length = models.PositiveSmallIntegerField(null=False)

    class Meta:
        abstract = True

    def as_roa_prefix(self):
        "Return value as a rpki.resource_set.roa_prefix_ip object."
        rng = self.as_resource_range()
        return self.roa_cls(rng.prefix_min, rng.prefixlen(), self.max_length)

    def __unicode__(self):
        p = self.as_resource_range()
        if p.prefixlen() == self.max_length:
            return str(p)
        return '%s-%s' % (str(p), self.max_length)


# ROAPrefix is declared first, so subclass picks up __unicode__ from it.
class ROAPrefixV4(ROAPrefix, rpki.gui.models.PrefixV4):
    "One v4 prefix in a ROA."

    roa_cls = rpki.resource_set.roa_prefix_ipv4

    class Meta:
        ordering = ('prefix_min',)


# ROAPrefix is declared first, so subclass picks up __unicode__ from it.
class ROAPrefixV6(ROAPrefix, rpki.gui.models.PrefixV6):
    "One v6 prefix in a ROA."

    roa_cls = rpki.resource_set.roa_prefix_ipv6

    class Meta:
        ordering = ('prefix_min',)


class ROA(SignedObject):
    asid = models.PositiveIntegerField(null=False)
    prefixes = models.ManyToManyField(ROAPrefixV4, related_name='roas')
    prefixes_v6 = models.ManyToManyField(ROAPrefixV6, related_name='roas')
    issuer = models.ForeignKey('Cert', related_name='roas', null=False)

    @models.permalink
    def get_absolute_url(self):
        return ('rpki.gui.cacheview.views.roa_detail', [str(self.pk)])

    class Meta:
        ordering = ('asid',)

    def __unicode__(self):
        return u'ROA for AS%d' % self.asid


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
