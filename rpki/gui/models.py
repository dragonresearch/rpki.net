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
Common classes for reuse in apps.
"""

__version__ = '$Id$'

from django.db import models

import rpki.resource_set
import rpki.POW


class IPAddressField(models.CharField):
    """
    Field class for rpki.POW.IPAddress, stored as zero-padded
    hexadecimal so lexicographic order is identical to numeric order.
    """

    # Django's CharField type doesn't distinguish between the length
    # of the human readable form and the length of the storage form,
    # so we have to leave room for IPv6 punctuation even though we
    # only store hexadecimal digits and thus will never use the full
    # width of the database field.  Price we pay for portability.
    #
    # Documentation on the distinction between the various conversion
    # methods is fairly opaque, to put it politely, and we have to
    # handle database engines which sometimes return buffers or other
    # classes instead of strings, so the conversions are a bit
    # finicky.  If this goes haywire, your best bet is probably to
    # litter the code with logging.debug() calls and debug by printf.

    def __init__(self, *args, **kwargs):
        kwargs["max_length"] = 40
        super(IPAddressField, self).__init__(*args, **kwargs)

    def deconstruct(self):
        name, path, args, kwargs = super(IPAddressField, self).deconstruct()
        del kwargs["max_length"]
        return name, path, args, kwargs

    @staticmethod
    def _value_to_ipaddress(value):
        if value is None or isinstance(value, rpki.POW.IPAddress):
            return value
        value = str(value)
        if ":" in value or "." in value:
            return rpki.POW.IPAddress(value)
        else:
            return rpki.POW.IPAddress.fromBytes(value.decode("hex"))

    def from_db_value(self, value, expression, connection, context):
        # Can't use super() here, see Django documentation.
        return self._value_to_ipaddress(value)

    def to_python(self, value):
        return self._value_to_ipaddress(
            super(IPAddressField, self).to_python(value))

    @staticmethod
    def _hex_from_ipaddress(value):
        if isinstance(value, rpki.POW.IPAddress):
            return value.toBytes().encode("hex")
        else:
            return value

    def get_prep_value(self, value):
        return super(IPAddressField, self).get_prep_value(
            self._hex_from_ipaddress(value))

    def get_db_prep_value(self, value, connection, prepared = False):
        return self._hex_from_ipaddress(
            super(IPAddressField, self).get_db_prep_value(value, connection, prepared))


class Prefix(models.Model):
    """Common implementation for models with an IP address range.

    Expects that `range_cls` is set to the appropriate subclass of
    rpki.resource_set.resource_range_ip."""

    def as_resource_range(self):
        """
        Returns the prefix as a rpki.resource_set.resource_range_ip object.
        """

        return self.range_cls(self.prefix_min, self.prefix_max)

    @property
    def prefixlen(self):
        "Returns the prefix length for the prefix in this object."
        return self.as_resource_range().prefixlen()

    def get_prefix_display(self):
        "Return a string representatation of this IP prefix."
        return str(self.as_resource_range())

    def __unicode__(self):
        """This method may be overridden by subclasses.  The default
        implementation calls get_prefix_display(). """

        return self.get_prefix_display()

    class Meta:
        abstract = True

        # default sort order reflects what "sh ip bgp" outputs
        ordering = ('prefix_min',)


class PrefixV4(Prefix):
    "IPv4 Prefix."

    range_cls = rpki.resource_set.resource_range_ipv4

    prefix_min = IPAddressField(db_index=True, null=False)
    prefix_max = IPAddressField(db_index=True, null=False)

    class Meta(Prefix.Meta):
        abstract = True


class PrefixV6(Prefix):
    "IPv6 Prefix."

    range_cls = rpki.resource_set.resource_range_ipv6

    prefix_min = IPAddressField(db_index=True, null=False)
    prefix_max = IPAddressField(db_index=True, null=False)

    class Meta(Prefix.Meta):
        abstract = True


class ASN(models.Model):
    """Represents a range of ASNs.

    This model is abstract, and is intended to be reused by applications."""

    min = models.PositiveIntegerField(null=False)
    max = models.PositiveIntegerField(null=False)

    class Meta:
        abstract = True
        ordering = ('min', 'max')

    def as_resource_range(self):
        return rpki.resource_set.resource_range_as(self.min, self.max)

    def __unicode__(self):
        return u'AS%s' % self.as_resource_range()

# vim:sw=4 ts=8 expandtab
