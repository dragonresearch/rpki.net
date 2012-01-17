# Common classes for resuse in apps

import struct

from django.db import models

import rpki.resource_set
import rpki.ipaddrs

class IPv6AddressField(models.Field):
    "Field large enough to hold a 128-bit unsigned integer."

    __metaclass__ = models.SubfieldBase

    def db_type(self, connection):
        return 'binary(16)'

    def to_python(self, value):
        if isinstance(value, rpki.ipaddrs.v6addr):
            return value
        x = struct.unpack('!QQ', value)
        return rpki.ipaddrs.v6addr((x[0] << 64) | x[1])

    def get_db_prep_value(self, value, connection, prepared):
        return struct.pack('!QQ', (long(value) >> 64) & 0xFFFFFFFFFFFFFFFFL, long(value) & 0xFFFFFFFFFFFFFFFFL)

class IPv4AddressField(models.Field):
    "Wrapper around rpki.ipaddrs.v4addr."

    __metaclass__ = models.SubfieldBase

    def db_type(self, connection):
        return 'int UNSIGNED'

    def to_python(self, value):
        if isinstance(value, rpki.ipaddrs.v4addr):
            return value
        return rpki.ipaddrs.v4addr(value)

    def get_db_prep_value(self, value, connection, prepared):
        return long(value)

class Prefix(models.Model):
    """Common implementation for models with an IP address range.

    Expects that `range_cls` is set to the appropriate subclass of
    rpki.resource_set.resource_range_ip."""

    def as_resource_range(self):
        """
        Returns the prefix as a rpki.resource_set.resource_range_ip object.
        """
        return self.range_cls(self.prefix_min, self.prefix_max)

    def prefixlen(self):
        "Returns the prefix length for the prefix in this object."
        return self.as_range().prefixlen()

    def get_prefix_display(self):
        "Returns a string version of the prefix in this object."
        return str(self.as_resource_range())

    class Meta:
        abstract = True
        
        # default sort order reflects what "sh ip bgp" outputs
        ordering = ('prefix_min',)

class PrefixV4(Prefix):
    "IPv4 Prefix."

    range_cls = rpki.resource_set.resource_range_ipv4

    prefix_min = IPv4AddressField(db_index=True, null=False)
    prefix_max = IPv4AddressField(db_index=True, null=False)

    class Meta:
        abstract = True

class PrefixV6(Prefix):
    "IPv6 Prefix."

    range_cls = rpki.resource_set.resource_range_ipv6

    prefix_min = IPv6AddressField(db_index=True, null=False)
    prefix_max = IPv6AddressField(db_index=True, null=False)

    class Meta:
        abstract = True

# vim:sw=4 ts=8 expandtab
