import binascii

from django.db import models

import rpki
import rpki.resource_set
import rpki.ipaddrs

class PositiveHugeIntegerField(models.Field):

    description = "Represents a 128-bit unsigned integer."

    __metaclass__ = models.SubfieldBase

    def db_type(self, connection):
        if connection.settings_dict['ENGINE'] == 'django.db.backends.mysql':
            return 'binary(16)'
        return 'blob'

    def to_python(self, value):
        if isinstance(value, int):
            return long(value)
        if isinstance(value, long):
            return value
        return long(binascii.hexlify(value), 16)

    def get_db_prep_value(self, value, connection, prepared=False):
        return binascii.unhexlify('%032x' % value)

class RouteOrigin(models.Model):

    asn = models.PositiveIntegerField(help_text='origin AS')
    family = models.PositiveSmallIntegerField(help_text='IP version')

    # address stored as unsigned integer to faciliate lookups
    prefix_min = PositiveHugeIntegerField()
    prefix_max = PositiveHugeIntegerField()

    def as_range(self):
        """
        Returns the prefix as a rpki.resource_set.resource_range_ip object.
        """
        cls = rpki.resource_set.resource_range_ipv4 if self.family == 4 else rpki.resource_set.resource_range_ipv6
        ipcls = rpki.ipaddrs.v4addr if self.family == 4 else rpki.ipaddrs.v6addr
        return cls(ipcls(self.prefix_min), ipcls(self.prefix_max))

    def get_prefix_display(self):
        """
        Returns a string version of the prefix in the routing entry.
        """
        return str(self.as_range())

    def prefixlen(self):
        """
        Returns the prefix length for this route object.
        """
        return self.as_range().prefixlen()

    def __unicode__(self):
        return u"AS%d's route origin for %s" % (self.asn, self.get_prefix_display())

    class Meta:
        # sort order reflects what "sh ip bgp" outputs
        ordering = ( 'family', 'prefix_min', 'prefix_max', 'asn' )

        unique_together = ('family', 'asn', 'prefix_min', 'prefix_max')

# vim:sw=4 ts=8 expandtab
