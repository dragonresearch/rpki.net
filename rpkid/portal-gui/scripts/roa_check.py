#!/usr/bin/env python
# $Id$
#
# Runs through all the published ROAs and updates the Django DB with the
# current active status of each defined ROA.
#

import socket

from rcynic_output_iterator import rcynic_xml_iterator, rcynic_roa
from rpki.resource_set import resource_set_ipv4, resource_set_ipv6
from rpki.resource_set import roa_prefix_set_ipv4, roa_prefix_set_ipv6
from rpki.resource_set import resource_range_ipv4, resource_range_ipv6
from rpki.ipaddrs import v4addr, v6addr

from rpki.gui.app.models import Roa

# build up a list of all the authenticated roa's using the asn as the key
roaiter = rcynic_xml_iterator(
        rcynic_root='/home/melkins/rcynic/rcynic-data/',
        xml_file='/home/melkins/rcynic/rcynic.xml')

# key is an ASN
# each element is a tuple of (resource_set_ipv4, resource_set_ipv6)
roaauth = {}

for roa in roaiter:
    if isinstance(roa, rcynic_roa):
        k = roa.asID
        if not roaauth.has_key(k):
            v = [resource_set_ipv4(), resource_set_ipv6()]
            roaauth[k] = v
        else:
            v = roaauth[k]
        for pfx in roa.prefix_sets:
            if isinstance(pfx, roa_prefix_set_ipv4):
                v[0] = v[0].union(pfx.to_resource_set())
            elif isinstance(pfx, roa_prefix_set_ipv6):
                v[1] = v[1].union(pfx.to_resource_set())

#for k, v in roaauth.iteritems():
#    print 'asn %d : prefixes %s' % (k, ' '.join(map(str,v)))

# run through all the ROA's in the GUI's database
for roa in Roa.objects.all():
    k = int(roa.asn)
    valid = False
    if roaauth.has_key(k):
        # ensure that all prefixes listed in the roa are present
        # we convert the list of prefixes into prefix sets and use the
        # resource_set class to perform set comparisons
        ipv4_set = resource_set_ipv4()
        ipv6_set = resource_set_ipv6()
        for pfx in roa.prefix.all():
            # IP addresses are just stored as strings in the sqlite db
            try:
                ipv4_set.append(resource_range_ipv4(v4addr(str(pfx.lo)), v4addr(str(pfx.hi))))
            except socket.error:
                ipv6_set.append(resource_range_ipv6(v6addr(str(pfx.lo)), v6addr(str(pfx.hi))))
        r = roaauth[k]
        if ipv4_set.issubset(r[0]) and ipv6_set.issubset(r[1]):
            valid = True
    if valid:
        if not roa.active:
            roa.active = True
            roa.save()
    else:
        print 'roa for asn %s is not valid' % (roa.asn, )
        if roa.active:
            roa.active = False
            roa.save()
