# $Id$

import rpki.resource_set
import rpki.ipaddrs

def str_to_range(lo, hi):
    """Convert IP address strings to resource_range_ip."""
    x = rpki.ipaddrs.parse(lo)
    y = rpki.ipaddrs.parse(hi)
    assert type(x) == type(y)
    if isinstance(x, rpki.ipaddrs.v4addr):
        return rpki.resource_set.resource_range_ipv4(x, y)
    else:
        return rpki.resource_set.resource_range_ipv6(x, y)

# vim:sw=4 ts=8 expandtab
