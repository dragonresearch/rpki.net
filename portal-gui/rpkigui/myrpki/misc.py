# $Id$

import socket
import rpki.resource_set
import rpki.ipaddrs

def str_to_addr(s):
    '''Convert an IP address string to either a v4addr or v6addr.'''
    if isinstance(s, unicode):
        s = s.encode() # v{4,6}addr require plain string
    try:
        return rpki.ipaddrs.v4addr(s)
    except socket.error:
        return rpki.ipaddrs.v6addr(s)

def str_to_range(lo, hi):
    """Convert IP address strings to resourcce_range_ip."""
    x = str_to_addr(lo)
    y = str_to_addr(hi)
    assert type(x) == type(y)
    if isinstance(x, rpki.ipaddrs.v4addr):
        return rpki.resource_set.resource_range_ipv4(x, y)
    else:
        return rpki.resource_set.resource_range_ipv6(x, y)

# vim:sw=4 ts=8 expandtab
