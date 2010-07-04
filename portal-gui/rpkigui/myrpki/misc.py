# $Id$

import socket
import rpki.resource_set
import rpki.ipaddrs

def str_to_range(lo, hi):
    """Convert IP address string to resourcce_range_ip."""
    try:
        v = rpki.resource_set.resource_range_ipv4(rpki.ipaddrs.v4addr(str(lo)), rpki.ipaddrs.v4addr(str(hi)))
    except socket.error:
        v = rpki.resource_set.resource_range_ipv6(rpki.ipaddrs.v6addr(str(lo)), rpki.ipaddrs.v6addr(str(hi)))
    return v

# vim:sw=4 ts=8 expandtab
