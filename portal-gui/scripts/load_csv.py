#!/usr/bin/env python
# $Id$
#
# Helper script to load existing data from csv into the Django DB.
# Primarly useful for the initial load, as the GUI does not sync changes
# made directly to the csv files back into the database.
#
# This script should be run from the directory containing the myrpki.conf
# for the handle you are loading data
#

import os
import csv
import socket # for socket.error

import rpki
import rpki.resource_set
import rpki.ipaddrs
from rpki.myrpki import csv_reader

from rpkigui.myrpki import models
from rpkigui.myrpki.views import add_roa_requests

cfg_file = os.getenv("MYRPKI_CONF", "myrpki.conf")
cfg = rpki.config.parser(cfg_file, "myrpki")
handle = cfg.get('handle')
asn_csv = cfg.get('asn_csv')
prefix_csv = cfg.get('prefix_csv')
roa_csv = cfg.get('roa_csv')

print 'processing csv files for resource handle', handle

conf = models.Conf.objects.get(handle=handle)

# every parent has a favorite
def best_child(parent, parent_range):
    '''Return the child address range that is the closest match, or
    returns the arguments if no children.'''
    best = None
    best_range = None
    for q in parent.children.all():
        if best is None:
            best = q
            best_range = q.as_resource_range()
        else:
            t = q.as_resource_range()
            if t.min >= best_range.min and t.max <= best_range.max:
                best = q
                best_range = t
    if best:
        if best.children.all():
            best, best_range = best_child(best, best_range)
        return (best, best_range)

    return parent, parent_range

def get_or_create_prefix(address_range):
    '''Returns a AddressRange object for the resource_range_ip specified
    as an argument.  If no match is found, a new AddressRange object is
    created as a child of the best matching received resource.'''

    # get all resources from our parents
    prefix_set = models.AddressRange.objects.filter(
            from_cert__parent__in=conf.parents.all())

    # gross, since we store the address ranges as strings in the django
    # db, we can't use the normal __lte and __gte filters, so we get to
    # do it in python instead.
    for prefix in prefix_set:
        prefix_range = prefix.as_resource_range()
        if (prefix_range.min <= address_range.min and
                prefix_range.max >= address_range.max):
            # there should only ever be a single matching prefix
            break
    else:
        raise RuntimeError, '%s does not match any received address range.' % (
                address_range,)

    # find the best match among the children + grandchildren
    prefix, prefix_range = best_child(prefix, prefix_range)

    print 'best match for %s is %s' % (address_range, prefix)
    if prefix_range.min != address_range.min or prefix_range.max != address_range.max:
        # create suballocation
        print 'creating new range' 
        prefix = models.AddressRange.objects.create(lo=str(address_range.min),
                hi=str(address_range.max), parent=prefix)

    return prefix

def get_or_create_asn(asn):
    asn_set = models.Asn.objects.filter(lo__lte=asn.min, hi__gte=asn.max,
            from_cert__parent__in=conf.parents.all())
    if not asn_set:
        raise RuntimeError, '%s does not match any received AS range' % (asn,)
    best = None
    for a in asn_set:
        if best is None:
            best = a
        elif a.lo >= best.lo and a.hi <= best.hi:
            best = a
    print 'best match for %s is %s' % (asn, best)
    if best.lo != asn.min or best.hi != asn.max:
        best = models.Asn.objects.create(lo=asn.min, hi=asn.max, parent=best)
    return best

def do_asns():
    for child_handle, asn in csv_reader(asn_csv, columns=2):
        asn_range = rpki.resource_set.resource_range_as.parse_str(asn)
        child = conf.children.get(handle=child_handle)
        asn = get_or_create_asn(asn_range)
        child.asn.add(asn)

def do_prefixes():
    for child_handle, prefix in csv_reader(prefix_csv, columns=2):
        child = conf.children.get(handle=child_handle)
        try:
            rs = rpki.resource_set.resource_range_ipv4.parse_str(prefix)
        except ValueError, err:
            rs = rpki.resource_set.resource_range_ipv6.parse_str(prefix)
        obj = get_or_create_prefix(rs)
        obj.allocated = child
        obj.save()

def do_roas():
    for prefix, asn, group in csv_reader(roa_csv, columns=3):
        try:
            rs = rpki.resource_set.roa_prefix_ipv4.parse_str(prefix)
        except ValueError, err:
            rs = rpki.resource_set.roa_prefix_ipv6.parse_str(prefix)

        print str(rs.min()), str(rs.max()), rs.max_prefixlen
        obj = get_or_create_prefix(rs.to_resource_range())
        add_roa_requests(conf, obj, [int(asn)], rs.max_prefixlen)

do_asns()
do_prefixes()
do_roas()
