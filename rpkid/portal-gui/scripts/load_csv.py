# $Id$
#
# Copyright (C) 2010, 2011  SPARTA, Inc. dba Cobham Analytic Solutions
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
#
#
# Helper script to load existing data from csv into the Django DB.
# Primarly useful for the initial load, as the GUI does not sync changes
# made directly to the csv files back into the database.
#
# This script should be run from the directory containing the rpki.conf
# for the handle you are loading data
#

import os
os.environ['DJANGO_SETTINGS_MODULE'] = 'rpki.gui.settings'

import csv
import socket # for socket.error

import rpki.resource_set, rpki.ipaddrs
from rpki.myrpki import csv_reader
from rpki.gui.app import models
from rpki.gui.app.views import add_roa_requests

cfg = rpki.config.parser(section='myrpki')
handle = cfg.get('handle')
asn_csv = cfg.get('asn_csv')
prefix_csv = cfg.get('prefix_csv')
roa_csv = cfg.get('roa_csv')

print 'processing csv files for resource handle', handle

conf = models.Conf.objects.get(handle=handle)

class RangeError(Exception):
    """
    Problem with ASN range or address range.
    """

# every parent has a favorite
def best_child(address_range, parent, parent_range):
    '''Return the child address range that is the closest match, or
    returns the arguments if no children.'''
    if address_range == parent_range:
        return (parent, parent_range)
    for q in list(parent.children.all()): # force strict evaluation
        t = q.as_resource_range()
        if t.min <= address_range.min and t.max >= address_range.max:
            return best_child(address_range, q, t)
        # check for overlap
        if t.min <= address_range.min <= t.max or t.min <= address_range.max <= t.max:
            raise RangeError, \
                    'can not handle overlapping ranges: %s and %s' % (address_range, t)
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
        raise RangeError, '%s does not match any received address range.' % (
                address_range,)

    # find the best match among the children + grandchildren
    prefix, prefix_range = best_child(address_range, prefix, prefix_range)

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
        raise RangeError, '%s does not match any received AS range' % (asn,)
    best = best_child(asn, asn_set[0], asn_set[0].as_resource_range())[0]
    print 'best match for %s is %s' % (asn, best)
    if best.lo != asn.min or best.hi != asn.max:
        best = models.Asn.objects.create(lo=asn.min, hi=asn.max, parent=best)
    return best

def do_asns():
    print 'processing', asn_csv
    for child_handle, asn in csv_reader(asn_csv, columns=2):
        asn_range = rpki.resource_set.resource_range_as.parse_str(asn)
        child = conf.children.get(handle=child_handle)
        asn = get_or_create_asn(asn_range)
        child.asn.add(asn)

def do_prefixes():
    print 'processing', prefix_csv
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
    print 'processing', roa_csv
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
