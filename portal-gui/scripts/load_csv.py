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

import rpki
import rpki.resource_set
import rpki.ipaddrs
from rpki.myrpki import csv_reader

from rpkigui.myrpki import models
from rpkigui.myrpki.views import update_roas
from rpkigui.myrpki.asnset import asnset

cfg_file = os.getenv("MYRPKI_CONF", "myrpki.conf")
cfg = rpki.config.parser(cfg_file, "myrpki")
handle = cfg.get('handle')
asn_csv = cfg.get('asn_csv')
prefix_csv = cfg.get('prefix_csv')
roa_csv = cfg.get('roa_csv')

conf = models.Conf.objects.get(handle=handle)

for asn, child_handle in csv_reader(asn_csv, columns=2):
    child = conf.children.get(conf=conf, handle=child_handle)
    asn = models.Asn.objects.get(lo=asn, hi=asn,
            from_cert__parent__in=conf.parents.all())
    child.asn.add(asn)

def prefix_to_range(s):
    """returns a tuple of (lo,hi) of the address range specified by a prefix"""
    net, bits = prefix.split('/')
    addr = rpki.resource_set.resource_range_ipv4.make_prefix(rpki.ipaddrs.v4addr(net), int(bits))
    return str(addr.min), str(addr.max)

for prefix, child_handle in csv_reader(prefix_csv, columns=2):
    child = conf.children.get(conf=conf, handle=child_handle)
    addr = prefix_to_range(prefix)
    obj = models.AddressRange.objects.get(lo=addr[0], hi=addr[1],
            from_cert__parent__in=conf.parents.all())
    child.address_range.add(obj)

for prefix, asn, group in csv_reader(roa_csv, columns=3):
    addr = prefix_to_range(prefix)
    obj = models.AddressRange.objects.get(lo=addr[0], hi=addr[1],
            from_cert__parent__in=conf.parents.all())
    roa_asns = asnset(obj.asns)
    asid = int(asn)
    if asid not in roa_asns:
        roa_asns.add(asid)
        obj.asns = str(roa_asns)
        obj.save()
        update_roas(conf, obj)
