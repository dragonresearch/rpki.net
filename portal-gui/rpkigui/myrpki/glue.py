"""
Copyright (C) 2010  SPARTA, Inc. dba Cobham Analytic Solutions

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND SPARTA DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL SPARTA BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

# $Id$

from __future__ import with_statement

import os
import os.path
import csv
import sys

from django.conf import settings
from django.db.models import F

import rpki
import rpki.config

from rpkigui.myrpki import models

#def form_to_conf(data):
#    """Write out a myrpki.conf based on the given form data."""
#    handle = data['handle']
#    confdir = settings.MYRPKI_DATA_DIR + '/' + handle
#    if os.path.exists(confdir):
#        raise RuntimeError, '%s: directory already exists!' % (confdir, )
#    os.makedirs(confdir)
#    template = open(settings.MYRPKI_DATA_DIR + '/examples/myrpki.conf', 'r').read()
#    # stuff the appropriate output directory into the dict
#    data['MYRPKI_DATA_DIR'] = confdir
#    with open(confdir + '/myrpki.conf', 'w') as conf:
#        print >>conf, template % data
#    invoke_rpki(handle, ['initialize'])

def invoke_rpki(handle, args):
    """Invoke the myrpki cli for the specified configuration."""
    config = settings.MYRPKI_DATA_DIR + '/' + handle + '/myrpki.conf'
    # default myrpki.conf uses relative paths, so chdir() to the repo first
    os.chdir(settings.MYRPKI_DATA_DIR + '/' + handle)
    cmd = '%s %s %s' % (sys.executable, settings.MYRPKI_PATH,
                        ' '.join(['--config=' + config] + args))
    print 'invoking', cmd
    os.system(cmd)

def read_identity(handle):
    fname = settings.MYRPKI_DATA_DIR + '/' + handle + '/entitydb/identity.xml'
    with open(fname, 'r') as fp:
        data = fp.read()
    return data

def read_child_response(handle, child):
    fname = '%s/%s/entitydb/children/%s.xml' % (settings.MYRPKI_DATA_DIR, handle, child)
    with open(fname, 'r') as fp:
        data = fp.read()
    return data

# FIXME - remove this once rpki.myrpki.csv_writer is an object with a
# .file field
def csv_writer(f):
  return csv.writer(f, dialect = csv.get_dialect("excel-tab"))

def output_asns(path, handle):
    '''Write out csv file containing asns delegated to my children.'''
    qs = models.Asn.objects.filter(lo=F('hi'), allocated__in=handle.children.all())
    with open(path, 'w') as f:
        w = csv_writer(f)
        w.writerows([asn.allocated.handle, asn.lo] for asn in qs)

def output_prefixes(path, handle):
    '''Write out csv file containing prefixes delegated to my children.'''
    qs = models.AddressRange.objects.filter(allocated__in=handle.children.all())
    with open(path, 'w') as f:
        w = csv_writer(f)
        w.writerows([p.allocated.handle, p.as_resource_range()] for p in qs)

def output_roas(path, handle):
    '''Write out csv file containing my roas.'''
    qs = models.RoaRequest.objects.filter(roa__in=handle.roas.all())
    with open(path, 'w') as f:
        w = csv_writer(f)
        w.writerows([req.as_roa_prefix(), req.roa.asn,
            '%s-group-%d' % (handle.handle, req.roa.pk)] for req in qs)

def configure_resources(handle):
    '''Write out the csv files and invoke the myrpki.py command line tool.'''
    # chdir to the repo dir since the default myrpki.conf uses relative
    # pathnames..
    os.chdir(settings.MYRPKI_DATA_DIR + '/' + handle.handle)
    cfg = rpki.config.parser('myrpki.conf', 'myrpki')
    output_asns(cfg.get('asn_csv'), handle)
    output_prefixes(cfg.get('prefix_csv'), handle)
    output_roas(cfg.get('roa_csv'), handle)
    run_rpkid = cfg.getboolean('run_rpkid')
    cmd = 'daemons' if run_rpkid else 'resources'
    invoke_rpki(handle.handle, ['configure_' + cmd])
    # handle the hosted case where some communication between rpkid operator
    # and resource holder is required
    if not run_rpkid:
        xml_path = cfg.get('xml_filename')
        if xml_path[0] != '/':
            # convert to full path
            xml_path = '%s/%s/%s' % (settings.MYRPKI_DATA_DIR, handle.handle, xml_path)
        # send the myrpki.xml to the rpkid hosting me
        invoke_rpki(handle.parents.all()[0].handle, ['configure_daemons', xml_path])
        # process the response
        invoke_rpki(handle.handle, ['configure_resources'])

# vim:sw=4 ts=8 expandtab
