# $Id$
"""
Copyright (C) 2010, 2011  SPARTA, Inc. dba Cobham Analytic Solutions

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
import stat
import sys

from django.db.models import F

import rpki
import rpki.config

from rpki.gui import settings
from rpki.gui.app import models

def conf(handle):
    return settings.CONFDIR + '/' + handle

#def form_to_conf(data):
#    """Write out a rpki.conf based on the given form data."""
#    handle = data['handle']
#    confdir = settings.MYRPKI_DATA_DIR + '/' + handle
#    if os.path.exists(confdir):
#        raise RuntimeError, '%s: directory already exists!' % (confdir, )
#    os.makedirs(confdir)
#    template = open(settings.MYRPKI_DATA_DIR + '/examples/rpki.conf', 'r').read()
#    # stuff the appropriate output directory into the dict
#    data['MYRPKI_DATA_DIR'] = confdir
#    with open(confdir + '/rpki.conf', 'w') as conf:
#        print >>conf, template % data
#    invoke_rpki(handle, ['initialize'])

def invoke_rpki(log, handle, args):
    """Invoke the myrpki cli for the specified configuration."""
    myrpki_dir = conf(handle)
    config = myrpki_dir + '/rpki.conf'
    # default rpki.conf uses relative paths, so chdir() to the repo first
    cmd = 'cd %s && %s %s' % (myrpki_dir, settings.MYRPKI, ' '.join(['--config=' + config] + args))
    print >>log, 'invoking', cmd
    os.system(cmd)

def read_file_from_handle(handle, fname):
    """read a filename relative to the directory for the given resource handle.  returns
    a tuple of (content, mtime)"""
    with open(conf(handle) + '/' + fname, 'r') as fp:
        data = fp.read()
        mtime = os.fstat(fp.fileno())[stat.ST_MTIME]
    return data, mtime

#def read_identity(handle):
#    fname = settings.MYRPKI_DATA_DIR + '/' + handle + '/entitydb/identity.xml'
#    with open(fname, 'r') as fp:
#        data = fp.read()
#    return data
read_identity = lambda h: read_file_from_handle(h, 'entitydb/identity.xml')[0]

def read_child_response(handle, child):
    fname = '%s/entitydb/children/%s.xml' % (conf(handle), child)
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

def configure_daemons(log, handle):
    args = ['configure_daemons']
    for hosted in handle.hosting.all():
        args.append(conf(hosted.handle) + '/myrpki.xml')
    invoke_rpki(log, handle.handle, args)

def configure_resources(log, handle):
    '''Write out the csv files and invoke the myrpki.py command line tool.'''
    # chdir to the repo dir since the default rpki.conf uses relative
    # pathnames..
    os.chdir(conf(handle.handle))
    cfg = rpki.config.parser('rpki.conf', 'myrpki')
    output_asns(cfg.get('asn_csv'), handle)
    output_prefixes(cfg.get('prefix_csv'), handle)
    output_roas(cfg.get('roa_csv'), handle)
    run_rpkidemo = cfg.getboolean('run_rpkidemo', False)
    if not run_rpkidemo:
        run_rpkid = cfg.getboolean('run_rpkid')
        if run_rpkid:
            configure_daemons(log, handle)
        else:
            invoke_rpki(log, handle.handle, ['configure_resources'])

            # send the myrpki.xml to the rpkid hosting me
            configure_daemons(log, handle.host)

            # process the response
            invoke_rpki(log, handle.handle, ['configure_resources'])

# vim:sw=4 ts=8 expandtab
