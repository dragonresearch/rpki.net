# $Id$

from __future__ import with_statement

import os
import os.path
import math
import rpki
from rpki.myrpki import csv_writer
from rpki.resource_set import resource_range_ipv4
from rpki.ipaddrs import v4addr
from django.conf import settings

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
    cmd = 'python ' + settings.MYRPKI_SRC_DIR + '/myrpki.py ' + ' '.join(['--config=' + config] + args)
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

def output_asns(path, handle):
    '''Write out csv file containing resources delegated to my children.'''
    f = csv_writer(path)
    for p in handle.children.all():
        for asn in p.asn.all():
            if asn.lo == asn.hi:
                f.writerow([p.handle, asn.lo])

def output_prefixes(path, handle):
    '''Write out csv file containing resources delegated to my children.'''
    confdir = settings.MYRPKI_DATA_DIR + '/' + handle.handle
    f = csv_writer(path)
    for p in handle.children.all():
        for prefix in p.address_range.all():
            f.writerow([p.handle, '%s-%s' % (prefix.lo, prefix.hi)])

def output_roas(path, handle):
    f = csv_writer(path)
    for roa in handle.roas.all():
        for req in roa.from_roa_request.all():
            f.writerow([req.as_roa_prefix(), roa.asn,
                '%s-group-%d' % (handle.handle, roa.pk)])

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
