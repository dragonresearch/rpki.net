from __future__ import with_statement

import os
import os.path
import csv
import math
import rpki.myrpki
from rpki.resource_set import resource_range_ipv4
from rpki.ipaddrs import v4addr
import settings

def form_to_conf(data):
    """Write out a myrpki.conf based on the given form data."""
    handle = data['handle']
    confdir = settings.MYRPKI_DATA_DIR + '/' + handle
    if os.path.exists(confdir):
        raise RuntimeError, '%s: directory already exists!' % (confdir, )
    os.makedirs(confdir)
    template = open(settings.MYRPKI_DATA_DIR + '/examples/myrpki.conf', 'r').read()
    # stuff the appropriate output directory into the dict
    data['MYRPKI_DATA_DIR'] = confdir
    with open(confdir + '/myrpki.conf', 'w') as conf:
        print >>conf, template % data
    invoke_rpki(handle, ['initialize'])

def invoke_rpki(handle, args):
    """Invoke the myrpki cli for the specified configuration."""
    config = settings.MYRPKI_DATA_DIR + '/' + handle + '/myrpki.conf'
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

def output_asns(handle):
    '''Write out csv file containing resources delegated to my children.'''
    confdir = settings.MYRPKI_DATA_DIR + '/' + handle.handle
    f = csv.writer(open(confdir + '/asns.csv', 'w'), delimiter='\t')
    for p in handle.children.all():
        for asn in p.asn.all():
            if asn.lo == asn.hi:
                f.writerow([p.handle, asn.lo])

def output_prefixes(handle):
    '''Write out csv file containing resources delegated to my children.'''
    confdir = settings.MYRPKI_DATA_DIR + '/' + handle.handle
    f = csv.writer(open(confdir + '/prefixes.csv', 'w'), delimiter='\t')
    for p in handle.children.all():
            for prefix in p.address_range.all():
                    f.writerow([p.handle, '%s-%s' % (prefix.lo, prefix.hi)])

def output_roas(handle):
    confdir = settings.MYRPKI_DATA_DIR + '/' + handle.handle
    f = csv.writer(open(confdir + '/roas.csv', 'w'), delimiter='\t')
    for r in handle.roas.all():
        for addr in r.prefix.all():
            f.writerow([resource_range_ipv4(v4addr(str(addr.lo)), v4addr(str(addr.hi))),
                r.asn, handle.handle])

def configure_resources(handle):
    # write out the .csv files and invoke the myrpki command line tool
    output_asns(handle)
    output_prefixes(handle)
    output_roas(handle)
    #invoke_rpki(handle.handle, ['configure_daemons'])
