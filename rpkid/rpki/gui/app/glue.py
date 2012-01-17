# $Id$
"""
Copyright (C) 2010, 2011  SPARTA, Inc. dba Cobham Analytic Solutions
Copyright (C) 2012  SPARTA, Inc. a Parsons Company

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

from __future__ import with_statement

import os, os.path, csv, stat, sys
from datetime import datetime, timedelta

from django.db.models import F

import rpki
import rpki.left_right
import rpki.publication
from rpki.irdb.zookeeper import Zookeeper
from rpki.gui.app import models, settings

def confpath(*handle):
    """
    Return the absolute pathname to the configuration directory for the
    given resource handle.  If additional arguments are given, they are
    taken to mean files/subdirectories relative to the configuration
    directory.

    """
    argv = [ settings.CONFDIR ]
    argv.extend(handle)
    return os.path.join(*argv)

def read_file_from_handle(handle, fname):
    """
    read a filename relative to the directory for the given resource
    handle.  returns a tuple of (content, mtime)

    """
    with open(confpath(handle, fname), 'r') as fp:
        data = fp.read()
        mtime = os.fstat(fp.fileno())[stat.ST_MTIME]
    return data, mtime

read_identity = lambda h: read_file_from_handle(h, 'entitydb/identity.xml')[0]

def output_asns(path, handle):
    """Write out csv file containing asns delegated to my children."""
    qs = models.Asn.objects.filter(lo=F('hi'), allocated__in=handle.children.all())
    w = rpki.myrpki.csv_writer(path)
    w.writerows([asn.allocated.handle, asn.lo] for asn in qs)
    w.close()

def output_prefixes(path, handle):
    """Write out csv file containing prefixes delegated to my children."""
    qs = models.AddressRange.objects.filter(allocated__in=handle.children.all())
    w = rpki.myrpki.csv_writer(path)
    w.writerows([p.allocated.handle, p.as_resource_range()] for p in qs)
    w.close()

def output_roas(path, handle):
    """Write out csv file containing my roas."""
    qs = models.RoaRequest.objects.filter(roa__in=handle.roas.all())
    w = rpki.myrpki.csv_writer(path)
    w.writerows([req.as_roa_prefix(), req.roa.asn,
                '%s-group-%d' % (handle.handle, req.roa.pk)] for req in qs)
    w.close()

def qualify_path(pfx, fname):
    """Ensure 'path' is an absolute filename."""
    return fname if fname.startswith('/') else os.path.join(pfx, fname)

def ghostbuster_to_vcard(gbr):
    """Convert a Ghostbuster object into a vCard object."""
    import vobject

    vcard = vobject.vCard()
    vcard.add('N').value = vobject.vcard.Name(family=gbr.family_name, given=gbr.given_name)

    adr_fields = [ 'box', 'extended', 'street', 'city', 'region', 'code', 'country' ]
    adr_dict = dict((f, getattr(gbr, f, '')) for f in adr_fields)
    if any(adr_dict.itervalues()):
        vcard.add('ADR').value = vobject.vcard.Address(**adr_dict)

    # mapping from vCard type to Ghostbuster model field
    # the ORG type is a sequence of organization unit names, so
    # transform the org name into a tuple before stuffing into the
    # vCard object
    attrs = [ ('FN',    'full_name',      None),
              ('TEL',   'telephone',      None),
              ('ORG',   'organization',   lambda x: (x,)),
              ('EMAIL', 'email_address',  None) ]
    for vtype, field, transform in attrs:
        v = getattr(gbr, field)
        if v:
            vcard.add(vtype).value = transform(v) if transform else v
    return vcard.serialize()

def qualify_path(pfx, fname):
    """Ensure 'path' is an absolute filename."""
    return fname if fname.startswith('/') else os.path.join(pfx, fname)

def configure_resources(log, handle):
    """
    This function should be called when resources for this resource
    holder have changed.  It updates IRDB and notifies rpkid to
    immediately process the changes, rather than waiting for the cron
    job to run.

    For backwards compatability (and backups), it also writes the csv
    files for use with the myrpki.py command line script.

    """
    path = confpath(handle.handle)

    # Read rpki.conf to determine the paths for the csv files.
    if handle.host:
        cfg = rpki.config.parser(os.path.join(path, 'rpki.conf'), section='myrpki')
    else:
        # Use the system rpki.conf for the self-hosted handle.
        cfg = get_system_config()

    output_asns(qualify_path(path, cfg.get('asn_csv')), handle)
    output_prefixes(qualify_path(path, cfg.get('prefix_csv')), handle)
    output_roas(qualify_path(path, cfg.get('roa_csv')), handle)

    roa_requests = []
    for roa in handle.roas.all():
        v4 = rpki.resource_set.roa_prefix_set_ipv4()
        v6 = rpki.resource_set.roa_prefix_set_ipv6()
        for req in roa.from_roa_request.all():
            pfx = req.as_roa_prefix()
            if isinstance(pfx, rpki.resource_set.roa_prefix_ipv4):
                v4.append(pfx)
            else:
                v6.append(pfx)
        roa_requests.append((roa.asn, v4, v6))

    children = []
    for child in handle.children.all():
        asns = rpki.resource_set.resource_set_as([a.as_resource_range() for a in child.asn.all()])

        v4 = rpki.resource_set.resource_set_ipv4()
        v6 = rpki.resource_set.resource_set_ipv6()
        for pfx in child.address_range.all():
            rng = pfx.as_resource_range()
            if isinstance(rng, rpki.resource_set.resource_range_ipv4):
                v4.append(rng)
            else:
                v6.append(rng)
            
        # Convert from datetime.datetime to rpki.sundial.datetime
        valid_until = rpki.sundial.datetime.fromdatetime(child.valid_until)
        children.append((child.handle, asns, v4, v6, valid_until))

    ghostbusters = []
    for gbr in handle.ghostbusters.all():
        vcard = ghostbuster_to_vcard(gbr)
        parent_set = gbr.parent.all()
        if parent_set:
            for p in parent_set:
                ghostbusters.append((p, vcard))
        else:
            ghostbusters.append((None, vcard))

    z.synchronize([handle])

def list_received_resources(log, conf):
    """Query rpkid for this resource handle's received resources.

    The semantics are to clear the entire table and populate with the
    list of certs received.  Other models should not reference the
    table directly with foreign keys."""

    z = Zookeeper(handle=conf.handle)
    pdus = z.call_rpkid(rpki.left_right.list_received_resources_elt.make_pdu(self_handle=conf.handle))

    models.ResourceCert.objects.filter(parent__issuer=conf).delete()

    for pdu in pdus:
        if isinstance(pdu, rpki.left_right.list_received_resources_elt):
            parent = models.Parent.get(issuer=conf, handle=pdu.parent_handle)

            not_before = datetime.strptime(pdu.notBefore, "%Y-%m-%dT%H:%M:%SZ")
            not_after = datetime.strptime(pdu.notAfter, "%Y-%m-%dT%H:%M:%SZ")

            cert = models.ResourceCert.objects.create(parent=parent, not_before=not_before, not_after=not_after)

            for asn in rpki.resource_set.resource_set_as(pdu.asn):
                cert.asn_ranges.add(min=asn.min, max=asn.max)

            for rng in rpki.resource_set.resource_set_ipv4(pdu.ipv4):
                cert.address_ranges.add(min=rng.min, max=rng.max)

            for rng in rpki.resource_set.resource_set_ipv6(pdu.ipv6):
                cert.address_ranges_v6.add(min=rng.min, max=rng.max)
        else:
            print >>log, "error: unexpected pdu from rpkid type=%s" % type(pdu)

def config_from_template(dest, a):
    """
    Create a new rpki.conf file from a generic template.  Go line by
    line through the template and substitute directives from the
    dictionary 'a'.

    """
    with open(dest, 'w') as f:
        for r in open(settings.RPKI_CONF_TEMPLATE):
            words = r.split()
            if words:
                word = words[0].strip()
                if word in a:
                    print >>f, "%s\t\t\t\t= %s\n" % (word, a[word])
                else:
                    print >>f, r,
            else:
                print >>f, r,

def initialize_handle(log, handle, host, owner=None, commit=True):
    """Create a new Conf object for this user."""
    print >>log, "initializing new resource handle %s" % handle

    qs = models.Conf.objects.filter(handle=handle)
    if not qs:
        conf = models.Conf(handle=handle, host=host)
        conf.save()
        if owner:
            conf.owner.add(owner)
    else:
        conf = qs[0]

    # Create the config directory if it doesn't already exist
    top = confpath(conf.handle)
    if not os.path.exists(top):
        os.makedirs(top)

    # Create rpki.conf file if it doesn't exist
#    if not os.path.exists(cfg_file):
#        print >>log, "generating rpki.conf for %s" % conf.handle
#        config_from_template(cfg_file,
#                {
#                    'handle'                 : conf.handle,
#                    'configuration_directory': top,
#                    'run_rpkid'              : 'false',
#                    'run_pubd'               : 'false',
#                    'run_rootd'              : 'false',
#                    'openssl'                : get_system_config().get('openssl')
#                })

    # Load configuration for self
    z = Zookeeper(handle=conf.handle)
    identity_xml = z.initialize()

    if commit:
        m.synchronize([conf.handle])

### CHILD ###

def import_child(log, conf, child_handle, xml_file):
    """Import a child's identity.xml."""
    z = Zookeeper(handle=conf.handle)
    wrapper, handle = z.configure_child(xml_file)
    z.synchronize([conf.handle])

def delete_child(log, conf, child_handle):
    z = Zookeeper(handle=conf.handle)
    z.delete_child(child_handle)
    z.synchronize([conf.handle])

### PARENT ###

def import_parent(log, conf, parent_handle, xml_file):
    z = Zookeeper(handle=conf.handle)
    wrapper, handle = z.configure_parent(xml_file)
    z.synchronize([conf.handle])

def delete_parent(log, conf, parent_handle):
    z = Zookeeper(handle=conf.handle)
    z.delete_parent(parent_handle)
    z.synchronize([conf.handle])

### PUBCLIENT ###

def import_pubclient(log, conf, xml_file):
    z = Zookeeper(handle=conf.handle)
    wrapper, client_handle = z.configure_publication_client(xml_file)
    z.synchronize([conf.handle])

def delete_publication_client(log, conf, client_handle):
    z = Zookeeper(handle=conf.handle)
    z.delete_publication_client(client_handle)
    z.synchronize([conf.handle])

### REPO ###

def import_repository(log, conf, xml_file):
    z = Zookeeper(handle=conf.handle)
    z.configure_repository(xml_file)
    z.synchronize([conf.handle])

def delete_repository(log, conf, repository_handle):
    z = Zookeeper(handle=conf.handle)
    z.delete_publication_client(repository_handle)
    z.synchronize([conf.handle])

def create_child(log, parent_conf, child_handle):
    """
    Implements the child create wizard to create a new locally hosted child

    """
    child_conf, child = initialize_handle(log, handle=child_handle, host=parent_conf, commit=False)

    parent_handle = parent_conf.handle

    parent = get_myrpki(parent_conf)

    child_identity_xml = os.path.join(child.cfg.get("entitydb_dir"), 'identity.xml')
    parent_response_xml = os.path.join(parent.cfg.get("entitydb_dir"), 'children', child_handle + '.xml')
    repo_req_xml = os.path.join(child.cfg.get('entitydb_dir'), 'repositories', parent_handle + '.xml')
    # XXX for now we assume the child is hosted by parent's pubd
    repo_resp_xml = os.path.join(parent.cfg.get('entitydb_dir'), 'pubclients', '%s.%s.xml' % (parent_handle, child_handle))

    parent.do_configure_child(child_identity_xml)

    child.do_configure_parent(parent_response_xml)

    parent.do_configure_publication_client(repo_req_xml)

    child.do_configure_repository(repo_resp_xml)

    # run twice the first time to get bsc cert issued
    sys.stdout = sys.stderr
    configure_daemons(log, child_conf, child)
    configure_daemons(log, child_conf, child)

def destroy_handle(log, handle):
    conf = models.Conf.objects.get(handle=handle)

    z = Zookeeper(handle=conf.host.handle)
    z.delete_child(conf.handle)
    z.delete_self(handle=conf.handle)
    z.delete_publication_client(client_handle=conf.handle)
    z.synchronize([conf.host.handle])

    conf.delete()

def read_child_response(log, conf, child_handle):
    m = get_myrpki(conf)
    bname = child_handle + '.xml'
    return open(os.path.join(m.cfg.get('entitydb_dir'), 'children', bname)).read()

def read_child_repo_response(log, conf, child_handle):
    """
    Return the XML file for the configure_publication_client response to the
    child.

    Note: the current model assumes the publication client is a child of this
    handle.

    """
    m = get_myrpki(conf)
    return open(os.path.join(m.cfg.get('entitydb_dir'), 'pubclients', '%s.%s.xml' % (conf.handle, child_handle))).read()

def update_bpki(log, conf):
    z = Zookeeper(handle=conf.handle)
    z.update_bpki()

# vim:sw=4 ts=8 expandtab
