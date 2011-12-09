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

from __future__ import with_statement

import os, os.path, csv, shutil, stat, sys
from datetime import datetime, timedelta

from django.db.models import F

import rpki, rpki.async, rpki.http, rpki.x509, rpki.left_right, rpki.myrpki
import rpki.publication
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

def build_rpkid_caller(cfg, verbose=False):
    """
    Returns a function suitable for calling rpkid using the
    configuration information specified in the rpki.config.parser
    object.

    """
    bpki_servers_dir = cfg.get("bpki_servers_directory")
    if not bpki_servers_dir.startswith('/'):
        bpki_servers_dir = confpath(cfg.get('handle'), bpki_servers_dir)

    bpki_servers = rpki.myrpki.CA(cfg.filename, bpki_servers_dir)
    rpkid_base = "http://%s:%s/" % (cfg.get("rpkid_server_host"), cfg.get("rpkid_server_port"))

    return rpki.async.sync_wrapper(rpki.http.caller(
        proto       = rpki.left_right,
        client_key  = rpki.x509.RSA(PEM_file = bpki_servers.dir + "/irbe.key"),
        client_cert = rpki.x509.X509(PEM_file = bpki_servers.dir + "/irbe.cer"),
        server_ta   = rpki.x509.X509(PEM_file = bpki_servers.cer),
        server_cert = rpki.x509.X509(PEM_file = bpki_servers.dir + "/rpkid.cer"),
        url         = rpkid_base + "left-right",
        debug       = verbose))

def build_pubd_caller(cfg):
    bpki_servers_dir = cfg.get("bpki_servers_directory")
    if not bpki_servers_dir.startswith('/'):
        bpki_servers_dir = confpath(cfg.get('handle'), bpki_servers_dir)

    bpki_servers = rpki.myrpki.CA(cfg.filename, bpki_servers_dir)
    pubd_base         = "http://%s:%s/" % (cfg.get("pubd_server_host"), cfg.get("pubd_server_port"))

    return rpki.async.sync_wrapper(rpki.http.caller(
        proto       = rpki.publication,
        client_key  = rpki.x509.RSA( PEM_file = bpki_servers.dir + "/irbe.key"),
        client_cert = rpki.x509.X509(PEM_file = bpki_servers.dir + "/irbe.cer"),
        server_ta   = rpki.x509.X509(PEM_file = bpki_servers.cer),
        server_cert = rpki.x509.X509(PEM_file = bpki_servers.dir + "/pubd.cer"),
        url         = pubd_base + "control"))

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

def get_system_config():
    """Returns an rpki.config.parser object for the system rpki.conf."""
    return rpki.config.parser(section='myrpki')

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

    # For hosted handles, get the config for the irdbd/rpkid host, which
    # contains the information needed to talk to the daemons.
    if handle.host:
        cfg = get_system_config()

    irdb = rpki.myrpki.IRDB(cfg)
    irdb.update(handle, roa_requests, children, ghostbusters)
    irdb.close()

    # Contact rpkid to request immediate update.
    call_rpkid = build_rpkid_caller(cfg)
    call_rpkid(rpki.left_right.self_elt.make_pdu(action='set', self_handle=handle.handle, run_now=True))

def list_received_resources(log, conf):
    """Query rpkid for this resource handle's children and received resources."""
    # always use the system rpki.conf for talking to the daemons
    cfg = get_system_config()
    call_rpkid = build_rpkid_caller(cfg)
    pdus = call_rpkid(rpki.left_right.list_received_resources_elt.make_pdu(self_handle=conf.handle),
                      rpki.left_right.child_elt.make_pdu(action="list", self_handle=conf.handle),
                      rpki.left_right.parent_elt.make_pdu(action="list", self_handle=conf.handle))

    for pdu in pdus:
        if isinstance(pdu, rpki.left_right.child_elt):
            # have we seen this child before?
            child_set = conf.children.filter(handle=pdu.child_handle)
            if not child_set:
                # default to 1 year.  no easy way to query irdb for the
                # current value.
                valid_until = datetime.now() + timedelta(days=365)
                child = models.Child(conf=conf, handle=pdu.child_handle,
                                     valid_until=valid_until)
                child.save()

        elif isinstance(pdu, rpki.left_right.parent_elt):
            # have we seen this parent before?
            parent_set = conf.parents.filter(handle=pdu.parent_handle)
            if not parent_set:
                parent = models.Parent(conf=conf, handle=pdu.parent_handle)
                parent.save()

        elif isinstance(pdu, rpki.left_right.list_received_resources_elt):

            # have we seen this parent before?
            parent_set = conf.parents.filter(handle=pdu.parent_handle)
            if not parent_set:
                parent = models.Parent(conf=conf, handle=pdu.parent_handle)
                parent.save()
            else:
                parent = parent_set[0]

            not_before = datetime.strptime(pdu.notBefore, "%Y-%m-%dT%H:%M:%SZ")
            not_after = datetime.strptime(pdu.notAfter, "%Y-%m-%dT%H:%M:%SZ")

            #print >>log, 'uri: %s, not before: %s, not after: %s' % (pdu.uri, not_before, not_after)

            # have we seen this resource cert before?
            cert_set = parent.resources.filter(uri=pdu.uri)
            if cert_set.count() == 0:
                cert = models.ResourceCert(uri=pdu.uri, parent=parent,
                        not_before=not_before, not_after=not_after)
            else:
                cert = cert_set[0]
                # update timestamps since it could have been modified
                cert.not_before = not_before
                cert.not_after = not_after
            cert.save()

            for asn in rpki.resource_set.resource_set_as(pdu.asn):
                # see if this resource is already part of the cert
                if cert.asn.filter(lo=asn.min, hi=asn.max).count() == 0:
                    # ensure this range wasn't seen from another of our parents
                    for v in models.Asn.objects.filter(lo=asn.min, hi=asn.max):
                        # determine if resource is delegated from another parent
                        if v.from_cert.filter(parent__in=conf.parents.all()).count():
                            cert.asn.add(v)
                            break
                    else:
                        cert.asn.create(lo=asn.min, hi=asn.max)
                    cert.save()

            # IPv4/6 - not separated in the django db
            def add_missing_address(addr_set):
               for ip in addr_set:
                   lo=str(ip.min)
                   hi=str(ip.max)
                   if cert.address_range.filter(lo=lo, hi=hi).count() == 0:
                       # ensure that this range wasn't previously seen from another of our parents
                       for v in models.AddressRange.objects.filter(lo=lo, hi=hi):
                           # determine if this resource is delegated from another parent as well
                           if v.from_cert.filter(parent__in=conf.parents.all()).count():
                               cert.address_range.add(v)
                               break
                       else:
                           cert.address_range.create(lo=lo, hi=hi)
                       cert.save()

            add_missing_address(rpki.resource_set.resource_set_ipv4(pdu.ipv4))
            add_missing_address(rpki.resource_set.resource_set_ipv6(pdu.ipv6))

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

class Myrpki(rpki.myrpki.main):
    """
    Wrapper around rpki.myrpki.main to force the config file to what I want,
    and avoid cli arg parsing.

    """
    def __init__(self, handle):
        self.cfg_file = confpath(handle, 'rpki.conf')
        self.read_config()

def get_myrpki(conf):
    """
    Return a rpki.myrpki.main() or subclass thereof depending on
    whether the 'conf' argument refers to the rpki host, or to a
    hosted conf.  When refering to a hosted conf, we use the wrapper
    subclass to force use of the stub rpki.conf located in the conf
    directory.  For the rpkid host, we use the system rpki.conf.

    """
    return Myrpki(conf.handle) if conf.host else rpki.myrpki.main()

def configure_daemons(log, conf, m):
    if conf.host:
        m.configure_resources_main()

        host = get_myrpki(conf.host)
        host.do_configure_daemons(m.cfg.get('xml_filename'))
    else:
        m.do_configure_daemons('')

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

    cfg_file = confpath(conf.handle, 'rpki.conf')

    # Create rpki.conf file if it doesn't exist
    if not os.path.exists(cfg_file):
        print >>log, "generating rpki.conf for %s" % conf.handle
        config_from_template(cfg_file,
                {
                    'handle'                 : conf.handle,
                    'configuration_directory': top,
                    'run_rpkid'              : 'false',
                    'run_pubd'               : 'false',
                    'run_rootd'              : 'false'
                    'openssl'                : get_system_config().get('openssl')
                })

    # Create stub csv files
    for f in ('asns', 'prefixes', 'roas'):
        p = confpath(conf.handle, f + '.csv')
        if not os.path.exists(p):
            f = open(p, 'w')
            f.close()

    # Load configuration for self
    m = get_myrpki(conf)
    m.do_initialize('')

    if commit:
        # run twice the first time to get bsc cert issued
        configure_daemons(log, conf, m)
        configure_daemons(log, conf, m)

    return conf, m

def import_child(log, conf, child_handle, xml_file):
    """Import a child's identity.xml."""
    m = get_myrpki(conf)
    m.do_configure_child(xml_file)
    configure_daemons(log, conf, m)

def import_parent(log, conf, parent_handle, xml_file):
    m = get_myrpki(conf)
    m.do_configure_parent(xml_file)
    configure_daemons(log, conf, m)

def import_pubclient(log, conf, xml_file):
    m = get_myrpki(conf)
    m.do_configure_publication_client(xml_file)
    configure_daemons(log, conf, m)

def import_repository(log, conf, xml_file):
    m = get_myrpki(conf)
    m.do_configure_repository(xml_file)
    configure_daemons(log, conf, m)

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

    cfg = rpki.config.parser(confpath(conf.host.handle, 'rpki.conf'), 'myrpki')
    call_rpkid = build_rpkid_caller(cfg)
    call_pubd = build_pubd_caller(cfg)

    # destroy the <self/> object and the <child/> object from the host/parent.
    rpkid_reply = call_rpkid(
            rpki.left_right.self_elt.make_pdu(action="destroy", self_handle=handle),
            rpki.left_right.child_elt.make_pdu(action="destroy", self_handle=conf.host.handle, child_handle=handle))
    if isinstance(rpkid_reply[0], rpki.left_right.report_error_elt):
        print >>log, "Error while calling pubd to delete client %s:" % handle
        print >>log, rpkid_reply[0]

    pubd_reply = call_pubd(rpki.publication.client_elt.make_pdu(action="destroy", client_handle=handle))
    if isinstance(pubd_reply[0], rpki.publication.report_error_elt):
        print >>log, "Error while calling pubd to delete client %s:" % handle
        print >>log, pubd_reply[0]

    conf.delete()

    shutil.remove(confpath(handle))

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
    m = get_myrpki(conf)

    # Automatically runs configure_daemons when self-hosted otherwise runs
    # configure_resources.
    m.do_update_bpki('')

    # when hosted, ship off to rpkid host
    if conf.host:
        configure_daemons(log, conf, m)

def delete_child(log, conf, child_handle):
    m = get_myrpki(conf)
    m.do_delete_child(child_handle)
    configure_daemons(log, conf, m)

def delete_parent(log, conf, parent_handle):
    m = get_myrpki(conf)
    m.do_delete_parent(parent_handle)
    configure_daemons(log, conf, m)

# vim:sw=4 ts=8 expandtab tw=79
