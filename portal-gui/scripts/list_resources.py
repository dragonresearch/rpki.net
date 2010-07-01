#!/usr/bin/env python

import os
from rpki.myrpki import EntityDB, CA
import rpki.config
import rpki.x509
import rpki.https
import rpki.async
import rpki.left_right
import rpki.resource_set
import rpki.ipaddrs

from rpkigui.myrpki import models

class ReceivedResources(object):
    def __init__(self, self_handle, parent_handle, asn, ipv4, ipv6, uri, not_before, not_after):
        self.self_handle = self_handle
        self.parent_handle = parent_handle
        self.asn = asn
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.uri = uri
        self.not_before = not_before
        self.not_after = not_after

    def __str__(self):
        return "%s's received resources from parent %s" % (self.self_handle, self.parent_handle, )

def query_rpkid(handle=None):
    """Fetch our received resources from the local rpkid using the myrpki.conf in the current directory."""
    cfg_file = os.getenv("MYRPKI_CONF", "myrpki.conf")
    cfg = rpki.config.parser(cfg_file, "myrpki")
    if handle is None:
        handle = cfg.get('handle')
    entitydb = EntityDB(cfg)
    bpki_resources = CA(cfg_file, cfg.get("bpki_resources_directory"))
    bpki_servers = CA(cfg_file, cfg.get("bpki_servers_directory"))
    rpkid_base = "https://%s:%s/" % (cfg.get("rpkid_server_host"), cfg.get("rpkid_server_port"))

    call_rpkid = rpki.async.sync_wrapper(rpki.https.caller(
        proto       = rpki.left_right,
        client_key  = rpki.x509.RSA( PEM_file = bpki_servers.dir + "/irbe.key"),
        client_cert = rpki.x509.X509(PEM_file = bpki_servers.dir + "/irbe.cer"),
        server_ta   = rpki.x509.X509(PEM_file = bpki_servers.cer),
        server_cert = rpki.x509.X509(PEM_file = bpki_servers.dir + "/rpkid.cer"),
        url         = rpkid_base + "left-right",
        debug = True))

    print 'calling rpkid...'
    rpkid_reply = call_rpkid(
        #rpki.left_right.parent_elt.make_pdu(action="list", tag="parents", self_handle=handle),
        #rpki.left_right.list_roa_requests_elt.make_pdu(tag='roas', self_handle=handle),
        rpki.left_right.list_received_resources_elt.make_pdu(tag = "resources",
            self_handle = handle))
    print 'done'

    resources = []
    for x in rpkid_reply:
        if isinstance(x, rpki.left_right.parent_elt):
           print x.parent_handle, x.sia_base, x.sender_name, x.recipient_name, \
               x.peer_contact_uri
        #elif isinstance(x, rpki.left_right.list_roa_requests_elt):
        #    print x.asn, x.ipv4, x.ipv6
        if isinstance(x, rpki.left_right.list_received_resources_elt):
            resources.append(ReceivedResources(self_handle=handle,
                parent_handle=x.parent_handle,
                asn=rpki.resource_set.resource_set_as(x.asn),
                ipv4=rpki.resource_set.resource_set_ipv4(x.ipv4),
                ipv6=rpki.resource_set.resource_set_ipv6(x.ipv6),
                uri=x.uri,
                not_after=x.notAfter,
                not_before=x.notBefore))
    return resources

x = query_rpkid()
for y in x:
    conf = models.Conf.objects.filter(handle=y.self_handle)[0]

    parent_set = conf.parents.filter(handle=y.parent_handle)
    if not parent_set:
        print 'have not yet seen parent %s, creating...' % (y.parent_handle, )
        # have not seen this parent before
        parent = models.Parent(conf=conf, handle=y.parent_handle)
        parent.save()
    else:
        parent = parent_set[0]

    # have we seen this resource cert before?
    cert_set = conf.resources.filter(uri=y.uri)
    if cert_set.count() == 0:
        # no
        cert = models.ResourceCert(uri=uri, parent=parent, not_before=x.not_before,
                not_after=x.not_after)
    else:
        # yes
        cert = cert_set[0]

    for asn in y.asn:
        # see if this resource is already part of the cert
        if cert.asn.get(lo=asn.min, hi=asn.max) is None:
            # ensure that this range wasn't previously seen from another of our parents
            for v in models.Asn.objects.filter(lo=asn.min, hi=asn.max):
                # determine if this resource is delegated from another parent as well
                if v.from_cert.filter(parent__in=conf.parents.all()).count():
                    cert.asn.add(v)
                    break
            else:
                print 'could not find ASN %s in known set' % ( asn, )
                cert.asn.create(lo=asn.min, hi=asn.max)
            cert.save()

    # IPv4/6 - not separated in the django db
    def add_missing_address(addr_set):
       for ip in addr_set:
           lo=str(ip.min)
           hi=str(ip.max)
           if cert.address_range.get(lo=lo, hi=hi) is None:
               # ensure that this range wasn't previously seen from another of our parents
               for v in models.AddressRange.objects.filter(lo=lo, hi=hi):
                   # determine if this resource is delegated from another parent as well
                   if v.from_cert.filter(parent__in=conf.parents.all()).count():
                       cert.address_range.add(v)
                       break
               else:
                   print 'could not find address range %s in known set' % ( ip, )
                   cert.address_range.create(lo=lo, hi=hi)
               cert.save()

    add_missing_address(y.ipv4)
    add_missing_address(y.ipv6)

# vim:sw=4 expandtab ts=4
