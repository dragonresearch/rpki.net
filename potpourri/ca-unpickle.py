#!/usr/bin/env python

# $Id$

"""
Unpickle trunk/ CA state packaged by ca-pickle and attempt to whack a
tk705/ rpki-ca instance into an equivalent state.
"""

# We need to fork separate processes to handle different databases
# (well, OK, there are other ways we could to this, but forks are
# by far the simplest).  So we organize the database-specific bits
# as separate functions, one per database to be whacked, and handle
# the fork management in a common loop.

import os
import sys
import time
import cPickle
import datetime
import argparse
import subprocess

import rpki.config
import rpki.x509
import rpki.POW

from base64 import urlsafe_b64encode


class LazyDict(object):
    """
    Convenience wrapper to allow attribute notation for brevity
    when diving into deeply nested mappings created by ca-pickle.
    """

    def __init__(self, *args, **kwargs):
        self._d = dict(*args, **kwargs)

    def __getattr__(self, name):
        if name in self._d:
            return self._d[name]
        name = name.replace("_", "-")
        if name in self._d:
            return self._d[name]
        raise AttributeError

    def __getitem__(self, name):
        return self._d[name]

    def __iter__(self):
        return self._d.iterkeys()

    def __len__(self):
        return len(self._d)

    @classmethod
    def insinuate(cls, thing):
        if isinstance(thing, dict):
            return cls((k, cls.insinuate(v)) for k, v in thing.iteritems())
        if isinstance(thing, list):
            return list(cls.insinuate(v) for v in thing)
        if isinstance(thing, tuple):
            return tuple(cls.insinuate(v) for v in thing)
        return thing


# None-safe wrappers for DER constructors.
def X509(obj):   return None if obj is None else rpki.x509.X509(          DER = obj)
def CRL(obj):    return None if obj is None else rpki.x509.CRL(           DER = obj)
def RSA(obj):    return None if obj is None else rpki.x509.RSA(           DER = obj)
def PKCS10(obj): return None if obj is None else rpki.x509.PKCS10(        DER = obj)
def MFT(obj):    return None if obj is None else rpki.x509.SignedManifest(DER = obj)
def ROA(obj):    return None if obj is None else rpki.x509.ROA(           DER = obj)
def GBR(obj):    return None if obj is None else rpki.x509.Ghostbuster(   DER = obj)
def REF(obj):    return None if obj is None else rpki.x509.SignedReferral(DER = obj)


# Other conversions

def ski_to_gski(ski):
    return None if ski is None else urlsafe_b64encode(ski).rstrip("=")

def cfg_to_bool(v):
    from ConfigParser import RawConfigParser
    states = RawConfigParser._boolean_states
    return states[v.lower()]


def main():

    os.environ.update(TZ = "UTC")
    time.tzset()

    global cfg
    cfg = rpki.config.argparser(doc = __doc__)
    cfg.argparser.add_argument("input_file", help = "input file")
    cfg.add_logging_arguments()
    args = cfg.argparser.parse_args()
    cfg.configure_logging(args = args)

    global world
    xzcat = subprocess.Popen(("xzcat", args.input_file), stdout = subprocess.PIPE)
    world = LazyDict.insinuate(cPickle.load(xzcat.stdout))
    if xzcat.wait() != 0:
        sys.exit("XZ unpickling failed with code {}".format(xzcat.returncode))

    for enabled, handler in ((world.cfg.myrpki.run_rpkid, rpkid_handler),
                             (world.cfg.myrpki.run_rpkid, irdb_handler),
                             (world.cfg.myrpki.run_pubd,  pubd_handler)):
        if not cfg_to_bool(enabled):
            continue
        if os.fork() == 0:
            handler()
            sys.exit()
        else:
            pid, status = os.wait()
            if status and os.WIFEXITED(status):
                sys.exit("Internal process exited with status {}".format(os.WEXITSTATUS(status)))
            if status and os.WIFSIGNALED(status):
                sys.exit("Internal process exited on signal {}".format(os.WTERMSIG(status)))


def rpkid_handler():
    os.environ.update(DJANGO_SETTINGS_MODULE = "rpki.django_settings.rpkid")
    import django
    django.setup()
    import rpki.rpkidb

    print "rpkid self"
    for row in world.db.rpkid.self:
        print " ", row.self_handle
        rpki.rpkidb.models.Tenant.objects.create(
            pk                      = row.self_id,
            tenant_handle           = row.self_handle,
            use_hsm                 = row.use_hsm,
            crl_interval            = row.crl_interval,
            regen_margin            = row.regen_margin,
            bpki_cert               = X509(row.bpki_cert),
            bpki_glue               = X509(row.bpki_glue))

    print "rpkid bsc"
    for row in world.db.rpkid.bsc:
        print " ", row.bsc_handle
        tenant = rpki.rpkidb.models.Tenant.objects.get(pk = row.self_id )
        rpki.rpkidb.models.BSC.objects.create(
            pk                      = row.bsc_id,
            bsc_handle              = row.bsc_handle,
            private_key_id          = RSA(row.private_key_id),
            pkcs10_request          = PKCS10(row.pkcs10_request),
            hash_alg                = row.hash_alg or "sha256",
            signing_cert            = X509(row.signing_cert),
            signing_cert_crl        = CRL(row.signing_cert_crl),
            tenant                  = tenant)

    print "rpkid repository"
    for row in world.db.rpkid.repository:
        print " ", row.repository_handle
        tenant = rpki.rpkidb.models.Tenant.objects.get(pk = row.self_id )
        bsc    = rpki.rpkidb.models.BSC.objects.get(   pk = row.bsc_id, tenant = tenant )
        rpki.rpkidb.models.Repository.objects.create(
            pk                      = row.repository_id,
            repository_handle       = row.repository_handle,
            peer_contact_uri        = row.peer_contact_uri,
            bpki_cert               = X509(row.bpki_cert),
            bpki_glue               = X509(row.bpki_glue),
            last_cms_timestamp      = row.last_cms_timestamp,
            bsc                     = bsc,
            tenant                  = tenant)

    print "rpkid parent"
    for row in world.db.rpkid.parent:
        print " ", row.parent_handle
        tenant     = rpki.rpkidb.models.Tenant.objects.get(    pk = row.self_id )
        bsc        = rpki.rpkidb.models.BSC.objects.get(       pk = row.bsc_id,        tenant = tenant )
        repository = rpki.rpkidb.models.Repository.objects.get(pk = row.repository_id, tenant = tenant )
        rpki.rpkidb.models.Parent.objects.create(
            pk                      = row.parent_id,
            parent_handle           = row.parent_handle,
            bpki_cert               = X509(row.bpki_cms_cert),
            bpki_glue               = X509(row.bpki_cms_glue),
            peer_contact_uri        = row.peer_contact_uri,
            sia_base                = row.sia_base,
            sender_name             = row.sender_name,
            recipient_name          = row.recipient_name,
            last_cms_timestamp      = row.last_cms_timestamp,
            bsc                     = bsc,
            repository              = repository,
            tenant                  = tenant)

    print "rpkid ca"
    for row in world.db.rpkid.ca:
        parent = rpki.rpkidb.models.Parent.objects.get(pk = row.parent_id)
        rpki.rpkidb.models.CA.objects.create(
            pk                      = row.ca_id,
            last_crl_manifest_number= max(row.last_crl_sn, row.last_manifest_sn),
            last_issued_sn          = row.last_issued_sn,
            sia_uri                 = row.sia_uri,
            parent_resource_class   = row.parent_resource_class,
            parent                  = parent)

    print "rpkid ca_detail"
    for row in world.db.rpkid.ca_detail:
        ca = rpki.rpkidb.models.CA.objects.get(pk = row.ca_id)
        rpki.rpkidb.models.CADetail.objects.create(
            pk                      = row.ca_detail_id,
            public_key              = RSA(row.public_key),
            private_key_id          = RSA(row.private_key_id),
            latest_crl              = CRL(row.latest_crl),
            crl_published           = row.crl_published,
            latest_ca_cert          = X509(row.latest_ca_cert),
            manifest_private_key_id = RSA(row.manifest_private_key_id),
            manifest_public_key     = RSA(row.manifest_public_key),
            latest_manifest         = MFT(row.latest_manifest),
            manifest_published      = row.manifest_published,
            state                   = row.state,
            ca_cert_uri             = row.ca_cert_uri,
            ca                      = ca)

    print "rpkid child"
    for row in world.db.rpkid.child:
        print " ", row.child_handle
        tenant     = rpki.rpkidb.models.Tenant.objects.get(pk = row.self_id)
        bsc        = rpki.rpkidb.models.BSC.objects.get(   pk = row.bsc_id, tenant = tenant)
        rpki.rpkidb.models.Child.objects.create(
            pk                      = row.child_id,
            child_handle            = row.child_handle,
            bpki_cert               = X509(row.bpki_cert),
            bpki_glue               = X509(row.bpki_glue),
            last_cms_timestamp      = row.last_cms_timestamp,
            tenant                  = tenant,
            bsc                     = bsc)

    print "rpkid child_cert"
    for row in world.db.rpkid.child_cert:
        child     = rpki.rpkidb.models.Child.objects.get(   pk = row.child_id)
        ca_detail = rpki.rpkidb.models.CADetail.objects.get(pk = row.ca_detail_id)
        rpki.rpkidb.models.ChildCert.objects.create(
            pk                      = row.child_cert_id,
            cert                    = X509(row.cert),
            published               = row.published,
            gski                    = ski_to_gski(row.ski),
            child                   = child,
            ca_detail               = ca_detail)

    print "rpkid revoked_cert"
    for row in world.db.rpkid.revoked_cert:
        ca_detail = rpki.rpkidb.models.CADetail.objects.get(pk = row.ca_detail_id)
        rpki.rpkidb.models.RevokedCert.objects.create(
            pk                      = row.revoked_cert_id,
            serial                  = row.serial,
            revoked                 = row.revoked,
            expires                 = row.expires,
            ca_detail               = ca_detail)

    print "rpkid roa"
    for row in world.db.rpkid.roa:
        tenant    = rpki.rpkidb.models.Tenant.objects.get(  pk = row.self_id)
        ca_detail = rpki.rpkidb.models.CADetail.objects.get(pk = row.ca_detail_id)
        prefixes = tuple((p.version, "%s/%s-%s".format(p.prefix, p.prefixlen, p.max_prefixlen))
                         for p in world.db.rpkid.roa_prefix
                         if p.roa_id == row.roa_id)
        ipv4 = ",".join(p for v, p in prefixes if v == 4) or None
        ipv6 = ",".join(p for v, p in prefixes if v == 6) or None
        rpki.rpkidb.models.ROA.objects.create(
            pk                      = row.roa_id,
            asn                     = row.asn,
            ipv4                    = ipv4,
            ipv6                    = ipv6,
            cert                    = X509(row.cert),
            roa                     = ROA(row.roa),
            published               = row.published,
            tenant                  = tenant,
            ca_detail               = ca_detail)

    print "rpkid ghostbuster"
    for row in world.db.rpkid.ghostbuster:
        tenant    = rpki.rpkidb.models.Tenant.objects.get(  pk = row.self_id)
        ca_detail = rpki.rpkidb.models.CADetail.objects.get(pk = row.ca_detail_id)
        rpki.rpkidb.models.Ghostbuster.objects.create(
            pk                      = row.ghostbuster_id,
            vcard                   = row.vcard,
            cert                    = X509(row.cert),
            ghostbuster             = GBR(row.ghostbuster),
            published               = row.published,
            tenant                  = tenant,
            ca_detail               = ca_detail)

    print "rpkid ee_cert"
    for row in world.db.rpkid.ee_cert:
        tenant    = rpki.rpkidb.models.Tenant.objects.get(  pk = row.self_id)
        ca_detail = rpki.rpkidb.models.CADetail.objects.get(pk = row.ca_detail_id)
        rpki.rpkidb.models.EECertificate.objects.create(
            pk                      = row.ee_cert_id,
            gski                    = ski_to_gski(row.ski),
            cert                    = X509(row.cert),
            published               = row.published,
            tenant                  = tenant,
            ca_detail               = ca_detail)

    if cfg_to_bool(world.cfg.myrpki.run_rootd):
        print "rootd enabled"
        root_dir = world.cfg.rootd["rpki-root-dir"]
        root_cer = X509(world.file[                       world.cfg.rootd["rpki-root-cert"    ] ])
        root_key = RSA( world.file[                       world.cfg.rootd["rpki-root-key"     ] ])
        root_crl = CRL( world.file[os.path.join(root_dir, world.cfg.rootd["rpki-root-crl"     ])])
        root_mft = MFT( world.file[os.path.join(root_dir, world.cfg.rootd["rpki-root-manifest"])])
        work_cer = X509(world.file[os.path.join(root_dir, world.cfg.rootd["rpki-subject-cert" ])])
        print "root cer: {!r}".format(root_cer)
        print "root key: {!r}".format(root_key)
        print "root crl: {!r}".format(root_crl)
        print "root.mft: {!r}".format(root_mft)
        print "work.cer: {!r}".format(work_cer)

        root_serial = root_cer.getSerial()
        work_serial = work_cer.getSerial()
        mft_serial  = root_mft.get_POW().certs()[0].getSerial()
        print "Serials: root {} worker {} manifest {} next {}".format(
            root_serial, work_serial, mft_serial,
            max(root_serial, work_serial, mft_serial) + 1)

        root_mft.extract()
        mft_number = root_mft.get_POW().getManifestNumber()
        crl_number = root_crl.getCRLNumber()
        print "Numbers: CRL {} manifest {} next {}".format(
            crl_number, mft_number, max(crl_number, mft_number) + 1)


def pubd_handler():
    os.environ.update(DJANGO_SETTINGS_MODULE = "rpki.django_settings.pubd")
    import django
    django.setup()
    import rpki.pubdb

    print "pubd client"
    for row in world.db.pubd.client:
        print " ", row.client_handle
        rpki.pubdb.models.Client.objects.create(
            pk                  = row.client_id,
            client_handle       = row.client_handle,
            base_uri            = row.base_uri,
            bpki_cert           = X509(row.bpki_cert),
            bpki_glue           = X509(row.bpki_glue),
            last_cms_timestamp  = row.last_cms_timestamp)


def irdb_handler():
    os.environ.update(DJANGO_SETTINGS_MODULE = "rpki.django_settings.irdb")
    import django
    django.setup()
    import rpki.irdb

    # Changes from  old to new rpki.irdb.models:
    #
    # * rpki.irdb.models.Rootd went away.
    #
    # * rpki.irdb.models.Repository acquired rrdp_notification_uri;
    #   initialize from current (not pickled) rpki.conf?
    #
    # * rpki.irdb.models.Client dropped parent_handle.
    #
    # Most pk fields are just id.  The one exception is Parent, whose pk
    # is turtle_ptr_id because it's also a foreign key pointing at Turtle.

    print "irdb ServerCA"
    for row in world.db.irdbd.irdb_serverca:
        rpki.irdb.models.ServerCA.objects.create(
            pk                  = row.id,
            certificate         = X509(row.certificate),
            private_key         = RSA(row.private_key),
            latest_crl          = CRL(row.latest_crl),
            next_serial         = row.next_serial,
            next_crl_number     = row.next_crl_number,
            last_crl_update     = row.last_crl_update,
            next_crl_update     = row.next_crl_update)

    print "irdb ResourceHolderCA"
    for row in world.db.irdbd.irdb_resourceholderca:
        print " ", row.handle
        rpki.irdb.models.ResourceHolderCA.objects.create(
            pk                  = row.id,
            certificate         = X509(row.certificate),
            private_key         = RSA(row.private_key),
            latest_crl          = CRL(row.latest_crl),
            next_serial         = row.next_serial,
            next_crl_number     = row.next_crl_number,
            last_crl_update     = row.last_crl_update,
            next_crl_update     = row.next_crl_update,
            handle              = row.handle)

    print "irdb HostedCA"
    for row in world.db.irdbd.irdb_hostedca:
        issuer = rpki.irdb.models.ServerCA.objects.get(        pk = row.issuer_id)
        hosted = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.hosted_id)
        rpki.irdb.models.HostedCA.objects.create(
            pk                  = row.id,
            certificate         = X509(row.certificate),
            issuer              = issuer,
            hosted              = hosted)

    print "irdb ServerRevocation"
    for row in world.db.irdbd.irdb_serverrevocation:
        issuer = rpki.irdb.models.ServerCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.ServerRevocation.objects.create(
            pk                  = row.id,
            serial              = row.serial,
            revoked             = row.revoked,
            expires             = row.expires,
            issuer              = issuer)

    print "irdb ResourceHolderRevocation"
    for row in world.db.irdbd.irdb_resourceholderrevocation:
        issuer = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.ResourceHolderRevocation.objects.create(
            pk                  = row.id,
            serial              = row.serial,
            revoked             = row.revoked,
            expires             = row.expires,
            issuer              = issuer)

    print "irdb ServerEE"
    for row in world.db.irdbd.irdb_serveree:
        issuer = rpki.irdb.models.ServerCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.ServerEE.objects.create(
            pk                  = row.id,
            certificate         = X509(row.certificate),
            private_key         = RSA(row.private_key),
            purpose             = row.purpose,
            issuer              = issuer)

    print "irdb Referral"
    for row in world.db.irdbd.irdb_referral:
        issuer = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.Referral.objects.create(
            pk                  = row.id,
            certificate         = X509(row.certificate),
            private_key         = RSA(row.private_key),
            issuer              = issuer)

    print "irdb BSC"
    for row in world.db.irdbd.irdb_bsc:
        issuer = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.BSC.objects.create(
            pk                  = row.id,
            certificate         = X509(row.certificate),
            handle              = row.handle,
            pkcs10              = PKCS10(row.pkcs10),
            issuer              = issuer)

    print "irdb Child"
    for row in world.db.irdbd.irdb_child:
        issuer = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.Child.objects.create(
            pk                  = row.id,
            certificate         = X509(row.certificate),
            handle              = row.handle,
            ta                  = X509(row.ta),
            valid_until         = row.valid_until,
            name                = row.name,
            issuer              = issuer)

    print "irdb ChildASN"
    for row in world.db.irdbd.irdb_childasn:
        child = rpki.irdb.models.Child.objects.get(pk = row.child_id)
        rpki.irdb.models.ChildASN.objects.create(
            pk                  = row.id,
            start_as            = row.start_as,
            end_as              = row.end_as,
            child               = child)

    print "irdb ChildNet"
    for row in world.db.irdbd.irdb_childnet:
        child = rpki.irdb.models.Child.objects.get(pk = row.child_id)
        rpki.irdb.models.ChildNet.objects.create(
            pk                  = row.id,
            start_ip            = row.start_ip,
            end_ip              = row.end_ip,
            version             = row.version,
            child               = child)

    # We'd like to consolidate Turtle into Parent now that Rootd is
    # gone.  Well, guess what, we can write this as if it already had
    # been and it should work either way.
    #
    # "Django is amazing when it's not terrifying."

    turtle_map = dict((row.id, row) for row in world.db.irdbd.irdb_turtle)

    print "irdb Parent"
    for row in world.db.irdbd.irdb_parent:
        issuer = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.Parent.objects.create(
            pk                  = row.turtle_ptr_id,
            service_uri         = turtle_map[row.turtle_ptr_id].service_uri,
            certificate         = X509(row.certificate),
            handle              = row.handle,
            ta                  = X509(row.ta),
            parent_handle       = row.parent_handle,
            child_handle        = row.child_handle,
            repository_type     = row.repository_type,
            referrer            = row.referrer,
            referral_authorization = REF(row.referral_authorization),
            issuer              = issuer)

    print "irdb ROARequest"
    for row in world.db.irdbd.irdb_roarequest:
        issuer = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.ROARequest.objects.create(
            pk                  = row.id,
            asn                 = row.asn,
            issuer              = issuer)

    print "irdb ROARequestPrefix"
    for row in world.db.irdbd.irdb_roarequestprefix:
        roa_request = rpki.irdb.models.ROARequest.objects.get(pk = row.roa_request_id)
        rpki.irdb.models.ROARequestPrefix.objects.create(
            pk                  = row.id,
            version             = row.version,
            prefix              = row.prefix,
            prefixlen           = row.prefixlen,
            max_prefixlen       = row.max_prefixlen,
            roa_request         = roa_request)

    print "irdb Ghostbuster"
    for row in world.db.irdbd.irdb_ghostbusterrequest:
        issuer = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.issuer_id)
        try:
            parent = rpki.irdb.models.Parent.objects.get(pk = row.parent_id)
        except rpki.irdb.models.Parent.DoesNotExist:
            parent = None
        rpki.irdb.models.GhostbusterRequest.objects.create(
            pk                  = row.id,
            vcard               = row.vcard,
            parent              = parent,
            issuer              = issuer)

    print "irdb EECertificateRequest"
    for row in world.db.irdbd.irdb_eecertificaterequest:
        issuer = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.EECertificateRequest.objects.create(
            pk                  = row.id,
            valid_until         = row.valid_until,
            pkcs10              = PKCS10(row.pkcs10),
            gski                = row.gski,
            cn                  = row.cn,
            sn                  = row.sn,
            eku                 = row.eku,
            issuer              = issuer)

    print "irdb EECertificateRequestASN"
    for row in world.db.irdbd.irdb_eecertificaterequestasn:
        ee_certificate_request = rpki.irdb.models.EECertificateRequest.objects.get(
            pk = row.ee_certificate_request_id)
        rpki.irdb.models.EECertificateRequestASN.objects.create(
            pk                  = row.id,
            start_as            = row.start_as,
            end_as              = row.end_as,
            ee_certificate_request = ee_certificate_request)

    print "irdb EECertificateRequestNet"
    for row in world.db.irdbd.irdb_eecertificaterequestnet:
        ee_certificate_request = rpki.irdb.models.EECertificateRequest.objects.get(
            pk = row.ee_certificate_request_id)
        rpki.irdb.models.EECertificateRequestNet.objects.create(
            pk                  = row.id,
            start_ip            = row.start_ip,
            end_ip              = row.end_ip,
            version             = row.version,
            ee_certificate_request = ee_certificate_request)

    # Turtle without a Parent can happen where the old database had a Rootd.
    # We probably need to do something that coordinates with whatever we do
    # about rootd in rpkid_handler(), but we haven't written that yet.

    print "irdb Repository"
    for row in world.db.irdbd.irdb_repository:
        issuer = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.issuer_id)
        try:
            turtle = rpki.irdb.models.Turtle.objects.get(pk = row.turtle_id)
        except rpki.irdb.models.Turtle.DoesNotExist:
            if not cfg_to_bool(world.cfg.myrpki.run_rootd):
                raise
            turtle = rpki.irdb.models.Turtle.objects.create(
                pk              = row.turtle_id,
                service_uri     =  "http://{rootd_host}:{rootd_port}/".format(
                    rootd_host = world.cfg.rootd.server_host,
                    rootd_port = world.cfg.rootd.server_port))
        rpki.irdb.models.Repository.objects.create(
            pk                  = row.id,
            certificate         = X509(row.certificate),
            handle              = row.handle,
            ta                  = X509(row.ta),
            client_handle       = row.client_handle,
            service_uri         = row.service_uri,
            sia_base            = row.sia_base,
            rrdp_notification_uri = cfg.get(section = "myrpki",
                                            option = "publication_rrdp_notification_uri"),
            turtle              = turtle,
            issuer              = issuer)

    print "irdb Client"
    for row in world.db.irdbd.irdb_client:
        issuer = rpki.irdb.models.ServerCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.Client.objects.create(
            pk                  = row.id,
            certificate         = X509(row.certificate),
            handle              = row.handle,
            ta                  = X509(row.ta),
            sia_base            = row.sia_base,
            issuer              = issuer)


if __name__ == "__main__":
    main()
