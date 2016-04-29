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
        for k, v in self._d.iteritems():
            self._d[k] = self._insinuate(v)

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

    def __repr__(self):
        return repr(self._d)

    @classmethod
    def _insinuate(cls, thing):
        if isinstance(thing, dict):
            return cls(thing)
        if isinstance(thing, list):
            return list(cls._insinuate(v) for v in thing)
        if isinstance(thing, tuple):
            return tuple(cls._insinuate(v) for v in thing)
        return thing


# None-safe wrappers for DER constructors.
def NoneSafe(obj, cls):
    return None if obj is None else cls(DER = obj)

def X509(obj):   return NoneSafe(obj, rpki.x509.X509)
def CRL(obj):    return NoneSafe(obj, rpki.x509.CRL)
def RSA(obj):    return NoneSafe(obj, rpki.x509.RSA)
def PKCS10(obj): return NoneSafe(obj, rpki.x509.PKCS10)
def MFT(obj):    return NoneSafe(obj, rpki.x509.SignedManifest)
def ROA(obj):    return NoneSafe(obj, rpki.x509.ROA)
def GBR(obj):    return NoneSafe(obj, rpki.x509.Ghostbuster)
def REF(obj):    return NoneSafe(obj, rpki.x509.SignedReferral)

# Other conversions

def SKI_to_gSKI(ski):
    return None if ski is None else urlsafe_b64encode(ski).rstrip("=")

def cfg_to_Bool(v):
    from ConfigParser import RawConfigParser
    states = RawConfigParser._boolean_states
    return states[v.lower()]

# Silly formatting

def show_model(db, model):
    print db, model

def show_handle(handle):
    print " ", handle

# Smoke 'em if you got 'em

def main():

    os.environ.update(TZ = "UTC")
    time.tzset()

    cfg = rpki.config.argparser(doc = __doc__)
    cfg.argparser.add_argument("input_file", help = "input file")
    cfg.add_logging_arguments()
    args = cfg.argparser.parse_args()
    cfg.configure_logging(args = args)

    xzcat = subprocess.Popen(("xzcat", args.input_file), stdout = subprocess.PIPE)
    world = LazyDict(cPickle.load(xzcat.stdout))
    if xzcat.wait() != 0:
        sys.exit("XZ unpickling failed with code {}".format(xzcat.returncode))

    root = Root(cfg, world)

    if root.enabled:
        print "Pickled configuration included rootd"
    else:
        print "Pickled configuration did not include rootd"

    for enabled, handler in ((world.cfg.myrpki.run_rpkid, rpkid_handler),
                             (world.cfg.myrpki.run_rpkid, irdb_handler),
                             (world.cfg.myrpki.run_pubd,  pubd_handler)):
        if not cfg_to_Bool(enabled):
            continue
        if os.fork() == 0:
            handler(cfg, world, root)
            sys.exit()
        else:
            pid, status = os.wait()
            if status and os.WIFEXITED(status):
                sys.exit("Internal process exited with status {}".format(os.WEXITSTATUS(status)))
            if status and os.WIFSIGNALED(status):
                sys.exit("Internal process exited on signal {}".format(os.WTERMSIG(status)))


class Root(object):

    def __init__(self, cfg, world):

        self.enabled = cfg_to_Bool(world.cfg.myrpki.run_rootd)

        if not self.enabled:
            return

        rootd = world.cfg.rootd

        self.root_dir = rootd["rpki-root-dir"]
        self.root_cer = X509(world.file[                            rootd["rpki-root-cert"    ] ])
        self.root_key = RSA( world.file[                            rootd["rpki-root-key"     ] ])
        self.root_crl = CRL( world.file[os.path.join(self.root_dir, rootd["rpki-root-crl"     ])])
        self.root_mft = MFT( world.file[os.path.join(self.root_dir, rootd["rpki-root-manifest"])])
        self.work_cer = X509(world.file[os.path.join(self.root_dir, rootd["rpki-subject-cert" ])])

        self.next_serial = 1 + max(
            self.root_cer.getSerial(),
            self.work_cer.getSerial(),
            self.root_mft.get_POW().certs()[0].getSerial())

        self.root_mft.extract()

        self.next_crl_manifest_number = 1 + max(
            self.root_mft.get_POW().getManifestNumber(),
            self.root_crl.getCRLNumber())

        turtles = tuple(row for row in world.db.irdbd.irdb_turtle
                        if row.id not in (r.turtle_ptr_id
                                          for r in world.db.irdbd.irdb_parent))
        if len(turtles) != 1:
            raise RuntimeError("Expected to find exactly one Parentless Turtle")
        self.rootd_turtle_id = turtles[0].id
        self.rootd_turtle_service_uri = turtles[0].service_uri

        print "Root key: {0.root_key!r}".format(self)
        print "Root cerificate: {0.root_cer!r}".format(self)
        print "Working certificate: {0.work_cer!r}".format(self)
        print "Next certificate serial: {0.next_serial}".format(self)
        print "Next CRL/manifest number: {0.next_crl_manifest_number}".format(self)
        print "Rootd turtle ID {0.rootd_turtle_id}".format(self)
        print "Rootd service URI:{0.rootd_turtle_service_uri}".format(self)

        # We need to build up the arguments that the forked functions should use
        # to create all of the missing objects needed to replace rootd.  We can't
        # (or, rather, shouldn't) attempt to generate SQL id values ourselves,
        # let Django handle that, but everything else we should be able to do.
        #
        # Relatively readable way of doing this would probably be to have one
        # dict per model creation call, containing all the keyword argument stuff
        # needed to create that model except for ID values Django will create
        # (and the forked functions will have to fill in, but they can do that,
        # because such ID values will never cross databases).  So we end up
        # setting a bunch of attributes in this template object, one per
        # model, each containing a dict for that model.

        # XXX
        self.irdb_Parent = dict()
        self.rpkid_Tenant = dict()
        self.rpkid_Parent = dict()
        self.rpkid_CA = dict()
        self.rpkid_CADetail = dict()


def rpkid_handler(cfg, world, root):
    os.environ.update(DJANGO_SETTINGS_MODULE = "rpki.django_settings.rpkid")
    import django
    django.setup()
    import rpki.rpkidb

    show_model("rpkid", "self")
    for row in world.db.rpkid.self:
        show_handle(row.self_handle)
        rpki.rpkidb.models.Tenant.objects.create(
            pk                      = row.self_id,
            tenant_handle           = row.self_handle,
            use_hsm                 = row.use_hsm,
            crl_interval            = row.crl_interval,
            regen_margin            = row.regen_margin,
            bpki_cert               = X509(row.bpki_cert),
            bpki_glue               = X509(row.bpki_glue))

    show_model("rpkid", "bsc")
    for row in world.db.rpkid.bsc:
        show_handle(row.bsc_handle)
        tenant = rpki.rpkidb.models.Tenant.objects.get(pk = row.self_id)
        rpki.rpkidb.models.BSC.objects.create(
            pk                      = row.bsc_id,
            bsc_handle              = row.bsc_handle,
            private_key_id          = RSA(row.private_key_id),
            pkcs10_request          = PKCS10(row.pkcs10_request),
            hash_alg                = row.hash_alg or "sha256",
            signing_cert            = X509(row.signing_cert),
            signing_cert_crl        = CRL(row.signing_cert_crl),
            tenant                  = tenant)

    show_model("rpkid", "repository")
    for row in world.db.rpkid.repository:
        show_handle(row.repository_handle)
        tenant = rpki.rpkidb.models.Tenant.objects.get(pk     = row.self_id)
        bsc    = rpki.rpkidb.models.BSC.objects.get(   pk     = row.bsc_id,
                                                       tenant = row.self_id)
        rpki.rpkidb.models.Repository.objects.create(
            pk                      = row.repository_id,
            repository_handle       = row.repository_handle,
            peer_contact_uri        = row.peer_contact_uri,
            bpki_cert               = X509(row.bpki_cert),
            bpki_glue               = X509(row.bpki_glue),
            last_cms_timestamp      = row.last_cms_timestamp,
            bsc                     = bsc,
            tenant                  = tenant)

    show_model("rpkid", "parent")
    for row in world.db.rpkid.parent:
        show_handle(row.parent_handle)
        tenant     = rpki.rpkidb.models.Tenant.objects.get(    pk     = row.self_id)
        bsc        = rpki.rpkidb.models.BSC.objects.get(       pk     = row.bsc_id,
                                                               tenant = row.self_id)
        repository = rpki.rpkidb.models.Repository.objects.get(pk     = row.repository_id,
                                                               tenant = row.self_id)
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

    show_model("rpkid", "ca")
    for row in world.db.rpkid.ca:
        parent = rpki.rpkidb.models.Parent.objects.get(pk = row.parent_id)
        last_crl_mft_number = max(row.last_crl_sn,
                                  row.last_manifest_sn)
        rpki.rpkidb.models.CA.objects.create(
            pk                      = row.ca_id,
            last_crl_manifest_number= last_crl_mft_number,
            last_issued_sn          = row.last_issued_sn,
            sia_uri                 = row.sia_uri,
            parent_resource_class   = row.parent_resource_class,
            parent                  = parent)

    show_model("rpkid", "ca_detail")
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

    show_model("rpkid", "child")
    for row in world.db.rpkid.child:
        show_handle(row.child_handle)
        tenant     = rpki.rpkidb.models.Tenant.objects.get(pk     = row.self_id)
        bsc        = rpki.rpkidb.models.BSC.objects.get(   pk     = row.bsc_id,
                                                           tenant = row.self_id)
        rpki.rpkidb.models.Child.objects.create(
            pk                      = row.child_id,
            child_handle            = row.child_handle,
            bpki_cert               = X509(row.bpki_cert),
            bpki_glue               = X509(row.bpki_glue),
            last_cms_timestamp      = row.last_cms_timestamp,
            tenant                  = tenant,
            bsc                     = bsc)

    show_model("rpkid", "child_cert")
    for row in world.db.rpkid.child_cert:
        child     = rpki.rpkidb.models.Child.objects.get(   pk = row.child_id)
        ca_detail = rpki.rpkidb.models.CADetail.objects.get(pk = row.ca_detail_id)
        rpki.rpkidb.models.ChildCert.objects.create(
            pk                      = row.child_cert_id,
            cert                    = X509(row.cert),
            published               = row.published,
            gski                    = SKI_to_gSKI(row.ski),
            child                   = child,
            ca_detail               = ca_detail)

    show_model("rpkid", "revoked_cert")
    for row in world.db.rpkid.revoked_cert:
        ca_detail = rpki.rpkidb.models.CADetail.objects.get(pk = row.ca_detail_id)
        rpki.rpkidb.models.RevokedCert.objects.create(
            pk                      = row.revoked_cert_id,
            serial                  = row.serial,
            revoked                 = row.revoked,
            expires                 = row.expires,
            ca_detail               = ca_detail)

    show_model("rpkid", "roa")
    for row in world.db.rpkid.roa:
        tenant    = rpki.rpkidb.models.Tenant.objects.get(  pk = row.self_id)
        ca_detail = rpki.rpkidb.models.CADetail.objects.get(pk = row.ca_detail_id)
        prefixes = tuple(
            (p.version, "{0.prefix}/{0.prefixlen}-{0.max_prefixlen}".format(p))
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

    show_model("rpkid", "ghostbuster")
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

    show_model("rpkid", "ee_cert")
    for row in world.db.rpkid.ee_cert:
        tenant    = rpki.rpkidb.models.Tenant.objects.get(  pk = row.self_id)
        ca_detail = rpki.rpkidb.models.CADetail.objects.get(pk = row.ca_detail_id)
        rpki.rpkidb.models.EECertificate.objects.create(
            pk                      = row.ee_cert_id,
            gski                    = SKI_to_gSKI(row.ski),
            cert                    = X509(row.cert),
            published               = row.published,
            tenant                  = tenant,
            ca_detail               = ca_detail)


def pubd_handler(cfg, world, root):
    os.environ.update(DJANGO_SETTINGS_MODULE = "rpki.django_settings.pubd")
    import django
    django.setup()
    import rpki.pubdb

    show_model("pubd", "client")
    for row in world.db.pubd.client:
        show_handle(row.client_handle)
        rpki.pubdb.models.Client.objects.create(
            pk                  = row.client_id,
            client_handle       = row.client_handle,
            base_uri            = row.base_uri,
            bpki_cert           = X509(row.bpki_cert),
            bpki_glue           = X509(row.bpki_glue),
            last_cms_timestamp  = row.last_cms_timestamp)


def irdb_handler(cfg, world, root):
    os.environ.update(DJANGO_SETTINGS_MODULE = "rpki.django_settings.irdb")
    import django
    django.setup()
    import rpki.irdb

    # Most pk fields are just id.  The one exception is Parent, whose pk
    # is turtle_ptr_id because it's (also) a foreign key pointing at Turtle.id.

    show_model("irdb", "ServerCA")
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

    show_model("irdb", "ResourceHolderCA")
    for row in world.db.irdbd.irdb_resourceholderca:
        show_handle(row.handle)
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

    show_model("irdb", "HostedCA")
    for row in world.db.irdbd.irdb_hostedca:
        issuer = rpki.irdb.models.ServerCA.objects.get(        pk = row.issuer_id)
        hosted = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.hosted_id)
        rpki.irdb.models.HostedCA.objects.create(
            pk                  = row.id,
            certificate         = X509(row.certificate),
            issuer              = issuer,
            hosted              = hosted)

    show_model("irdb", "ServerRevocation")
    for row in world.db.irdbd.irdb_serverrevocation:
        issuer = rpki.irdb.models.ServerCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.ServerRevocation.objects.create(
            pk                  = row.id,
            serial              = row.serial,
            revoked             = row.revoked,
            expires             = row.expires,
            issuer              = issuer)

    show_model("irdb", "ResourceHolderRevocation")
    for row in world.db.irdbd.irdb_resourceholderrevocation:
        issuer = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.ResourceHolderRevocation.objects.create(
            pk                  = row.id,
            serial              = row.serial,
            revoked             = row.revoked,
            expires             = row.expires,
            issuer              = issuer)

    show_model("irdb", "ServerEE")
    for row in world.db.irdbd.irdb_serveree:
        issuer = rpki.irdb.models.ServerCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.ServerEE.objects.create(
            pk                  = row.id,
            certificate         = X509(row.certificate),
            private_key         = RSA(row.private_key),
            purpose             = row.purpose,
            issuer              = issuer)

    show_model("irdb", "Referral")
    for row in world.db.irdbd.irdb_referral:
        issuer = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.Referral.objects.create(
            pk                  = row.id,
            certificate         = X509(row.certificate),
            private_key         = RSA(row.private_key),
            issuer              = issuer)

    show_model("irdb", "BSC")
    for row in world.db.irdbd.irdb_bsc:
        show_handle(row.handle)
        issuer = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.BSC.objects.create(
            pk                  = row.id,
            certificate         = X509(row.certificate),
            handle              = row.handle,
            pkcs10              = PKCS10(row.pkcs10),
            issuer              = issuer)

    show_model("irdb", "Child")
    for row in world.db.irdbd.irdb_child:
        show_handle(row.handle)
        issuer = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.Child.objects.create(
            pk                  = row.id,
            certificate         = X509(row.certificate),
            handle              = row.handle,
            ta                  = X509(row.ta),
            valid_until         = row.valid_until,
            name                = row.name,
            issuer              = issuer)

    show_model("irdb", "ChildASN")
    for row in world.db.irdbd.irdb_childasn:
        child = rpki.irdb.models.Child.objects.get(pk = row.child_id)
        rpki.irdb.models.ChildASN.objects.create(
            pk                  = row.id,
            start_as            = row.start_as,
            end_as              = row.end_as,
            child               = child)

    show_model("irdb", "ChildNet")
    for row in world.db.irdbd.irdb_childnet:
        child = rpki.irdb.models.Child.objects.get(pk = row.child_id)
        rpki.irdb.models.ChildNet.objects.create(
            pk                  = row.id,
            start_ip            = row.start_ip,
            end_ip              = row.end_ip,
            version             = row.version,
            child               = child)

    # We'd like to consolidate Turtle into Parent now that Rootd is gone.
    # Well, guess what, due to the magic of multi-table inheritance,
    # we can write this code as if we had already performed that merge,
    # and the code should work either way.
    #
    # "Django is amazing when it's not terrifying."

    turtle_map = dict((row.id, row) for row in world.db.irdbd.irdb_turtle)

    show_model("irdb", "Parent")
    for row in world.db.irdbd.irdb_parent:
        show_handle(row.handle)
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

    show_model("irdb", "ROARequest")
    for row in world.db.irdbd.irdb_roarequest:
        issuer = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.ROARequest.objects.create(
            pk                  = row.id,
            asn                 = row.asn,
            issuer              = issuer)

    show_model("irdb", "ROARequestPrefix")
    for row in world.db.irdbd.irdb_roarequestprefix:
        roa_request = rpki.irdb.models.ROARequest.objects.get(pk = row.roa_request_id)
        rpki.irdb.models.ROARequestPrefix.objects.create(
            pk                  = row.id,
            version             = row.version,
            prefix              = row.prefix,
            prefixlen           = row.prefixlen,
            max_prefixlen       = row.max_prefixlen,
            roa_request         = roa_request)

    show_model("irdb", "Ghostbuster")
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

    show_model("irdb", "EECertificateRequest")
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

    show_model("irdb", "EECertificateRequestASN")
    for row in world.db.irdbd.irdb_eecertificaterequestasn:
        ee_certificate_request = rpki.irdb.models.EECertificateRequest.objects.get(
            pk = row.ee_certificate_request_id)
        rpki.irdb.models.EECertificateRequestASN.objects.create(
            pk                  = row.id,
            start_as            = row.start_as,
            end_as              = row.end_as,
            ee_certificate_request = ee_certificate_request)

    show_model("irdb", "EECertificateRequestNet")
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
    # We can create an irdb parent, but only handle_rpkid() (or rpkid itself)
    # can create an rpkidb Parent object, so we need to coordinate with handle_rpkid().
    #
    # Probably the best plan is to continue along the path of collecting all the data
    # needed to create all rootd-related objects in this script's Root class, and
    # figure all that out before ever forking any of the handlers.  Then rpkid_handler()
    # and this function can both just create what we already decided to create.

    rrdp_notification_uri = cfg.get(section = "myrpki", option = "publication_rrdp_notification_uri")

    show_model("irdb", "Repository")
    for row in world.db.irdbd.irdb_repository:
        show_handle(row.handle)
        issuer = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.issuer_id)
        try:
            parent = rpki.irdb.models.Parent.objects.get(pk = row.turtle_id)
        except rpki.irdb.models.Parent.DoesNotExist:
            if not root.enabled or row.turtle_id != root.rootd_turtle_id:
                raise
            print "++ Need to create Parent to replace Rootd"
            continue # XXX
            parent = rpki.irdb.models.Parent.objects.create(
                pk              = row.turtle_id,
                service_uri     = root.rootd_turtle_service_uri)
        rpki.irdb.models.Repository.objects.create(
            pk                  = row.id,
            certificate         = X509(row.certificate),
            handle              = row.handle,
            ta                  = X509(row.ta),
            client_handle       = row.client_handle,
            service_uri         = row.service_uri,
            sia_base            = row.sia_base,
            rrdp_notification_uri = rrdp_notification_uri,
            turtle              = parent,
            issuer              = issuer)

    show_model("irdb", "Client")
    for row in world.db.irdbd.irdb_client:
        show_handle(row.handle)
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
