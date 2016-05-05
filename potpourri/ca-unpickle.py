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
import uuid
import time
import cPickle
import tempfile
import datetime
import argparse
import urlparse
import subprocess

import rpki.config
import rpki.x509
import rpki.POW
import rpki.resource_set

from base64 import urlsafe_b64encode

class LazyDict(object):
    """
    Convenience wrapper to allow attribute notation for brevity
    when diving into deeply nested mappings created by ca-pickle.
    """

    def __init__(self, *args, **kwargs):
        #self._d = dict(*args, **kwargs)
        self.__dict__["_d"] = dict(*args, **kwargs)
        for k, v in self._d.iteritems():
            self._d[k] = self._insinuate(v)

    def __getattr__(self, name):
        if name in self._d:
            return self._d[name]
        name = name.replace("_", "-")
        if name in self._d:
            return self._d[name]
        raise AttributeError

    def __setattr__(self, name, value):
        if name in self._d:
            self._d[name] = value
        else:
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


class FixURI(object):
    """
    Clean up URIs.  Mostly this means adjusting port numbers as necessary
    to accomodate differences between pickled and current rpki.conf.
    """

    def __init__(self, cfg, args, world):
        fmt = "{host}:{port}".format
        self.old_rpkid = fmt(host = world.cfg.rpkid.server_host,
                             port = world.cfg.rpkid.server_port)
        self.new_rpkid = fmt(host = cfg.get(section = "rpkid", option  = "server-host"),
                             port = cfg.get(section = "rpkid", option  = "server-port"))
        self.old_pubd  = fmt(host = world.cfg.pubd.server_host,
                             port = world.cfg.pubd.server_port)
        self.new_pubd  = fmt(host = cfg.get(section = "pubd", option  = "server-host"),
                             port = cfg.get(section = "pubd", option  = "server-port"))
        self.new_irdbd = fmt(host = world.cfg.irdbd.server_host,
                             port = world.cfg.irdbd.server_port)
        self.new_irdbd = fmt(host = cfg.get(section = "irdbd", option  = "server-host"),
                             port = cfg.get(section = "irdbd", option  = "server-port"))
        self.old_rsyncd = world.cfg.myrpki.publication_rsync_server
        self.new_rsyncd = cfg.get(section = "myrpki",
                                  option = "publication_rsync_server")

    def _fix(self, uri, scheme, old_netloc, new_netloc):
        u = urlparse.urlparse(uri)
        uri = urlparse.urlunparse(u)
        old = urlparse.urlunparse((scheme, old_netloc) + u[2:])
        new = urlparse.urlunparse((scheme, new_netloc) + u[2:])
        return new if uri == old or not u.netloc else uri

    def rpkid(self, uri):  return self._fix(uri, "http",  self.old_rpkid,  self.new_rpkid)
    def pubd(self, uri):   return self._fix(uri, "http",  self.old_pubd,   self.new_pubd)
    def irdbd(self, uri):  return self._fix(uri, "http",  self.old_irdbd,  self.new_irdbd)
    def rsyncd(self, uri): return self._fix(uri, "rsync", self.old_rsyncd, self.new_rsyncd)


# None-safe wrappers for ASN.1 constructors.
def NoneSafe(obj, cls):
    if obj is None:
        return None
    elif "-----BEGIN" in obj:
        return cls(PEM = obj)
    else:
        return cls(DER = obj)

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

def show_instance(id, handle = None):
    if handle:
        print " ", id, handle
    else:
        print " ", id

# Smoke 'em if you got 'em

def main():

    os.environ.update(TZ = "UTC")
    time.tzset()

    cfg = rpki.config.argparser(doc = __doc__)
    cfg.argparser.add_argument("--rootd", action = "store_true",
                               help = "enable extra processing for rootd transitions")
    cfg.add_logging_arguments()
    cfg.argparser.add_argument("input_file", help = "input file")
    args = cfg.argparser.parse_args()
    cfg.configure_logging(args = args)

    xzcat = subprocess.Popen(("xzcat", args.input_file), stdout = subprocess.PIPE)
    world = LazyDict(cPickle.load(xzcat.stdout))
    if xzcat.wait() != 0:
        sys.exit("XZ unpickling failed with code {}".format(xzcat.returncode))

    fixuri = FixURI(cfg, args, world)

    root = Root(cfg, args, world, fixuri)

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
            handler(cfg, args, world, root, fixuri)
            sys.exit()
        else:
            pid, status = os.wait()
            if status and os.WIFEXITED(status):
                sys.exit("Internal process exited with status {}".format(os.WEXITSTATUS(status)))
            if status and os.WIFSIGNALED(status):
                sys.exit("Internal process exited on signal {}".format(os.WTERMSIG(status)))


class Root(object):

    @staticmethod
    def iter_get(iterable):
        result = tuple(iterable)
        if len(result) == 1:
            return result[0]
        else:
            raise RuntimeError("Iterable returned {} results, expected one".format(len(result)))

    def __init__(self, cfg, args, world, fixuri):

        self.enabled = cfg_to_Bool(world.cfg.myrpki.run_rootd) and args.rootd

        if not self.enabled:
            return

        r = world.cfg.rootd
        d = os.path.join(r.rpki_root_dir, "")

        rpki_root_cer  = X509(world.file[    r.rpki_root_cert    ])
        rpki_root_key  = RSA( world.file[    r.rpki_root_key     ])
        rpki_root_crl  = CRL( world.file[d + r.rpki_root_crl     ])
        rpki_root_mft  = MFT( world.file[d + r.rpki_root_manifest])
        rpki_work_cer  = X509(world.file[d + r.rpki_subject_cert ])

        rootd_bpki_ta  = X509(world.file[    r.bpki_ta           ])
        rootd_bpki_cer = X509(world.file[    r.rootd_bpki_cert   ])
        rootd_bpki_key = RSA( world.file[    r.rootd_bpki_key    ])
        child_bpki_cer = X509(world.file[    r.child_bpki_cert   ])

        rpki_root_resources  = rpki_root_cer.get_3779resources()
        rpki_root_class_name = r.rpki_class_name

        rpki_root_mft_key = rpki.x509.RSA.generate()

        # Maybe we'll figure out a prettier handle to use later
        root_handle = str(uuid.uuid4())

        rpki_root_last_serial = max(
            rpki_root_cer.getSerial(),
            rpki_work_cer.getSerial(),
            self.iter_get(rpki_root_mft.get_POW().certs()).getSerial())

        rpki_root_mft.extract()

        rpki_root_last_crl_manifest_number = max(
            rpki_root_mft.get_POW().getManifestNumber(),
            rpki_root_crl.getCRLNumber())

        rootd_turtle = self.iter_get(row for row in world.db.irdbd.irdb_turtle
                                     if row.id not in
                                     frozenset(p.turtle_ptr_id for p in world.db.irdbd.irdb_parent))
        self.rootd_turtle_id = rootd_turtle.id

        serverca = self.iter_get(world.db.irdbd.irdb_serverca)
        serverca_cer = X509(serverca.certificate)
        serverca_key = RSA(serverca.private_key)

        rootd = self.iter_get(world.db.irdbd.irdb_rootd)

        work_resourceholderca = self.iter_get(row for row in world.db.irdbd.irdb_resourceholderca
                                              if row.id == rootd.issuer_id)
        work_resourceholderca_cer = X509(work_resourceholderca.certificate)

        self.work_resourceholderca_id = work_resourceholderca.id

        work_tenant = self.iter_get(row for row in world.db.rpkid.self
                                    if row.self_handle == work_resourceholderca.handle)

        work_rpkid_parent = self.iter_get(row for row in world.db.rpkid.parent
                                          if row.parent_handle == work_resourceholderca.handle
                                          and row.self_id == work_tenant.self_id)

        now = rpki.sundial.now()

        crl_interval = cfg.getint(section = "myrpki",
                                  option  = "tenant_crl_interval",
                                  default = 6 * 60 * 60)

        regen_margin = cfg.getint(section = "myrpki",
                                  option  = "tenant_regen_margin",
                                  default = 14 * 24 * 60 * 60 + 2 * 60)

        # Whole lota new BPKI glorp.

        root_resourceholderca_serial = 1
        root_resourceholderca_key = rpki.x509.RSA.generate()
        root_resourceholderca_cer = rpki.x509.X509.bpki_self_certify(
            keypair             = root_resourceholderca_key,
            subject_name        = rpki.x509.X501DN.from_cn("{} BPKI resource CA".format(root_handle)),
            serial              = root_resourceholderca_serial,
            now                 = now,
            notAfter            = now + rpki.sundial.timedelta(days = 3652))
        root_resourceholderca_serial += 1
        root_resourceholderca_crl = rpki.x509.CRL.generate(
            keypair             = root_resourceholderca_key,
            issuer              = root_resourceholderca_cer,
            serial              = 1,
            thisUpdate          = now,
            nextUpdate          = now + rpki.sundial.timedelta(hours = 25),
            revokedCertificates = ())

        root_bsc_key    = rpki.x509.RSA.generate()
        root_bsc_pkcs10 = rpki.x509.PKCS10.create(keypair = root_bsc_key)
        root_bsc_cer    = root_resourceholderca_cer.bpki_certify(
            keypair             = root_resourceholderca_key,
            subject_name        = root_bsc_pkcs10.getSubject(),
            subject_key         = root_bsc_pkcs10.getPublicKey(),
            serial              = root_resourceholderca_serial,
            now                 = now,
            notAfter            = now + rpki.sundial.timedelta(days = 60),
            is_ca               = False,
            pathLenConstraint   = None)
        root_resourceholderca_serial += 1

        root_repository_bpki_cer = root_resourceholderca_cer.bpki_certify(
            keypair             = root_resourceholderca_key,
            subject_name        = serverca_cer.getSubject(),
            subject_key         = serverca_cer.getPublicKey(),
            serial              = root_resourceholderca_serial,
            now                 = now,
            notAfter            = now + rpki.sundial.timedelta(days = 60),
            is_ca               = True,
            pathLenConstraint   = 0)
        root_resourceholderca_serial += 1

        root_parent_bpki_cer = root_resourceholderca_cer.bpki_certify(
            keypair             = root_resourceholderca_key,
            subject_name        = root_resourceholderca_cer.getSubject(),
            subject_key         = root_resourceholderca_cer.getPublicKey(),
            serial              = root_resourceholderca_serial,
            now                 = now,
            notAfter            = now + rpki.sundial.timedelta(days = 60),
            is_ca               = True,
            pathLenConstraint   = 0)
        root_resourceholderca_serial += 1

        root_child_bpki_cer =  root_resourceholderca_cer.bpki_certify(
            keypair             = root_resourceholderca_key,
            subject_name        = work_resourceholderca_cer.getSubject(),
            subject_key         = work_resourceholderca_cer.getPublicKey(),
            serial              = root_resourceholderca_serial,
            now                 = now,
            notAfter            = now + rpki.sundial.timedelta(days = 60),
            is_ca               = True,
            pathLenConstraint   = 0)
        root_resourceholderca_serial += 1

        root_hostedca_cer = serverca_cer.bpki_certify(
            keypair             = serverca_key,
            subject_name        = root_resourceholderca_cer.getSubject(),
            subject_key         = root_resourceholderca_cer.getPublicKey(),
            serial              = serverca.next_serial,
            now                 = now,
            notAfter            = now + rpki.sundial.timedelta(days = 60),
            is_ca               = True,
            pathLenConstraint   = 1)
        serverca.next_serial += 1

        root_client_cer = serverca_cer.bpki_certify(
            keypair             = serverca_key,
            subject_name        = root_resourceholderca_cer.getSubject(),
            subject_key         = root_resourceholderca_cer.getPublicKey(),
            serial              = serverca.next_serial,
            now                 = now,
            notAfter            = now + rpki.sundial.timedelta(days = 60),
            is_ca               = True,
            pathLenConstraint   = 0)
        serverca.next_serial += 1

        # Various contact URIs.

        root_up_down_path = "/up-down/{root}/{work}".format(
            root = root_handle,
            work = work_resourceholderca.handle)

        root_loopback_uri = fixuri.rpkid("/up-down/{root}/{root}".format(
            root = root_handle))

        root_publication_control_uri = fixuri.pubd("/client/{root}".format(
            root = root_handle))

        root_rsync_uri = fixuri.rsyncd("/{module}/{handle}/".format(
            module = cfg.get(section = "myrpki", option = "publication_rsync_module"),
            handle = root_handle))

        rpki_root_cer_uri = fixuri.rsyncd("/{module}/{gski}.cer".format(
            module = cfg.get(section = "myrpki", option = "publication_rsync_module"),
            gski   = rpki_root_key.gSKI()))

        rpki_root_crl_uri = root_rsync_uri + rpki_root_key.gSKI() + ".crl"

        rpki_root_mft_uri = root_rsync_uri + rpki_root_key.gSKI() + ".mft"

        rrdp_notification_uri = cfg.get(section = "myrpki",
                                        option = "publication_rrdp_notification_uri")

        # Some sanity checks

        if len(world.db.irdbd.irdb_rootd) != 1:
            raise RuntimeError("Unexpected length for pickled rpki.irdb.models.Rootd")

        if rootd.turtle_ptr_id != self.rootd_turtle_id:
            raise RuntimeError("Pickled rpki.irdb.models.Rootd does not match Turtle ID")

        if rootd.certificate != rootd_bpki_cer.get_DER():
            raise RuntimeError("Pickled rootd BPKI certificate does not match pickled SQL")

        if rootd.private_key != rootd_bpki_key.get_DER():
            raise RuntimeError("Pickled rootd BPKI key does not match pickled SQL")

        if rootd_turtle.service_uri != work_rpkid_parent.peer_contact_uri:
            raise RuntimeError("Inconsistent pickled Rootd configuration")

        if serverca_cer != rootd_bpki_ta:
            raise RuntimeError("Pickled rootd BPKI TA does not match pickled SQL ServerCA")

        if work_resourceholderca_cer != child_bpki_cer:
            raise RuntimeError("Pickled rootd BPKI child CA does not match pickled SQL")

        if rootd_turtle.service_uri != "http://{host}:{port}/".format(
                host = world.cfg.rootd.server_host,
                port = world.cfg.rootd.server_port):
            raise RuntimeError("Pickled Rootd service_uri does not match pickled configuration")

        # Updated RPKI root certificate, CRL and manifest.
        # The root certificate URI here isn't really right, but it's (probably) harmless.

        rpki_root_last_serial += 1
        rpki_root_cer = rpki.x509.X509.self_certify(
            keypair             = rpki_root_key,
            subject_key         = rpki_root_key.get_public(),
            serial              = rpki_root_last_serial,
            sia                 = (root_rsync_uri, rpki_root_mft_uri, None, rrdp_notification_uri),
            notAfter            = rpki_root_resources.valid_until,
            resources           = rpki_root_resources)

        rpki_root_last_crl_manifest_number += 1

        root_rpki_crl = rpki.x509.CRL.generate(
            keypair             = rpki_root_key,
            issuer              = rpki_root_cer,
            serial              = rpki_root_last_crl_manifest_number,
            thisUpdate          = now,
            nextUpdate          = now + rpki.sundial.timedelta(seconds = crl_interval),
            revokedCertificates = ())

        rpki_root_last_serial += 1
        mft_cer = rpki_root_cer.issue(
            keypair             = rpki_root_key,
            subject_key         = rpki_root_mft_key.get_public(),
            serial              = rpki_root_last_serial,
            sia                 = (None, None, rpki_root_mft_uri, rrdp_notification_uri),
            resources           = rpki.resource_set.resource_bag.from_inheritance(),
            aia                 = rpki_root_cer_uri,
            crldp               = rpki_root_crl_uri,
            notBefore           = now,
            notAfter            = rpki_root_cer.getNotAfter(),
            is_ca               = False)

        rpki_root_mft_objs = [
            (rpki_root_key.gSKI() + ".crl", root_rpki_crl),
            (work_resourceholderca_cer.gSKI() + ".cer", work_resourceholderca_cer)]

        rpki_root_mft = rpki.x509.SignedManifest.build(
            keypair             = rpki_root_mft_key,
            certs               = mft_cer,
            serial              = rpki_root_last_crl_manifest_number,
            thisUpdate          = now,
            nextUpdate          = now + rpki.sundial.timedelta(seconds = crl_interval),
            names_and_objs      = rpki_root_mft_objs)

        # Adjust saved working CA's parent object to point at new root.
        # We supply just the path portion of the URI here, to avoid confusing fixuri.rpkid() later.
        #
        # NB: This is the rpkid Parent object.  We'd perform the same updates for the irdb Parent
        # object, but it doesn't exist under the old schema, instead we had the Rootd object which
        # doesn't contain the fields we need to set here.  So we'll need to create a new irdb Parent
        # object for the working CA, coresponding to the rpkid Parent object we're updating here.

        work_rpkid_parent.parent_handle    = root_handle
        work_rpkid_parent.recipient_name   = root_handle
        work_rpkid_parent.peer_contact_uri = root_up_down_path
        work_rpkid_parent.bpki_cms_cert    = root_hostedca_cer.get_DER()

        # Templates we'll pass to ORM .objects.create() calls in handlers,
        # after filling in foreign key fields as needed.

        self.irdb_work_Parent = dict(
            certificate                 = root_hostedca_cer,
            handle                      = root_handle,
            ta                          = root_resourceholderca_cer,
            service_uri                 = fixuri.rpkid(root_up_down_path),
            parent_handle               = root_handle,
            child_handle                = work_rpkid_parent.sender_name,
            repository_type             = "none",
            referrer                    = None,
            referral_authorization      = None,
            asn_resources               = "",
            ipv4_resources              = "",
            ipv6_resources              = "",
            # Foreign keys:             issuer
        )

        self.irdb_root_ResourceHolderCA = dict(
            certificate                 = root_resourceholderca_cer,
            private_key                 = root_resourceholderca_key,
            latest_crl                  = root_resourceholderca_crl,
            next_serial                 = root_resourceholderca_serial,
            next_crl_number             = 2,
            last_crl_update             = root_resourceholderca_crl.getThisUpdate(),
            next_crl_update             = root_resourceholderca_crl.getNextUpdate(),
            handle                      = root_handle,
        )

        self.irdb_root_HostedCA = dict(
            certificate                 = root_hostedca_cer,
            # Foreign keys:             issuer, hosted
        )

        self.irdb_root_Parent = dict(
            certificate                 = root_parent_bpki_cer,
            handle                      = root_handle,
            ta                          = root_resourceholderca_cer,
            service_uri                 = root_loopback_uri,
            parent_handle               = root_handle,
            child_handle                = root_handle,
            repository_type             = "none",
            referrer                    = None,
            referral_authorization      = None,
            asn_resources               = "0-4294967295",
            ipv4_resources              = "0.0.0.0/0",
            ipv6_resources              = "::/0",
            # Foreign keys:             issuer
        )

        self.irdb_root_BSC = dict(
            certificate                 = root_bsc_cer,
            handle                      = "bsc",
            pkcs10                      = root_bsc_pkcs10,
            # Foreign keys:             issuer
        )

        self.irdb_root_Child = dict(
            certificate                 = root_child_bpki_cer,
            handle                      = work_resourceholderca.handle,
            ta                          = work_resourceholderca_cer,
            valid_until                 = work_resourceholderca_cer.getNotAfter(),
            # Foreign keys:             issuer
        )

        self.irdb_root_ChildASN = dict(
            start_as                    = 0,
            end_as                      = 4294967295,
            # Foreign keys:             child
        )

        self.irdb_root_ChildNet = dict(
            start_ip                    = "0.0.0.0",
            end_ip                      = "255.255.255.255",
            version                     = 4,
            # Foreign keys:             child
        )

        self.irdb_root_ChildNet = dict(
            start_ip                    = "::",
            end_ip                      = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            version                     = 6,
            # Foreign keys:             child
        )

        self.irdb_root_Repository = dict(
            certificate                 = root_repository_bpki_cer,
            handle                      = root_handle,
            ta                          = serverca_cer,
            client_handle               = root_handle,
            service_uri                 = root_publication_control_uri,
            sia_base                    = root_rsync_uri,
            rrdp_notification_uri       = rrdp_notification_uri,
            # Foreign keys:             issuer, parent
        )

        self.irdb_root_Client = dict(
            certificate                 = root_client_cer,
            handle                      = root_handle,
            ta                          = root_resourceholderca_cer,
            sia_base                    = root_rsync_uri,
            # Foreign keys:             issuer
        )

        self.pubd_root_Client = dict(
            client_handle               = root_handle,
            base_uri                    = root_rsync_uri,
            bpki_cert                   = root_client_cer,
            bpki_glue                   = None,
            last_cms_timestamp          = None,
        )

        self.rpkid_root_Tenant = dict(
            tenant_handle               = root_handle,
            use_hsm                     = False,
            crl_interval                = crl_interval,
            regen_margin                = regen_margin,
            bpki_cert                   = root_hostedca_cer,
            bpki_glue                   = None,
        )

        self.rpkid_root_BSC = dict(
            bsc_handle                  = "bsc",
            private_key_id              = root_bsc_key,
            pkcs10_request              = root_bsc_pkcs10,
            signing_cert                = root_bsc_cer,
            signing_cert_crl            = root_resourceholderca_crl,
            # Foreign keys:             tenant
        )

        self.rpkid_root_Repository = dict(
            repository_handle           = root_handle,
            peer_contact_uri            = root_publication_control_uri,
            rrdp_notification_uri       = rrdp_notification_uri,
            bpki_cert                   = root_repository_bpki_cer,
            bpki_glue                   = None,
            last_cms_timestamp          = None,
            # Foreign keys:             tenant, bsc
        )

        self.rpkid_root_Parent = dict(
            parent_handle               = root_handle,
            bpki_cert                   = root_parent_bpki_cer,
            bpki_glue                   = None,
            peer_contact_uri            = root_loopback_uri,
            sia_base                    = root_rsync_uri,
            sender_name                 = root_handle,
            recipient_name              = root_handle,
            last_cms_timestamp          = None,
            root_asn_resources          = "0-4294967295",
            root_ipv4_resources         = "0.0.0.0/0",
            root_ipv6_resources         = "::/0",
            # Foreign keys:             tenant, bsc, repository
        )

        self.rpkid_root_CA = dict(
            last_crl_manifest_number    = rpki_root_last_crl_manifest_number,
            last_issued_sn              = rpki_root_last_serial,
            sia_uri                     = root_rsync_uri,
            parent_resource_class       = world.cfg.rootd.rpki_class_name,
            # Foreign keys:             parent
        )

        self.rpkid_root_CADetail = dict(
            public_key                  = rpki_root_key.get_public(),
            private_key_id              = rpki_root_key,
            latest_crl                  = rpki_root_crl,
            crl_published               = None,
            latest_ca_cert              = rpki_root_cer,
            manifest_private_key_id     = rpki_root_mft_key,
            manifest_public_key         = rpki_root_mft_key.get_public(),
            latest_manifest             = rpki_root_mft,
            manifest_published          = None,
            state                       = "active",
            ca_cert_uri                 = rpki_root_cer_uri,
            # Foreign keys:             ca
        )

        self.rpkid_root_Child = dict(
            child_handle                = work_resourceholderca.handle,
            bpki_cert                   = root_child_bpki_cer,
            bpki_glue                   = None,
            last_cms_timestamp          = None,
            # Foreign keys:             tenant, bsc
        )

        self.rpkid_root_ChildCert = dict(
            cert                        = rpki_work_cer,
            published                   = None,
            gski                        = rpki_work_cer.gSKI(),
            # Foreign keys:             child, ca_detail
        )


def reset_sequence(*app_labels):
    # Apparently this is the approved way of telling the database to reset its
    # idea of what sequence numbers to use in AutoField columns we've touched.
    #
    # The need to specify "--no-color" here is a particularly cute touch.

    from django.core import management
    from django.db   import connection

    with tempfile.TemporaryFile() as f:
        management.call_command("sqlsequencereset", *app_labels, no_color = True, stdout = f)
        f.seek(0)
        cmds = f.read().split(";")

    with connection.cursor() as cur:
        for cmd in cmds:
            cmd = cmd.strip()
            if cmd:
                cur.execute(cmd)


def rpkid_handler(cfg, args, world, root, fixuri):
    os.environ.update(DJANGO_SETTINGS_MODULE = "rpki.django_settings.rpkid")
    import django
    django.setup()
    import rpki.rpkidb

    show_model("rpkid", "self")
    for row in world.db.rpkid.self:
        show_instance(row.self_id, row.self_handle)
        rpki.rpkidb.models.Tenant.objects.create(
            pk                          = row.self_id,
            tenant_handle               = row.self_handle,
            use_hsm                     = row.use_hsm,
            crl_interval                = row.crl_interval,
            regen_margin                = row.regen_margin,
            bpki_cert                   = X509(row.bpki_cert),
            bpki_glue                   = X509(row.bpki_glue))

    show_model("rpkid", "bsc")
    for row in world.db.rpkid.bsc:
        show_instance(row.bsc_id, row.bsc_handle)
        tenant = rpki.rpkidb.models.Tenant.objects.get(pk = row.self_id)
        rpki.rpkidb.models.BSC.objects.create(
            pk                          = row.bsc_id,
            bsc_handle                  = row.bsc_handle,
            private_key_id              = RSA(row.private_key_id),
            pkcs10_request              = PKCS10(row.pkcs10_request),
            hash_alg                    = row.hash_alg or "sha256",
            signing_cert                = X509(row.signing_cert),
            signing_cert_crl            = CRL(row.signing_cert_crl),
            tenant                      = tenant)

    rrdp_notification_uri = cfg.get(section = "myrpki", option = "publication_rrdp_notification_uri")

    show_model("rpkid", "repository")
    for row in world.db.rpkid.repository:
        show_instance(row.repository_id, row.repository_handle)
        tenant = rpki.rpkidb.models.Tenant.objects.get(pk     = row.self_id)
        bsc    = rpki.rpkidb.models.BSC.objects.get(   pk     = row.bsc_id,
                                                       tenant = row.self_id)
        rpki.rpkidb.models.Repository.objects.create(
            pk                          = row.repository_id,
            repository_handle           = row.repository_handle,
            peer_contact_uri            = fixuri.pubd(row.peer_contact_uri),
            rrdp_notification_uri       = rrdp_notification_uri,
            bpki_cert                   = X509(row.bpki_cert),
            bpki_glue                   = X509(row.bpki_glue),
            last_cms_timestamp          = row.last_cms_timestamp,
            bsc                         = bsc,
            tenant                      = tenant)

    show_model("rpkid", "parent")
    for row in world.db.rpkid.parent:
        show_instance(row.parent_id, row.parent_handle)
        tenant     = rpki.rpkidb.models.Tenant.objects.get(    pk     = row.self_id)
        bsc        = rpki.rpkidb.models.BSC.objects.get(       pk     = row.bsc_id,
                                                               tenant = row.self_id)
        repository = rpki.rpkidb.models.Repository.objects.get(pk     = row.repository_id,
                                                               tenant = row.self_id)
        rpki.rpkidb.models.Parent.objects.create(
            pk                          = row.parent_id,
            parent_handle               = row.parent_handle,
            bpki_cert                   = X509(row.bpki_cms_cert),
            bpki_glue                   = X509(row.bpki_cms_glue),
            peer_contact_uri            = fixuri.rpkid(row.peer_contact_uri),
            sia_base                    = fixuri.rsyncd(row.sia_base),
            sender_name                 = row.sender_name,
            recipient_name              = row.recipient_name,
            last_cms_timestamp          = row.last_cms_timestamp,
            bsc                         = bsc,
            repository                  = repository,
            tenant                      = tenant)

    show_model("rpkid", "ca")
    for row in world.db.rpkid.ca:
        show_instance(row.ca_id)
        parent = rpki.rpkidb.models.Parent.objects.get(pk = row.parent_id)
        last_crl_mft_number = max(row.last_crl_sn,
                                  row.last_manifest_sn)
        rpki.rpkidb.models.CA.objects.create(
            pk                          = row.ca_id,
            last_crl_manifest_number    = last_crl_mft_number,
            last_issued_sn              = row.last_issued_sn,
            sia_uri                     = fixuri.rsyncd(row.sia_uri),
            parent_resource_class       = row.parent_resource_class,
            parent                      = parent)

    show_model("rpkid", "ca_detail")
    for row in world.db.rpkid.ca_detail:
        show_instance(row.ca_detail_id)
        ca = rpki.rpkidb.models.CA.objects.get(pk = row.ca_id)
        rpki.rpkidb.models.CADetail.objects.create(
            pk                          = row.ca_detail_id,
            public_key                  = RSA(row.public_key),
            private_key_id              = RSA(row.private_key_id),
            latest_crl                  = CRL(row.latest_crl),
            crl_published               = row.crl_published,
            latest_ca_cert              = X509(row.latest_ca_cert),
            manifest_private_key_id     = RSA(row.manifest_private_key_id),
            manifest_public_key         = RSA(row.manifest_public_key),
            latest_manifest             = MFT(row.latest_manifest),
            manifest_published          = row.manifest_published,
            state                       = row.state,
            ca_cert_uri                 = fixuri.rsyncd(row.ca_cert_uri),
            ca                          = ca)

    show_model("rpkid", "child")
    for row in world.db.rpkid.child:
        show_instance(row.child_id, row.child_handle)
        tenant     = rpki.rpkidb.models.Tenant.objects.get(pk     = row.self_id)
        bsc        = rpki.rpkidb.models.BSC.objects.get(   pk     = row.bsc_id,
                                                           tenant = row.self_id)
        rpki.rpkidb.models.Child.objects.create(
            pk                          = row.child_id,
            child_handle                = row.child_handle,
            bpki_cert                   = X509(row.bpki_cert),
            bpki_glue                   = X509(row.bpki_glue),
            last_cms_timestamp          = row.last_cms_timestamp,
            tenant                      = tenant,
            bsc                         = bsc)

    show_model("rpkid", "child_cert")
    for row in world.db.rpkid.child_cert:
        show_instance(row.child_cert_id)
        child     = rpki.rpkidb.models.Child.objects.get(   pk = row.child_id)
        ca_detail = rpki.rpkidb.models.CADetail.objects.get(pk = row.ca_detail_id)
        rpki.rpkidb.models.ChildCert.objects.create(
            pk                          = row.child_cert_id,
            cert                        = X509(row.cert),
            published                   = row.published,
            gski                        = SKI_to_gSKI(row.ski),
            child                       = child,
            ca_detail                   = ca_detail)

    show_model("rpkid", "revoked_cert")
    for row in world.db.rpkid.revoked_cert:
        show_instance(row.revoked_cert_id)
        ca_detail = rpki.rpkidb.models.CADetail.objects.get(pk = row.ca_detail_id)
        rpki.rpkidb.models.RevokedCert.objects.create(
            pk                          = row.revoked_cert_id,
            serial                      = row.serial,
            revoked                     = row.revoked,
            expires                     = row.expires,
            ca_detail                   = ca_detail)

    show_model("rpkid", "roa")
    for row in world.db.rpkid.roa:
        show_instance(row.roa_id)
        tenant    = rpki.rpkidb.models.Tenant.objects.get(  pk = row.self_id)
        ca_detail = rpki.rpkidb.models.CADetail.objects.get(pk = row.ca_detail_id)
        prefixes = tuple(
            (p.version, "{0.prefix}/{0.prefixlen}-{0.max_prefixlen}".format(p))
            for p in world.db.rpkid.roa_prefix
            if p.roa_id == row.roa_id)
        ipv4 = ",".join(p for v, p in prefixes if v == 4) or None
        ipv6 = ",".join(p for v, p in prefixes if v == 6) or None
        rpki.rpkidb.models.ROA.objects.create(
            pk                          = row.roa_id,
            asn                         = row.asn,
            ipv4                        = ipv4,
            ipv6                        = ipv6,
            cert                        = X509(row.cert),
            roa                         = ROA(row.roa),
            published                   = row.published,
            tenant                      = tenant,
            ca_detail                   = ca_detail)

    show_model("rpkid", "ghostbuster")
    for row in world.db.rpkid.ghostbuster:
        show_instance(row.ghostbuster_id)
        tenant    = rpki.rpkidb.models.Tenant.objects.get(  pk = row.self_id)
        ca_detail = rpki.rpkidb.models.CADetail.objects.get(pk = row.ca_detail_id)
        rpki.rpkidb.models.Ghostbuster.objects.create(
            pk                          = row.ghostbuster_id,
            vcard                       = row.vcard,
            cert                        = X509(row.cert),
            ghostbuster                 = GBR(row.ghostbuster),
            published                   = row.published,
            tenant                      = tenant,
            ca_detail                   = ca_detail)

    show_model("rpkid", "ee_cert")
    for row in world.db.rpkid.ee_cert:
        show_instance(row.ee_cert_id)
        tenant    = rpki.rpkidb.models.Tenant.objects.get(  pk = row.self_id)
        ca_detail = rpki.rpkidb.models.CADetail.objects.get(pk = row.ca_detail_id)
        rpki.rpkidb.models.EECertificate.objects.create(
            pk                          = row.ee_cert_id,
            gski                        = SKI_to_gSKI(row.ski),
            cert                        = X509(row.cert),
            published                   = row.published,
            tenant                      = tenant,
            ca_detail                   = ca_detail)

    reset_sequence("rpkidb")

    if root.enabled:
        tenant = rpki.rpkidb.models.Tenant.objects.create(**dict(
            root.rpkid_root_Tenant))
        bsc = rpki.rpkidb.models.BSC.objects.create(**dict(
            root.rpkid_root_BSC,
            tenant = tenant))
        repository = rpki.rpkidb.models.Repository.objects.create(**dict(
            root.rpkid_root_Repository,
            tenant = tenant,
            bsc    = bsc))
        parent = rpki.rpkidb.models.Parent.objects.create(**dict(
            root.rpkid_root_Parent,
            tenant     = tenant,
            bsc        = bsc,
            repository = repository))
        ca = rpki.rpkidb.models.CA.objects.create(**dict(
            root.rpkid_root_CA,
            parent = parent))
        ca_detail = rpki.rpkidb.models.CADetail.objects.create(**dict(
            root.rpkid_root_CADetail,
            ca = ca))
        child = rpki.rpkidb.models.Child.objects.create(**dict(
            root.rpkid_root_Child,
            tenant = tenant,
            bsc    = bsc))
        child_cert = rpki.rpkidb.models.ChildCert.objects.create(**dict(
            root.rpkid_root_ChildCert,
            child     = child,
            ca_detail = ca_detail))


def pubd_handler(cfg, args, world, root, fixuri):
    os.environ.update(DJANGO_SETTINGS_MODULE = "rpki.django_settings.pubd")
    import django
    django.setup()
    import rpki.pubdb

    show_model("pubd", "client")
    for row in world.db.pubd.client:
        show_instance(row.client_id, row.client_handle)
        rpki.pubdb.models.Client.objects.create(
            pk                          = row.client_id,
            client_handle               = row.client_handle,
            base_uri                    = fixuri.rsyncd(row.base_uri),
            bpki_cert                   = X509(row.bpki_cert),
            bpki_glue                   = X509(row.bpki_glue),
            last_cms_timestamp          = row.last_cms_timestamp)

    reset_sequence("pubdb")

    if root.enabled:
        rpki.pubdb.models.Client.objects.create(**dict(
            root.pubd_root_Client))


def irdb_handler(cfg, args, world, root, fixuri):
    os.environ.update(DJANGO_SETTINGS_MODULE = "rpki.django_settings.irdb")
    import django
    django.setup()
    import rpki.irdb

    # Most pk fields are just id.  The one exception is Parent, whose pk
    # is turtle_ptr_id because it's (also) a foreign key pointing at Turtle.id.

    show_model("irdb", "ServerCA")
    for row in world.db.irdbd.irdb_serverca:
        show_instance(row.id)
        rpki.irdb.models.ServerCA.objects.create(
            pk                          = row.id,
            certificate                 = X509(row.certificate),
            private_key                 = RSA(row.private_key),
            latest_crl                  = CRL(row.latest_crl),
            next_serial                 = row.next_serial,
            next_crl_number             = row.next_crl_number,
            last_crl_update             = row.last_crl_update,
            next_crl_update             = row.next_crl_update)

    show_model("irdb", "ResourceHolderCA")
    for row in world.db.irdbd.irdb_resourceholderca:
        show_instance(row.id, row.handle)
        rpki.irdb.models.ResourceHolderCA.objects.create(
            pk                          = row.id,
            certificate                 = X509(row.certificate),
            private_key                 = RSA(row.private_key),
            latest_crl                  = CRL(row.latest_crl),
            next_serial                 = row.next_serial,
            next_crl_number             = row.next_crl_number,
            last_crl_update             = row.last_crl_update,
            next_crl_update             = row.next_crl_update,
            handle                      = row.handle)

    show_model("irdb", "HostedCA")
    for row in world.db.irdbd.irdb_hostedca:
        show_instance(row.id)
        issuer = rpki.irdb.models.ServerCA.objects.get(        pk = row.issuer_id)
        hosted = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.hosted_id)
        rpki.irdb.models.HostedCA.objects.create(
            pk                          = row.id,
            certificate                 = X509(row.certificate),
            issuer                      = issuer,
            hosted                      = hosted)

    show_model("irdb", "ServerRevocation")
    for row in world.db.irdbd.irdb_serverrevocation:
        show_instance(row.id)
        issuer = rpki.irdb.models.ServerCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.ServerRevocation.objects.create(
            pk                          = row.id,
            serial                      = row.serial,
            revoked                     = row.revoked,
            expires                     = row.expires,
            issuer                      = issuer)

    show_model("irdb", "ResourceHolderRevocation")
    for row in world.db.irdbd.irdb_resourceholderrevocation:
        show_instance(row.id)
        issuer = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.ResourceHolderRevocation.objects.create(
            pk                          = row.id,
            serial                      = row.serial,
            revoked                     = row.revoked,
            expires                     = row.expires,
            issuer                      = issuer)

    show_model("irdb", "ServerEE")
    for row in world.db.irdbd.irdb_serveree:
        show_instance(row.id)
        issuer = rpki.irdb.models.ServerCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.ServerEE.objects.create(
            pk                          = row.id,
            certificate                 = X509(row.certificate),
            private_key                 = RSA(row.private_key),
            purpose                     = row.purpose,
            issuer                      = issuer)

    show_model("irdb", "Referral")
    for row in world.db.irdbd.irdb_referral:
        show_instance(row.id)
        issuer = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.Referral.objects.create(
            pk                          = row.id,
            certificate                 = X509(row.certificate),
            private_key                 = RSA(row.private_key),
            issuer                      = issuer)

    show_model("irdb", "BSC")
    for row in world.db.irdbd.irdb_bsc:
        show_instance(row.id, row.handle)
        issuer = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.BSC.objects.create(
            pk                          = row.id,
            certificate                 = X509(row.certificate),
            handle                      = row.handle,
            pkcs10                      = PKCS10(row.pkcs10),
            issuer                      = issuer)

    show_model("irdb", "Child")
    for row in world.db.irdbd.irdb_child:
        show_instance(row.id, row.handle)
        issuer = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.Child.objects.create(
            pk                          = row.id,
            certificate                 = X509(row.certificate),
            handle                      = row.handle,
            ta                          = X509(row.ta),
            valid_until                 = row.valid_until,
            name                        = row.name,
            issuer                      = issuer)

    show_model("irdb", "ChildASN")
    for row in world.db.irdbd.irdb_childasn:
        show_instance(row.id)
        child = rpki.irdb.models.Child.objects.get(pk = row.child_id)
        rpki.irdb.models.ChildASN.objects.create(
            pk                          = row.id,
            start_as                    = row.start_as,
            end_as                      = row.end_as,
            child                       = child)

    show_model("irdb", "ChildNet")
    for row in world.db.irdbd.irdb_childnet:
        show_instance(row.id)
        child = rpki.irdb.models.Child.objects.get(pk = row.child_id)
        rpki.irdb.models.ChildNet.objects.create(
            pk                          = row.id,
            start_ip                    = row.start_ip,
            end_ip                      = row.end_ip,
            version                     = row.version,
            child                       = child)

    turtle_map = dict((row.id, row) for row in world.db.irdbd.irdb_turtle)

    show_model("irdb", "Parent")
    for row in world.db.irdbd.irdb_parent:
        show_instance(row.turtle_ptr_id, row.handle)
        issuer = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.Parent.objects.create(
            pk                          = row.turtle_ptr_id,
            service_uri                 = fixuri.rpkid(turtle_map[row.turtle_ptr_id].service_uri),
            certificate                 = X509(row.certificate),
            handle                      = row.handle,
            ta                          = X509(row.ta),
            parent_handle               = row.parent_handle,
            child_handle                = row.child_handle,
            repository_type             = row.repository_type,
            referrer                    = row.referrer,
            referral_authorization      = REF(row.referral_authorization),
            issuer                      = issuer)

    show_model("irdb", "ROARequest")
    for row in world.db.irdbd.irdb_roarequest:
        show_instance(row.id)
        issuer = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.ROARequest.objects.create(
            pk                          = row.id,
            asn                         = row.asn,
            issuer                      = issuer)

    show_model("irdb", "ROARequestPrefix")
    for row in world.db.irdbd.irdb_roarequestprefix:
        show_instance(row.id)
        roa_request = rpki.irdb.models.ROARequest.objects.get(pk = row.roa_request_id)
        rpki.irdb.models.ROARequestPrefix.objects.create(
            pk                          = row.id,
            version                     = row.version,
            prefix                      = row.prefix,
            prefixlen                   = row.prefixlen,
            max_prefixlen               = row.max_prefixlen,
            roa_request                 = roa_request)

    show_model("irdb", "Ghostbuster")
    for row in world.db.irdbd.irdb_ghostbusterrequest:
        show_instance(row.id)
        issuer = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.issuer_id)
        try:
            parent = rpki.irdb.models.Parent.objects.get(pk = row.parent_id)
        except rpki.irdb.models.Parent.DoesNotExist:
            parent = None
        rpki.irdb.models.GhostbusterRequest.objects.create(
            pk                          = row.id,
            vcard                       = row.vcard,
            parent                      = parent,
            issuer                      = issuer)

    show_model("irdb", "EECertificateRequest")
    for row in world.db.irdbd.irdb_eecertificaterequest:
        show_instance(row.id)
        issuer = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.EECertificateRequest.objects.create(
            pk                          = row.id,
            valid_until                 = row.valid_until,
            pkcs10                      = PKCS10(row.pkcs10),
            gski                        = row.gski,
            cn                          = row.cn,
            sn                          = row.sn,
            eku                         = row.eku,
            issuer                      = issuer)

    show_model("irdb", "EECertificateRequestASN")
    for row in world.db.irdbd.irdb_eecertificaterequestasn:
        show_instance(row.id)
        ee_certificate_request = rpki.irdb.models.EECertificateRequest.objects.get(
            pk = row.ee_certificate_request_id)
        rpki.irdb.models.EECertificateRequestASN.objects.create(
            pk                          = row.id,
            start_as                    = row.start_as,
            end_as                      = row.end_as,
            ee_certificate_request      = ee_certificate_request)

    show_model("irdb", "EECertificateRequestNet")
    for row in world.db.irdbd.irdb_eecertificaterequestnet:
        show_instance(row.id)
        ee_certificate_request = rpki.irdb.models.EECertificateRequest.objects.get(
            pk = row.ee_certificate_request_id)
        rpki.irdb.models.EECertificateRequestNet.objects.create(
            pk                          = row.id,
            start_ip                    = row.start_ip,
            end_ip                      = row.end_ip,
            version                     = row.version,
            ee_certificate_request      = ee_certificate_request)

    # Turtle without a Parent can happen where the old database had a Rootd.
    # We can create an irdb parent, but only handle_rpkid() (or rpkid itself)
    # can create an rpkidb Parent object, so we need to coordinate with handle_rpkid().

    rrdp_notification_uri = cfg.get(section = "myrpki", option = "publication_rrdp_notification_uri")

    show_model("irdb", "Repository")
    for row in world.db.irdbd.irdb_repository:
        show_instance(row.turtle_id, row.handle)
        issuer = rpki.irdb.models.ResourceHolderCA.objects.get(pk = row.issuer_id)
        try:
            parent = rpki.irdb.models.Parent.objects.get(pk = row.turtle_id)
        except rpki.irdb.models.Parent.DoesNotExist:
            if row.turtle_id in set(r.turtle_ptr_id for r in world.db.irdbd.irdb_rootd):
                print "  Skipping repository for old rootd instance"
                continue
            else:
                raise
        rpki.irdb.models.Repository.objects.create(
            pk                          = row.id,
            certificate                 = X509(row.certificate),
            handle                      = row.handle,
            ta                          = X509(row.ta),
            client_handle               = row.client_handle,
            service_uri                 = fixuri.pubd(row.service_uri),
            sia_base                    = fixuri.rsyncd(row.sia_base),
            rrdp_notification_uri       = rrdp_notification_uri,
            parent                      = parent,
            issuer                      = issuer)

    show_model("irdb", "Client")
    for row in world.db.irdbd.irdb_client:
        show_instance(row.id, row.handle)
        issuer = rpki.irdb.models.ServerCA.objects.get(pk = row.issuer_id)
        rpki.irdb.models.Client.objects.create(
            pk                          = row.id,
            certificate                 = X509(row.certificate),
            handle                      = row.handle,
            ta                          = X509(row.ta),
            sia_base                    = fixuri.rsyncd(row.sia_base),
            issuer                      = issuer)

    reset_sequence("irdb")

    if root.enabled:
        irdb_parent = rpki.irdb.models.Parent.objects.create(**dict(
            root.irdb_work_Parent,
            issuer = rpki.irdb.models.ResourceHolderCA.objects.get(
                pk = root.work_resourceholderca_id)))
        serverca = rpki.irdb.models.ServerCA.objects.get()
        resourceholderca = rpki.irdb.models.ResourceHolderCA.objects.create(**dict(
            root.irdb_root_ResourceHolderCA))
        hostedca = rpki.irdb.models.HostedCA(**dict(
            root.irdb_root_HostedCA,
            issuer = serverca,
            hosted = resourceholderca))
        parent = rpki.irdb.models.Parent.objects.create(**dict(
            root.irdb_root_Parent,
            issuer = resourceholderca))
        bsc = rpki.irdb.models.BSC.objects.create(**dict(
            root.irdb_root_BSC,
            issuer = resourceholderca))
        child = rpki.irdb.models.Child.objects.create(**dict(
            root.irdb_root_Child,
            issuer = resourceholderca))
        childasn = rpki.irdb.models.ChildASN.objects.create(**dict(
            root.irdb_root_ChildASN,
            child = child))
        childnet = rpki.irdb.models.ChildNet.objects.create(**dict(
            root.irdb_root_ChildNet,
            child = child))
        repository = rpki.irdb.models.Repository.objects.create(**dict(
            root.irdb_root_Repository,
            parent = parent,
            issuer = resourceholderca))
        client = rpki.irdb.models.Client.objects.create(**dict(
            root.irdb_root_Client,
            issuer = serverca))


if __name__ == "__main__":
    main()
