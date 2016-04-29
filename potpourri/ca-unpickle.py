#!/usr/bin/env python

# $Id$

"""
Unpickle trunk/ CA state packaged by ca-pickle and attempt to whack a
tk705/ rpki-ca instance into an equivalent state.
"""

import os
import sys
import time
import cPickle
import datetime
import argparse
import subprocess

import rpki.config
import rpki.x509


class LazyDict(object):
    """
    Convenience wrapper to allow attribute notation for brevity
    when diving into deeply nested mappings created by ca-pickle.
    """

    def __init__(self, *args, **kwargs):
        self._d = dict(*args, **kwargs)

    def __getitem__(self, name):
        if name in self._d:
            return self._d[name]
        raise AttributeError

    __getattr__ = __getitem__

    def __missing__(self, name):
        raise AttributeError

    def __iter__(self):
        return self._d.iterkeys()

    iterkeys = __iter__

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


os.environ.update(TZ = "UTC")
time.tzset()

cfg = rpki.config.argparser(doc = __doc__)
cfg.argparser.add_argument("input_file", help = "input file")
cfg.add_logging_arguments()
args = cfg.argparser.parse_args()
cfg.configure_logging(args = args)

xzcat = subprocess.Popen(("xzcat", args.input_file), stdout = subprocess.PIPE)
world = LazyDict.insinuate(cPickle.load(xzcat.stdout))
if xzcat.wait() != 0:
    sys.exit("XZ unpickling failed with code {}".format(xzcat.returncode))

# Trivial test, but if this works, the LazyDict stuff is probably working
#print "Engine handle is", world.cooked_config.myrpki.handle

def maybe_X509(obj):   return None if obj is None else rpki.x509.X509(  DER = obj)
def maybe_CRL(obj):    return None if obj is None else rpki.x509.CRL(   DER = obj)
def maybe_RSA(obj):    return None if obj is None else rpki.x509.RSA(   DER = obj)
def maybe_PKCS10(obj): return None if obj is None else rpki.x509.PKCS10(DER = obj)

# Because of the way Django ORM uses DJANGO_SETTINGS_MODULE, we'll
# probably need to fork() to handle the several databases.  Shouldn't
# be particularly difficult, write three driver functions and a
# service function that fork()s then calls a driver, or something like
# that.
#
# Prototype with rpkid for now, fork later.

os.environ.update(DJANGO_SETTINGS_MODULE = "rpki.django_settings.rpkid")
import django
django.setup()
import rpki.rpkidb

print "rpkid self"
for row in world.databases.rpkid.self:
    print " ", row.self_handle
    rpki.rpkidb.models.Tenant.objects.create(
        pk                      = row.self_id,
        tenant_handle           = row.self_handle,
        use_hsm                 = row.use_hsm,
        crl_interval            = row.crl_interval,
        regen_margin            = row.regen_margin,
        bpki_cert               = maybe_X509(row.bpki_cert),
        bpki_glue               = maybe_X509(row.bpki_glue))

print "rpkid bsc"
for row in world.databases.rpkid.bsc:
    print " ", row.bsc_handle
    tenant = rpki.rpkidb.models.Tenant.objects.get(pk = row.self_id)
    rpki.rpkidb.models.BSC.objects.create(
        pk                      = row.bsc_id,
        bsc_handle              = row.bsc_handle,
        private_key_id          = maybe_RSA(row.private_key_id),
        pkcs10_request          = maybe_PKCS10(row.pkcs10_request),
        hash_alg                = row.hash_alg or "sha256",
        signing_cert            = maybe_X509(row.signing_cert),
        signing_cert_crl        = maybe_CRL(row.signing_cert_crl),
        tenant                  = tenant)

print "rpkid repository"
for row in world.databases.rpkid.repository:
    print " ", row.repository_handle
    tenant = rpki.rpkidb.models.Tenant.objects.get(pk = row.self_id                )
    bsc    = rpki.rpkidb.models.BSC.objects.get   (pk = row.bsc_id, tenant = tenant)
    rpki.rpkidb.models.Repository.objects.create(
        pk                      = row.repository_id,
        repository_handle       = row.repository_handle,
        peer_contact_uri        = row.peer_contact_uri,
        bpki_cert               = maybe_X509(row.bpki_cert),
        bpki_glue               = maybe_X509(row.bpki_glue),
        last_cms_timestamp      = row.last_cms_timestamp,
        bsc                     = bsc,
        tenant                  = tenant)

print "rpkid parent"
for row in world.databases.rpkid.parent:
    print " ", row.parent_handle
    tenant     = rpki.rpkidb.models.Tenant.objects.get    (pk = row.self_id                       )
    bsc        = rpki.rpkidb.models.BSC.objects.get       (pk = row.bsc_id,        tenant = tenant)
    repository = rpki.rpkidb.models.Repository.objects.get(pk = row.repository_id, tenant = tenant)
    rpki.rpkidb.models.Parent.objects.create(
        pk                      = row.parent_id,
        parent_handle           = row.parent_handle,
        bpki_cert               = maybe_X509(row.bpki_cms_cert),
        bpki_glue               = maybe_X509(row.bpki_cms_glue),
        peer_contact_uri        = row.peer_contact_uri,
        sia_base                = row.sia_base,
        sender_name             = row.sender_name,
        recipient_name          = row.recipient_name,
        last_cms_timestamp      = row.last_cms_timestamp,
        bsc                     = bsc,
        repository              = repository,
        tenant                  = tenant)
