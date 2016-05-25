#!/usr/bin/env python

# $Id$

# Copyright (C) 2016  Parsons Government Services ("PARSONS")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND PARSONS DISCLAIMS ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL
# PARSONS BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
# OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
Replace key in an rpkid root Parent object with a different key,
presumably salvaged from an old rootd configuration.

This does horrible things to the internal state of your rpkid
installation.  Do not use it unless you understand exactly what
it does and know why running it is necessary.

YOU HAVE BEEN WARNED.

Not to be used without a doctor's prescription and a paid-up life
insurance policy.
"""

import os
import sys
import time
import argparse
import urlparse

import rpki.config
import rpki.x509
import rpki.resource_set

os.environ.update(TZ = "UTC")
time.tzset()

cfg = rpki.config.argparser(doc = __doc__)
cfg.argparser.add_argument("--simon-says-whack-my-rpki-root", 
                           action = "store_true")
cfg.argparser.add_argument("-k", "--root-key", 
                           type = lambda s: rpki.x509.RSA(Auto_file = s),
                           help = "root key to install")
cfg.argparser.add_argument("-b", "--backup",
                           help = "back up currently installed root key before whacking")
args = cfg.argparser.parse_args()

if not args.simon_says_whack_my_rpki_root:
    sys.exit("You didn't say \"Simon says\"")

print "Loading rpkidb environment"
os.environ.update(DJANGO_SETTINGS_MODULE = "rpki.django_settings.rpkid")
import django
django.setup()
import rpki.rpkidb
from django.db.models import Q

# We expect to find exactly one root CADetail object.

print "Looking for rpkidb root CADetail"
ca_detail = rpki.rpkidb.models.CADetail.objects.get(
    ~Q(ca__parent__root_asn_resources  = "")|
    ~Q(ca__parent__root_ipv4_resources = "")|
    ~Q(ca__parent__root_ipv6_resources = ""))

if args.backup:
    print "Backing up installed root key to", args.backup
    with os.fdopen(os.open(args.backup, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0700), "w") as f:
        f.write(ca_detail.private_key_id.get_PEM())

print "Extracting data from old CADetail"
old_cer = ca_detail.latest_ca_cert
old_crl = ca_detail.latest_crl
old_mft = ca_detail.latest_manifest
old_uri = ca_detail.ca_cert_uri

old_mft.get_POW().extractWithoutVerifying()

mft_uri = old_cer.get_sia_manifest_uri()
crl_uri = os.path.splitext(mft_uri)[0] + ".crl"
mft_cer = rpki.x509.X509(POW = old_mft.get_POW().certs()[0])

gski = args.root_key.gSKI()

def fix_uri(uri):
    return "{head}/{gski}{fn2}".format(
        head = os.path.dirname(uri),
        gski = gski,
        fn2  = os.path.splitext(uri)[1])

new_uri = fix_uri(old_uri)

print "Generating new root certificate"
new_cer = rpki.x509.X509.self_certify(
    keypair             = args.root_key,
    subject_key         = args.root_key.get_public(),
    serial              = old_cer.getSerial(),
    sia                 = (fix_uri(old_cer.get_sia_directory_uri()),
                           fix_uri(mft_uri), None, old_cer.get_sia_rrdp_notify()),
    notBefore           = old_cer.getNotBefore(),
    notAfter            = old_cer.getNotAfter(),
    resources           = old_cer.get_3779resources())

print "Generating new root CRL"
new_crl = rpki.x509.CRL.generate(
    keypair             = args.root_key,
    issuer              = new_cer,
    serial              = old_crl.getCRLNumber(),
    thisUpdate          = old_crl.getThisUpdate(),
    nextUpdate          = old_crl.getNextUpdate(),
    revokedCertificates = ())

print "Generating new root manifest EE certificate"
mft_cer = new_cer.issue(
    keypair             = args.root_key,
    subject_key         = ca_detail.manifest_public_key,
    serial              = mft_cer.getSerial(),
    sia                 = (None, None, 
                           fix_uri(mft_cer.get_sia_object_uri()),
                           mft_cer.get_sia_rrdp_notify()),
    resources           = rpki.resource_set.resource_bag.from_inheritance(),
    aia                 = new_uri,
    crldp               = fix_uri(crl_uri),
    notBefore           = mft_cer.getNotBefore(),
    notAfter            = mft_cer.getNotAfter(),
    is_ca               = False)

print "Generating new root manifest"
new_mft = rpki.x509.SignedManifest.build(
    keypair             = ca_detail.manifest_private_key_id,
    certs               = mft_cer,
    serial              = old_mft.get_POW().getManifestNumber(),
    thisUpdate          = old_mft.getThisUpdate(),
    nextUpdate          = old_mft.getNextUpdate(),
    names_and_objs      = [(gski + ".crl", new_crl)])

print "Updating CADetail"
ca_detail.public_key            = args.root_key.get_public()
ca_detail.private_key_id        = args.root_key
ca_detail.crl_published         = None
ca_detail.manifest_published    = None
ca_detail.ca_cert_uri           = new_uri
ca_detail.latest_ca_cert        = new_cer
ca_detail.latest_crl            = new_crl
ca_detail.latest_manifest       = new_mft

print "Saving updated CADetail"
ca_detail.save()
