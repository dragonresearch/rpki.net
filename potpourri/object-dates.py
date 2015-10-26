#!/usr/bin/env python
# $Id$

# Extract notBefore, notAfter, thisUpdate and nextUpdate dates from
# RPKI objects.

# Copyright (C) 2013--2014 Dragon Research Labs ("DRL")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL DRL BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

import sys
import os.path
import rpki.POW

extract_flags = (rpki.POW.CMS_NOCRL |
                 rpki.POW.CMS_NO_SIGNER_CERT_VERIFY |
                 rpki.POW.CMS_NO_ATTR_VERIFY |
                 rpki.POW.CMS_NO_CONTENT_VERIFY)

def get_mft(fn):
    cms = rpki.POW.Manifest.derReadFile(fn)
    cms.verify(rpki.POW.X509Store(), None, extract_flags)
    return cms, cms.certs()[0]

def get_roa(fn):
    return None, rpki.POW.CMS.derReadFile(fn).certs()[0]

def get_gbr(fn):
    return None, rpki.POW.CMS.derReadFile(fn).certs()[0]

def get_crl(fn):
    return rpki.POW.CRL.derReadFile(fn), None

def get_cer(fn):
    return None, rpki.POW.X509.derReadFile(fn)

dispatch = dict(mft = get_mft,
                roa = get_roa,
                gbr = get_gbr,
                crl = get_crl,
                cer = get_cer)

for fn in sys.argv[1:]:
    obj, cer = dispatch[os.path.splitext(fn)[1][1:]](fn)
    print fn
    if cer is not None:
        print "notBefore: ", cer.getNotBefore()
    if obj is not None:
        print "thisUpdate:", obj.getThisUpdate()
        print "nextUpdate:", obj.getNextUpdate()
    if cer is not None:
        print "notAfter:  ", cer.getNotAfter()
    print
