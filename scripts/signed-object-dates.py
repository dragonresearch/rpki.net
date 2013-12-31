#!/usr/bin/env python
# $Id$

# Extract notBefore, and notAfter values from an RPKI signed object;
# if the object is a manifest, also extract thisUpdate and nextUpdate.

# Copyright (C) 2013 Dragon Research Labs ("DRL")
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
import rpki.POW

extract_flags = (rpki.POW.CMS_NOCRL |
                 rpki.POW.CMS_NO_SIGNER_CERT_VERIFY |
                 rpki.POW.CMS_NO_ATTR_VERIFY |
                 rpki.POW.CMS_NO_CONTENT_VERIFY)

for fn in sys.argv[1:]:
  cls = rpki.POW.Manifest if fn.endswith(".mft") else rpki.POW.CMS
  cms = cls.derReadFile(fn)
  cer = cms.certs()[0]
  print fn
  print " notBefore: ", cer.getNotBefore()
  if fn.endswith(".mft"):
    cms.verify(rpki.POW.X509Store(), None, extract_flags)
    print " thisUpdate:", cms.getThisUpdate()
    print " nextUpdate:", cms.getNextUpdate()
  print " notAfter:  ", cer.getNotAfter()
  print
