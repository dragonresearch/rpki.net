# $Id$

# Copyright (C) 2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

import POW, rpki.x509, os

key = rpki.x509.RSA(Auto_file = "biz-certs/Alice-EE.key").get_POW()
ee = rpki.x509.X509(Auto_file = "biz-certs/Alice-EE.cer").get_POW()

ca = rpki.x509.X509(Auto_file = "biz-certs/Alice-CA.cer").get_POW()
ta = rpki.x509.X509(Auto_file = "biz-certs/Alice-Root.cer").get_POW()

store = POW.X509Store()
store.addTrust(ta)

if store.verify(ca):
  print "Verified CA"
  store.addTrust(ca)
else:
  print "Couldn't verify CA"

if store.verify(ee):
  print "Verified EE"
  store.addTrust(ee)
else:
  print "Couldn't verify EE"

oid = "1.2.840.113549.1.9.16.1.24"

plaintext = "Wombats Are Us"

for args in ((ee, key, [ca], plaintext, oid),
             (ee, key, [ca], plaintext, oid, POW.CMS_NOATTR),
             (ee, key, [ca], plaintext, oid, POW.CMS_NOCERTS),
             (ee, key, [], plaintext, oid),
             (ee, key, [], plaintext, oid, POW.CMS_NOATTR),
             (ee, key, [], plaintext, oid, POW.CMS_NOCERTS)):

  print "Testing", repr(args)

  cms = POW.CMS()
  cms.sign(*args)

  if True:
    f = open("test-pow-cms.der", "w")
    f.write(cms.derWrite())
    f.close()
    if True:
      f = os.popen("dumpasn1 2>&1 -a test-pow-cms.der")
      print "\n".join(x for x in f.read().splitlines() if x.startswith(" "))
      f.close()
    if True:
      os.unlink("test-pow-cms.der")

  if True:
    f = os.popen("../openssl/openssl/apps/openssl cms -print -cmsout -inform DER", "w")
    f.write(cms.derWrite())
    f.close()
    
  cms.verify(store, [ee])
