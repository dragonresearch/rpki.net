"""
Scratch pad for working out what CMS referral code looks like.

This is only in subversion for archival and backup, I don't expect
users to run this, and will delete it in the near future.


$Id$

Copyright (C) 2010  Internet Systems Consortium ("ISC")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import subprocess, os, sys, myrpki

original_xml = '''\
<publication_referral xmlns="http://www.hactrn.net/uris/rpki/publication-spec/"
                      sia_base=rsync://repository.example/path/to/me/space-i-give-to-my-child">
  Base64 encoded BPKI TA of resource holding aspect of my child xxx blah blah blah blah xxx
</publication_referral>
'''

f = open("original.xml", "w")
f.write(original_xml)
f.close()

myrpki.openssl = "/u/sra/rpki/subvert-rpki.hactrn.net/openssl/openssl/apps/openssl"
os.putenv("OPENSSL_CONF", "/dev/null")

bpki = myrpki.CA("test/Alice/myrpki.conf", "test/Alice/bpki/resources")
bpki.ee("/CN=Alice Signed Referral CMS Test EE Certificate", "CMSEE")

# "id-ct-xml" from rpki.oids
oid = ".".join(map(str, (1, 2, 840, 113549, 1, 9, 16, 1, 28)))

format = "DER"                          # PEM or DER

subprocess.check_call((myrpki.openssl, "cms", "-sign",
                       "-binary", "-nodetach", "-nosmimecap", "-keyid", "-outform", format,
                       "-econtent_type", oid, "-md", "sha256",
                       "-inkey",  "test/Alice/bpki/resources/CMSEE.key",
                       "-signer", "test/Alice/bpki/resources/CMSEE.cer",
                       "-in",  "original.xml",
                       "-out", "original.%s" % format.lower()))

if format == "DER":
  subprocess.call(("dumpasn1", "-a", "original.cms"))

# verifying may not be necessary here, that might be pubd's job.  or
# at least we can make it the job of the code formerly known as irdbd,
# where we have full libraries available to us.  but blunder ahead...

subprocess.check_call((myrpki.openssl, "cms", "-verify", "-inform", format,
                       "-CAfile", "test/Alice/bpki/resources/ca.cer",
                       "-in",     "original.%s" % format.lower()))
