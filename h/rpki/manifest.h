/*
 * Copyright (C) 2009--2012  Internet Systems Consortium ("ISC")
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 * Portions copyright (C) 2006--2008  American Registry for Internet Numbers ("ARIN")
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id$ */

#ifndef __MANIFEST_H__
#define __MANIFEST_H__

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/safestack.h>
#include <openssl/conf.h>
#include <openssl/rand.h>
#include <openssl/asn1t.h>
#include <openssl/cms.h>

#include <rpki/sk_manifest.h>

/*
 * ASN.1 templates.  Not sure that ASN1_EXP_OPT() is the right macro
 * for these defaulted "version" fields, but it's what the examples
 * for this construction use.  So far it has not mattered, as code
 * using these definitions have only decoded manifests, never encoded
 * them.  We'll see if that breaks with encoding.
 *
 * Putting this section under conditional compilation is a hack to
 * keep Doxygen's parser from becoming hopelessly confused by the
 * weird OpenSSL ASN.1 macros.  Someday perhaps I'll have time to
 * track down the problem in Doxygen's parser, but this works for now.
 */

#ifndef DOXYGEN_GETS_HOPELESSLY_CONFUSED_BY_THIS_SECTION

typedef struct FileAndHash_st {
  ASN1_IA5STRING *file;
  ASN1_BIT_STRING *hash;
} FileAndHash;

DECLARE_STACK_OF(FileAndHash)

ASN1_SEQUENCE(FileAndHash) = {
  ASN1_SIMPLE(FileAndHash, file, ASN1_IA5STRING),
  ASN1_SIMPLE(FileAndHash, hash, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(FileAndHash)

typedef struct Manifest_st {
  ASN1_INTEGER *version, *manifestNumber;
  ASN1_GENERALIZEDTIME *thisUpdate, *nextUpdate;
  ASN1_OBJECT *fileHashAlg;
  STACK_OF(FileAndHash) *fileList;
} Manifest;

ASN1_SEQUENCE(Manifest) = {
  ASN1_EXP_OPT(Manifest, version, ASN1_INTEGER, 0),
  ASN1_SIMPLE(Manifest, manifestNumber, ASN1_INTEGER),
  ASN1_SIMPLE(Manifest, thisUpdate, ASN1_GENERALIZEDTIME),
  ASN1_SIMPLE(Manifest, nextUpdate, ASN1_GENERALIZEDTIME),
  ASN1_SIMPLE(Manifest, fileHashAlg, ASN1_OBJECT),
  ASN1_SEQUENCE_OF(Manifest, fileList, FileAndHash)
} ASN1_SEQUENCE_END(Manifest)

DECLARE_ASN1_FUNCTIONS(FileAndHash)
DECLARE_ASN1_FUNCTIONS(Manifest)

IMPLEMENT_ASN1_FUNCTIONS(FileAndHash)
IMPLEMENT_ASN1_FUNCTIONS(Manifest)

#endif /* DOXYGEN_GETS_HOPELESSLY_CONFUSED_BY_THIS_SECTION */

#endif /* __MANIFEST_H__ */
