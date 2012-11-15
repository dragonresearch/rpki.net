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

#ifndef __ROA_H__
#define __ROA_H__

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

#include <rpki/sk_roa.h>

/*
 * ASN.1 templates.  Not sure that ASN1_EXP_OPT() is the right macro
 * for these defaulted "version" fields, but it's what the examples
 * for this construction use.  So far it has not mattered, as code
 * using these definitions have only decoded ROAs, never encoded
 * them.  We'll see if that breaks with encoding.
 *
 * Putting this section under conditional compilation is a hack to
 * keep Doxygen's parser from becoming hopelessly confused by the
 * weird OpenSSL ASN.1 macros.  Someday perhaps I'll have time to
 * track down the problem in Doxygen's parser, but this works for now.
 */

#ifndef DOXYGEN_GETS_HOPELESSLY_CONFUSED_BY_THIS_SECTION

typedef struct ROAIPAddress_st {
  ASN1_BIT_STRING *IPAddress;
  ASN1_INTEGER *maxLength;
} ROAIPAddress;

DECLARE_STACK_OF(ROAIPAddress)

ASN1_SEQUENCE(ROAIPAddress) = {
  ASN1_SIMPLE(ROAIPAddress, IPAddress, ASN1_BIT_STRING),
  ASN1_OPT(ROAIPAddress, maxLength, ASN1_INTEGER)
} ASN1_SEQUENCE_END(ROAIPAddress)

typedef struct ROAIPAddressFamily_st {
  ASN1_OCTET_STRING *addressFamily;
  STACK_OF(ROAIPAddress) *addresses;
} ROAIPAddressFamily;

DECLARE_STACK_OF(ROAIPAddressFamily)

ASN1_SEQUENCE(ROAIPAddressFamily) = {
  ASN1_SIMPLE(ROAIPAddressFamily, addressFamily, ASN1_OCTET_STRING),
  ASN1_SEQUENCE_OF(ROAIPAddressFamily, addresses, ROAIPAddress)
} ASN1_SEQUENCE_END(ROAIPAddressFamily)

typedef struct ROA_st {
  ASN1_INTEGER *version, *asID;
  STACK_OF(ROAIPAddressFamily) *ipAddrBlocks;
} ROA;

ASN1_SEQUENCE(ROA) = {
  ASN1_EXP_OPT(ROA, version, ASN1_INTEGER, 0),
  ASN1_SIMPLE(ROA, asID, ASN1_INTEGER),
  ASN1_SEQUENCE_OF(ROA, ipAddrBlocks, ROAIPAddressFamily)
} ASN1_SEQUENCE_END(ROA)

DECLARE_ASN1_FUNCTIONS(ROAIPAddress)
DECLARE_ASN1_FUNCTIONS(ROAIPAddressFamily)
DECLARE_ASN1_FUNCTIONS(ROA)

IMPLEMENT_ASN1_FUNCTIONS(ROAIPAddress)
IMPLEMENT_ASN1_FUNCTIONS(ROAIPAddressFamily)
IMPLEMENT_ASN1_FUNCTIONS(ROA)

#endif /* DOXYGEN_GETS_HOPELESSLY_CONFUSED_BY_THIS_SECTION */

#endif /* __ROA_H__ */
