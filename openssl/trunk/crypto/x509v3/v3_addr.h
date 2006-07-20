/*
 * Copyright (C) 2006  American Registry for Internet Numbers ("ARIN")
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

/*
 * This will end up merged into some OpenSSL header file or another
 * (probably crypto/x509v3/x509v3.h) but for the moment I want it
 * under revision control.
 */

#ifndef HEADER_V3_ADDR_H
#define HEADER_V3_ADDR_H

#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

typedef struct IPAddressRange_st {
  ASN1_BIT_STRING	*min, *max;
} IPAddressRange;

#define	IPAddressOrRange_addressPrefix	0
#define	IPAddressOrRange_addressRange	1

typedef struct IPAddressOrRange_st {
  int type;
  union {
    ASN1_BIT_STRING	*addressPrefix;
    IPAddressRange	*addressRange;
  } u;
} IPAddressOrRange;

typedef STACK_OF(IPAddressOrRange) IPAddressOrRanges;
DECLARE_STACK_OF(IPAddressOrRange)

#define	IPAddressChoice_inherit			0
#define	IPAddressChoice_addressesOrRanges	1

typedef struct IPAddressChoice_st {
  int type;
  union {
    ASN1_NULL		*inherit;
    IPAddressOrRanges	*asIdsOrRanges;
  } u;
} IPAddressChoice;

typedef struct IPAddressFamily_st {
  ASN1_OCTET_STRING	*addressFamily;
  IPAddressChoice	*ipAddressChoice;
} IPAddressFamily;

typedef STACK_OF(IPAddressFamily) IPAddrBlocks;
DECLARE_STACK_OF(IPAddressFamily)

DECLARE_ASN1_FUNCTIONS(IPAddressRange)
DECLARE_ASN1_FUNCTIONS(IPAddressOrRange)
DECLARE_ASN1_FUNCTIONS(IPAddressChoice)
DECLARE_ASN1_FUNCTIONS(IPAddressFamily)

#endif /* HEADER_V3_ADDR_H */
