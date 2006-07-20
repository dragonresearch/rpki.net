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

#ifndef HEADER_V3_ASID_H
#define HEADER_V3_ASID_H

#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

typedef struct ASRange_st {
  ASN1_INTEGER *min, *max;
} ASRange;

#define	ASIdOrRange_id		0
#define	ASIdOrRange_range	1

typedef struct ASIdOrRange_st {
  int type;
  union {
    ASN1_INTEGER *id;
    ASRange      *range;
  } u;
} ASIdOrRange;

typedef STACK_OF(ASIdOrRange) ASIdOrRanges;
DECLARE_STACK_OF(ASIdOrRange)

#define	ASIdentifierChoice_inherit		0
#define	ASIdentifierChoice_asIdsOrRanges	1

typedef struct ASIdentifierChoice_st {
  int type;
  union {
    ASN1_NULL    *inherit;
    ASIdOrRanges *asIdsOrRanges;
  } u;
} ASIdentifierChoice;

typedef struct ASIdentifiers_st {
  ASIdentifierChoice *asnum, *rdi;
} ASIdentifiers;

DECLARE_ASN1_FUNCTIONS(ASRange)
DECLARE_ASN1_FUNCTIONS(ASIdOrRange)
DECLARE_ASN1_FUNCTIONS(ASIdentiferChoice)
DECLARE_ASN1_FUNCTIONS(ASIdentifiers)

#endif /* HEADER_V3_ASID_H */
