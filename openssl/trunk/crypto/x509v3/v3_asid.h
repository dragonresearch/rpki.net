/* $Id$ */
/*
 * This will end up merged into some OpenSSL header file or another
 * (probably crypto/x509v3/x509v3.h) but for the moment I want it
 * under revision control.
 */

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
    ASRange *range;
  } u;
} ASIdOrRange;

typedef STACK_OF(ASIdOrRange) ASIdOrRanges;
DECLARE_STACK_OF(ASIdOrRange)

#define	ASIdentifierChoice_inherit		0
#define	ASIdentifierChoice_asIdsOrRanges	1

typedef struct ASIdentifierChoice_st {
  int type;
  union {
    ASN1_NULL *inherit;
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
