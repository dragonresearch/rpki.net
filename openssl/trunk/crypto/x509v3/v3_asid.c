/* v3_asid.c */

/* $Id$ */
/*
 * Initial attempt to implement RFC 3779 section 3.  I'd be very
 * surprised if this even compiled yet, as I'm still figuring out
 * OpenSSL's ASN.1 template goop.
 */

#include <stdio.h>
#include "cryptlib.h"
#include <openssl/conf.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509v3.h>

/* RFC 3779 AS ID */

ASN1_SEQUENCE(ASRange) = {
	ASN1_SIMPLE(ASRange, min, ASN1_INTEGER),
	ASN1_SIMPLE(ASRange, max, ASN1_INTEGER)
} ASN1_SEQUENCE_END(ASRange)

ASN1_CHOICE(ASIdOrRange) = {
	ASN1_SIMPLE(ASIdOrRange, u.id, ASN1_INTEGER),
	ASN1_SIMPLE(ASIdOrRange, u.range, ASRange)
} ASN1_CHOICE_END(ASIdOrRange)

ASN1_CHOICE(ASIdentiferChoice) = {
	ASN1_IMP(ASIdentiferChoice, u.inherit, ASN1_NULL),
	ASN1_IMP_SEQUENCE_OF(ASIdentiferChoice, u.asIdsOrRanges, ASIdOrRange)
} ASN1_CHOICE_END(ASIdentiferChoice)

ASN1_SEQUENCE(ASIdentifiers) = {
	ASN1_EXP_OPT(ASIdentifiers, asnum, ASIdentiferChoice, 0),
	ASN1_EXP_OPT(ASIdentifiers, rdi, ASIdentiferChoice, 1)
} ASN1_SEQUENCE_END(ASIdentifiers)

IMPLEMENT_ASN1_FUNCTIONS(ASRange)
IMPLEMENT_ASN1_FUNCTIONS(ASIdOrRange)
IMPLEMENT_ASN1_FUNCTIONS(ASIdentiferChoice)
IMPLEMENT_ASN1_FUNCTIONS(ASIdentifiers)

static int i2r_ASIdentifierChoice(BIO *out, ASIdentiferChoice *choice, int indent, const char *msg)
{
  int i;
  char *s;
  if (choice == NULL)
    return 1;
  BIO_printf(out, "%*s%s: ", indent, "", msg);
  switch (choice->type) {
  case ASIdentifierChoice_inherit:
    BIO_puts(out, "inherit");
    break;
  case ASIdentifierChoice_asIdsOrRanges:
    for (i = 0; i < sk_ASIdOrRange_num(choice->u.asIdsOrRanges); i++) {
      ASIdOrRange aor = sk_ASIdOrRange_num(choice->u.asIdsOrRanges, i);
      if (i > 0)
	BIO_puts(out, ", ");
      switch (aor->type) {
      case ASIdOrRange_id:
	if ((s = i2s_ASN1_INTEGER(NULL, aor->u.id)) == NULL)
	  return 0;
	BIO_puts(out, s);
	OPENSSL_free(s);
	break;
      case ASIdOrRange_range:
	if ((s = i2s_ASN1_INTEGER(NULL, aor->u.range->min)) == NULL)
	  return 0;
	BIO_puts(out, s);
	OPENSSL_free(s);
	BIO_puts(out, " - ");
	if ((s = i2s_ASN1_INTEGER(NULL, aor->u.range->max)) == NULL)
	  return 0;
	BIO_puts(out, s);
	OPENSSL_free(s);
	break;
      default:
	return 0;
      }
    }
    break;
  default:
    return 0;
  }
  BIO_puts(out, "\n");
  return 1;
}

static int i2r_ASIdentifiers(X509V3_EXT_METHOD *method, ASIdentifiers *asid, BIO *out, int indent)
{
  return (i2r_ASIdentifierChoice(out, asid->asnum, indent, "Autonomous System Numbers") &&
	  i2r_ASIdentifierChoice(out, asid->rdi,   indent, "Routing Domain Identifiers"));
}

static ASIdentifiers *r2i_ASIdentifiers(X509V3_EXT_METHOD *method, X509V3_CTX *ctx, char *value);

X509V3_EXT_METHOD v3_asid = {
	NID_ASIdentifiers,				/* nid */
	0,						/* flags */
	ASN1_ITEM_ref(ASIdentifiers),			/* template */
	NULL, NULL, NULL, NULL,				/* Old ASN.1 functions, ignored */
	NULL,						/* i2s */
	NULL,						/* s2i */
	NULL,						/* i2v */
	NULL,						/* v2i */
	(X509V3_EXT_I2R) i2r_ASIdentifiers,		/* i2r */
	(X509V3_EXT_R2I) r2i_ASIdentifiers,		/* r2i */
	NULL						/* extension-specific data */
};
