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
 * Initial attempt to implement RFC 3779 section 3.  I'd be very
 * surprised if this even compiled yet, as I'm still figuring out
 * OpenSSL's ASN.1 template goop.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "cryptlib.h"
#include <openssl/conf.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>

ASN1_SEQUENCE(ASRange) = {
  ASN1_SIMPLE(ASRange, min, ASN1_INTEGER),
  ASN1_SIMPLE(ASRange, max, ASN1_INTEGER)
} ASN1_SEQUENCE_END(ASRange)

ASN1_CHOICE(ASIdOrRange) = {
  ASN1_SIMPLE(ASIdOrRange, u.id,    ASN1_INTEGER),
  ASN1_SIMPLE(ASIdOrRange, u.range, ASRange)
} ASN1_CHOICE_END(ASIdOrRange)

ASN1_CHOICE(ASIdentifierChoice) = {
  ASN1_SIMPLE(ASIdentifierChoice,      u.inherit,       ASN1_NULL),
  ASN1_SEQUENCE_OF(ASIdentifierChoice, u.asIdsOrRanges, ASIdOrRange)
} ASN1_CHOICE_END(ASIdentifierChoice)

ASN1_SEQUENCE(ASIdentifiers) = {
  ASN1_EXP_OPT(ASIdentifiers, asnum, ASIdentifierChoice, 0),
  ASN1_EXP_OPT(ASIdentifiers, rdi,   ASIdentifierChoice, 1)
} ASN1_SEQUENCE_END(ASIdentifiers)

IMPLEMENT_ASN1_FUNCTIONS(ASRange)
IMPLEMENT_ASN1_FUNCTIONS(ASIdOrRange)
IMPLEMENT_ASN1_FUNCTIONS(ASIdentifierChoice)
IMPLEMENT_ASN1_FUNCTIONS(ASIdentifiers)

/*
 * i2r method for an ASIdentifierChoice.
 */
static int i2r_ASIdentifierChoice(BIO *out,
				  ASIdentifierChoice *choice,
				  int indent,
				  const char *msg)
{
  int i;
  char *s;
  if (choice == NULL)
    return 1;
  BIO_printf(out, "%*s%s:\n", indent, "", msg);
  switch (choice->type) {
  case ASIdentifierChoice_inherit:
    BIO_printf(out, "%*sinherit\n", indent + 2, "");
    break;
  case ASIdentifierChoice_asIdsOrRanges:
    for (i = 0; i < sk_ASIdOrRange_num(choice->u.asIdsOrRanges); i++) {
      ASIdOrRange *aor = sk_ASIdOrRange_value(choice->u.asIdsOrRanges, i);
      switch (aor->type) {
      case ASIdOrRange_id:
	if ((s = i2s_ASN1_INTEGER(NULL, aor->u.id)) == NULL)
	  return 0;
	BIO_printf(out, "%*s%s\n", indent + 2, "", s);
	OPENSSL_free(s);
	break;
      case ASIdOrRange_range:
	if ((s = i2s_ASN1_INTEGER(NULL, aor->u.range->min)) == NULL)
	  return 0;
	BIO_printf(out, "%*s%s-", indent + 2, "", s);
	OPENSSL_free(s);
	if ((s = i2s_ASN1_INTEGER(NULL, aor->u.range->max)) == NULL)
	  return 0;
	BIO_printf(out, "%s\n", s);
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
  return 1;
}

/*
 * i2r method for an ASIdentifier extension.
 */
static int i2r_ASIdentifiers(X509V3_EXT_METHOD *method,
			     void *ext,
			     BIO *out,
			     int indent)
{
  ASIdentifiers *asid = ext;
  return (i2r_ASIdentifierChoice(out, asid->asnum, indent,
				 "Autonomous System Numbers") &&
	  i2r_ASIdentifierChoice(out, asid->rdi, indent,
				 "Routing Domain Identifiers"));
}

/*
 * Comparision function for "stack" sorting.
 */
static int ASIdOrRange_cmp(const ASIdOrRange * const *a_,
			   const ASIdOrRange * const *b_)
{
  const ASIdOrRange *a = *a_, *b = *b_;

  assert((a->type == ASIdOrRange_id && a->u.id != NULL) ||
	 (a->type == ASIdOrRange_range && a->u.range != NULL &&
	  a->u.range->min != NULL && a->u.range->max != NULL));

  assert((b->type == ASIdOrRange_id && b->u.id != NULL) ||
	 (b->type == ASIdOrRange_range && b->u.range != NULL &&
	  b->u.range->min != NULL && b->u.range->max != NULL));

  if (a->type == ASIdOrRange_id && b->type == ASIdOrRange_id)
    return ASN1_INTEGER_cmp(a->u.id, b->u.id);

  if (a->type == ASIdOrRange_range && b->type == ASIdOrRange_range) {
    int r = ASN1_INTEGER_cmp(a->u.range->min, b->u.range->min);
    return r != 0 ? r : ASN1_INTEGER_cmp(a->u.range->max, b->u.range->max);
  }

  if (a->type == ASIdOrRange_id)
    return ASN1_INTEGER_cmp(a->u.id, b->u.range->min);
  else
    return ASN1_INTEGER_cmp(a->u.range->min, b->u.id);
}

/*
 * Some of the following helper routines might want to become globals
 * eventually.
 */

/*
 * Add an inherit element to an ASIdentifierChoice.
 */
static int asid_add_inherit(ASIdentifierChoice **choice)
{
  if (*choice == NULL) {
    if ((*choice = ASIdentifierChoice_new()) == NULL)
      return 0;
    if (((*choice)->u.inherit = ASN1_NULL_new()) == NULL)
      return 0;
    (*choice)->type = ASIdentifierChoice_inherit;
  }
  return (*choice)->type == ASIdentifierChoice_inherit;
}

/*
 * Add an ID or range to an ASIdentifierChoice.
 */
static int asid_add_id_or_range(ASIdentifierChoice **choice,
				ASN1_INTEGER *min,
				ASN1_INTEGER *max)
{
  ASIdOrRange *aor;
  if (*choice != NULL && (*choice)->type == ASIdentifierChoice_inherit)
    return 0;
  if (*choice == NULL) {
    if ((*choice = ASIdentifierChoice_new()) == NULL)
      return 0;
    (*choice)->u.asIdsOrRanges = sk_ASIdOrRange_new(ASIdOrRange_cmp);
    if ((*choice)->u.asIdsOrRanges == NULL)
      return 0;
    (*choice)->type = ASIdentifierChoice_asIdsOrRanges;
  }
  if ((aor = ASIdOrRange_new()) == NULL)
    return 0;
  if (max == NULL) {
    aor->type = ASIdOrRange_id;
    aor->u.id = min;
  } else {
    aor->type = ASIdOrRange_range;
    if ((aor->u.range = ASRange_new()) == NULL)
      goto err;
    assert(aor->u.range->min == NULL);
    aor->u.range->min = min;
    assert(aor->u.range->max == NULL);
    aor->u.range->max = max;
  }
  if (!(sk_ASIdOrRange_push((*choice)->u.asIdsOrRanges, aor)))
    goto err;
  return 1;

 err:
  ASIdOrRange_free(aor);
  return 0;
}

/*
 * Whack an ASIdentifierChoice into canonical form.
 */
static int asid_canonize(ASIdentifierChoice *choice)
{
  ASN1_INTEGER *a_max_plus_one = NULL;
  BIGNUM *bn = NULL;
  int i, ret = 0;

  /*
   * Nothing to do for empty element or inheritance.
   */
  if (choice == NULL || choice->type == ASIdentifierChoice_inherit)
    return 1;

  /*
   * We have a list.  Sort it.
   */
  assert(choice->type == ASIdentifierChoice_asIdsOrRanges);
  sk_ASIdOrRange_sort(choice->u.asIdsOrRanges);

  /*
   * Now resolve any duplicates or overlaps.
   */
  for (i = 0; i < sk_ASIdOrRange_num(choice->u.asIdsOrRanges) - 1; i++) {
    ASIdOrRange *a = sk_ASIdOrRange_value(choice->u.asIdsOrRanges, i);
    ASIdOrRange *b = sk_ASIdOrRange_value(choice->u.asIdsOrRanges, i + 1);
    ASN1_INTEGER *a_min, *a_max, *b_min, *b_max;

    switch (a->type) {
    case ASIdOrRange_id:
      a_min = a_max = a->u.id;
      break;
    case ASIdOrRange_range:
      a_min = a->u.range->min;
      a_max = a->u.range->max;
      break;
    }

    switch (b->type) {
    case ASIdOrRange_id:
      b_min = b_max = b->u.id;
      break;
    case ASIdOrRange_range:
      b_min = b->u.range->min;
      b_max = b->u.range->max;
      break;
    }

    /*
     * Make sure we're properly sorted (paranoia).
     */
    assert(ASN1_INTEGER_cmp(a_min, b_min) <= 0);

    /*
     * If a contains b, remove b.
     */
    if (ASN1_INTEGER_cmp(a_max, b_max) >= 0) {
      	sk_ASIdOrRange_delete(choice->u.asIdsOrRanges, i + 1);
	ASIdOrRange_free(b);
	--i;
	continue;
    }

    /*
     * If b contains a, remove a.
     */
    if (ASN1_INTEGER_cmp(a_min, b_min) == 0 &&
	ASN1_INTEGER_cmp(a_max, b_max) <= 0) {
      	sk_ASIdOrRange_delete(choice->u.asIdsOrRanges, i);
	ASIdOrRange_free(a);
	--i;
	continue;
    }

    /*
     * Calculate a_max + 1 to check for adjacency.
     */
    if ((bn == NULL && (bn = BN_new()) == NULL) ||
	ASN1_INTEGER_to_BN(a_max, bn) == NULL ||
	!BN_add_word(bn, 1) ||
	(a_max_plus_one = BN_to_ASN1_INTEGER(bn, a_max_plus_one)) == NULL)
      goto err;
    
    /*
     * If a and b are adjacent or overlap, merge them.
     */
    if (ASN1_INTEGER_cmp(a_max_plus_one, b_min) >= 0) {
      ASIdOrRange *aor = ASIdOrRange_new();
      if (aor == NULL)
	goto err;
      aor->type = ASIdOrRange_range;
      if ((aor->u.range = ASRange_new()) == NULL) {
	ASIdOrRange_free(aor);
	goto err;
      }
      aor->u.range->min = a_min;
      aor->u.range->max = b_max;
      sk_ASIdOrRange_set(choice->u.asIdsOrRanges, i, aor);
      sk_ASIdOrRange_delete(choice->u.asIdsOrRanges, i + 1);
      switch (a->type) {
      case ASIdOrRange_id:
	a->u.id = NULL;
	break;
      case ASIdOrRange_range:
	a->u.range->min = NULL;
	break;
      }
      ASIdOrRange_free(a);
      switch (b->type) {
      case ASIdOrRange_id:
	b->u.id = NULL;
	break;
      case ASIdOrRange_range:
	b->u.range->max = NULL;
	break;
      }
      ASIdOrRange_free(b);
      i--;
      continue;
    }
  }

  ret = 1;

 err:
  ASN1_INTEGER_free(a_max_plus_one);
  BN_free(bn);
  return ret;
}

/*
 * v2i method for an ASIdentifier extension.
 */
static void *v2i_ASIdentifiers(struct v3_ext_method *method,
			       struct v3_ext_ctx *ctx,
			       STACK_OF(CONF_VALUE) *values)
{
  ASIdentifiers *asid = NULL;
  ASIdentifierChoice **choice;
  ASN1_INTEGER *min, *max;
  CONF_VALUE *val;
  char *s;
  int i;

  if ((asid = ASIdentifiers_new()) == NULL) {
    X509V3err(X509V3_F_V2I_ASIDENTIFIERS, ERR_R_MALLOC_FAILURE);
    return NULL;
  }

  for (i = 0; i < sk_CONF_VALUE_num(values); i++) {
    val = sk_CONF_VALUE_value(values, i);

    /*
     * Figure out whether this is an AS or an RDI.
     */
    if (       !name_cmp(val->name, "AS")) {
      choice = &asid->asnum;
    } else if (!name_cmp(val->name, "RDI")) {
      choice = &asid->rdi;
    } else {
      X509V3err(X509V3_F_V2I_ASIDENTIFIERS, X509V3_R_EXTENSION_NAME_ERROR);
      X509V3_conf_err(val);
      goto err;
    }

    /*
     * Handle inheritance.
     */
    if (!strcmp(val->value, "inherit")) {
      if (asid_add_inherit(choice))
	continue;
      X509V3err(X509V3_F_V2I_ASIDENTIFIERS, X509V3_R_INVALID_INHERITANCE);
      X509V3_conf_err(val);
      goto err;
    }

    /*
     * Number or range.  Add it to the list, we'll sort the list later.
     */
    if (!X509V3_get_value_int(val, &min)) {
      X509V3err(X509V3_F_V2I_ASIDENTIFIERS, X509V3_R_INVALID_ASNUMBER);
      X509V3_conf_err(val);
      goto err;
    }
    if ((s = strchr(val->value, '-')) == NULL) {
      max = NULL;
    } else if ((max = s2i_ASN1_INTEGER(NULL, s + strspn(s, "- \t"))) == NULL) {
      X509V3err(X509V3_F_V2I_ASIDENTIFIERS, X509V3_R_INVALID_ASRANGE);
      X509V3_conf_err(val);
      goto err;
    }
    if (!asid_add_id_or_range(choice, min, max)) {
      X509V3err(X509V3_F_V2I_ASIDENTIFIERS, ERR_R_MALLOC_FAILURE);
      goto err;
    }
  }

  /*
   * Canonize the result, then we're done.
   */
  asid_canonize(asid->asnum);
  asid_canonize(asid->rdi);
  return asid;

 err:
  ASIdentifiers_free(asid);
  return NULL;
}

/*
 * OpenSSL dispatch.
 */

X509V3_EXT_METHOD v3_asid = {
  NID_sbgp_autonomousSysNum,	/* nid */
  0,				/* flags */
  ASN1_ITEM_ref(ASIdentifiers),	/* template */
  0, 0, 0, 0,			/* old functions, ignored */
  0,				/* i2s */
  0,				/* s2i */
  0,				/* i2v */
  v2i_ASIdentifiers,		/* v2i */
  i2r_ASIdentifiers,		/* i2r */
  0,				/* r2i */
  NULL				/* extension-specific data */
};
