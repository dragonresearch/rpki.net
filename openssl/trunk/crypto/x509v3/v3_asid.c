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
#include <assert.h>
#include "cryptlib.h"
#include <openssl/conf.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509v3.h>

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
 * Write human-readable dump of ASIdentifiers extension.
 * ASIdentifiers is just a wrapper for two ASIdentifierChoices, so we
 * do almost all the work in i2r_ASIdentifierChoice().
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
  BIO_printf(out, "%*s%s: ", indent, "", msg);
  switch (choice->type) {
  case ASIdentifierChoice_inherit:
    BIO_puts(out, "inherit");
    break;
  case ASIdentifierChoice_asIdsOrRanges:
    for (i = 0; i < sk_ASIdOrRange_num(choice->u.asIdsOrRanges); i++) {
      ASIdOrRange *aor = sk_ASIdOrRange_value(choice->u.asIdsOrRanges, i);
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
 * Comparision function for stack sorting.
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

static int asid_add_inherit(ASIdentifierChoice **choice)
{
  if (*choice == NULL) {
    if ((*choice = ASIdentifierChoice_new()) == NULL)
      return 0;
    memset(*choice, 0, sizeof(**choice));
    if (((*choice)->u.inherit = ASN1_NULL_new()) == NULL)
      return 0;
    (*choice)->type = ASIdentifierChoice_inherit;
  }
  return (*choice)->type == ASIdentifierChoice_inherit;
}

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
    memset(*choice, 0, sizeof(**choice));
    (*choice)->u.asIdsOrRanges = sk_ASIdOrRange_new(ASIdOrRange_cmp);
    if ((*choice)->u.asIdsOrRanges == NULL)
      return 0;
    (*choice)->type = ASIdentifierChoice_asIdsOrRanges;
  }
  if ((aor = ASIdOrRange_new()) == NULL)
    return 0;
  memset(aor, 0, sizeof(*aor));
  if (max == NULL) {
    aor->type = ASIdOrRange_id;
    aor->u.id = min;
  } else {
    aor->type = ASIdOrRange_range;
    if ((aor->u.range = ASRange_new()) == NULL)
      goto err;
    aor->u.range->min = min;
    aor->u.range->max = max;
  }
  if (!(sk_ASIdOrRange_push((*choice)->u.asIdsOrRanges, aor)))
    goto err;
  return 1;

 err:
  if (aor->u.range != NULL)
    ASRange_free(aor->u.range);
  ASIdOrRange_free(aor);
  return 0;
}

static void asid_cleanup(ASIdentifierChoice *choice)
{
  int i;
  if (choice == NULL)
    return;
  switch (choice->type) {
  case ASIdentifierChoice_inherit:
    if (choice->u.inherit != NULL)
      ASN1_NULL_free(choice->inherit);
    choice->u.inherit = NULL;
    break;
  case ASIdOrRange_range:
    if (choice->u.asIdsOrRanges == NULL)
      break;
    for (i = 0; i < sk_ASIdOrRange_num(choice->asIdsOrRanges); i++) {
      ASIdOrRange *aor = sk_ASIdOrRange_value(choice->asIdsOrRanges, i);
      switch (aor->type) {
      case ASIdOrRange_id:
	if (aor->u.id != NULL)
	  ASN1_INTEGER_free(aor->u.id);
	aor->u.id = NULL;
	break;
      case ASIdOrRange_range:
	if (aor->u.range != NULL) {
	  if (aor->u.range->min != NULL)
	    ASN1_INTEGER_free(aor->u.range->min);
	  aor->u.range->min = NULL;
	  if (aor->u.range->max != NULL)
	    ASN1_INTEGER_free(aor->u.range->max);
	  aor->u.range->max = NULL;
	  ASRange_free(aor->u.range);
	  aor->u.range = NULL;
	}
      }
      ASIdOrRange_free(aor);
      sk_ASIdOrRange_set(choice->asIdsOrRanges, i, NULL);
    }
    sk_ASIdOrRange_free(choice->asIdsOrRanges);
    choice->u.asIdsOrRanges == NULL;
    break;
  }
  ASIdentifierChoice_free(choice);
}

static void asid_canonize(ASIdentifierChoice *choice)
{
  int i;

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
    ASIdOrRange *a = sk_ASIdOrRange_num(choice->u.asIdsOrRanges, i);
    ASIdOrRange *b = sk_ASIdOrRange_num(choice->u.asIdsOrRanges, i + 1);

    /*
     * Comparing ID a with ID b, remove a if they're equal.
     */
    if (a->type == ASIdOrRange_id && b->type == ASIdOrRange_id) {
      if (ASN1_INTEGER_cmp(a->u.id, b->u.id) == 0) {
	sk_ASIdOrRange_delete(choice->u.asIdsOrRanges, i);
	ASN1_INTEGER_free(a->u.id);
	ASIdOrRange_free(a);
	i--;
      }
      continue;
    }

    /*
     * Comparing ID a with range b, remove a if contained in b.
     */
    if (a->type == ASIdOrRange_id) {
      if (ASN1_INTEGER_cmp(a->u.id, b->u.range->min) >= 0 &&
	  ASN1_INTEGER_cmp(a->u.id, b->u.range->max) <= 0) {
	sk_ASIdOrRange_delete(choice->u.asIdsOrRanges, i);
	ASN1_INTEGER_free(a->u.id);
	ASIdOrRange_free(a);
	i--;
      }
      continue;
    }

    /*
     * Comparing range a with ID b, remove b if contained in a.
     */
    if (b->type == ASIdOrRange_id) {
      if (ASN1_INTEGER_cmp(b->u.id, a->u.range->min) >= 0 &&
	  ASN1_INTEGER_cmp(b->u.id, a->u.range->max) <= 0) {
	sk_ASIdOrRange_delete(choice->u.asIdsOrRanges, i + 1);
	ASN1_INTEGER_free(b->u.id);
	ASIdOrRange_free(b);
	i--;
      }
      continue;
    }

    /*
     * Comparing range a with range b, remove b if contained in a.
     */
    if (ASN1_INTEGER_cmp(a->u.range->max, b->u.range->max) >= 0) {
      ASN1_INTEGER_free(b->u.range->min);
      ASN1_INTEGER_free(b->u.range->max);
      sk_ASIdOrRange_delete(choice->u.asIdsOrRanges, i + 1);
      ASRange_free(b->u.range);
      ASIdOrRange_free(b);
      i--;
      continue;
    }

    /*
     * Comparing range a with range b, merge if they overlap.
     */
    if (ASN1_INTEGER_cmp(a->u.range->max, b->u.range->min) >= 0) {
      ASN1_INTEGER_free(a->u.range->max);
      ASN1_INTEGER_free(b->u.range->min);
      b->u.range->min = a->u.range->min;
      sk_ASIdOrRange_delete(choice->u.asIdsOrRanges, i);
      ASRange_free(a->u.range);
      ASIdOrRange_free(a);
      i--;
      continue;
    }
  }
}

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
    X509V3err(X509V3_F_V2I_ASIdentifiers, ERR_R_MALLOC_FAILURE);
    return NULL;
  }
  memset(asid, 0, sizeof(*asid));

  for (i = 0; i < sk_CONF_VALUE_num(values); i++) {
    val = sk_CONF_VALUE_value(values, i);

    /*
     * Figure out whether this is an AS or an RDI.
     */
    if (!strcmp(val->name, "as")) {
      choice = &asid->asnum;
    } else if (!strcmp(val->name, "rdi")) {
      choice = &asid->rdi;
    } else {
      X509V3err(X509V3_F_V2I_ASIdentifiers, X509V3_R_EXTENSION_NAME_ERROR);
      X509V3_conf_err(val);
      goto err;
    }

    /*
     * Handle inheritance.
     */
    if (!strcmp(val->value, "inherit")) {
      if (asid_add_inherit(choice))
	continue;
      X509V3err(X509V3_F_V2I_ASIdentifiers, X509V3_R_INVALID_INHERITANCE);
      X509V3_conf_err(val);
      goto err;
    }

    /*
     * Number or range.  Add it to the list, we'll sort the list later.
     */
    if (!X509V3_get_value_int(val, &min)) {
      X509V3err(X509V3_F_V2I_ASIdentifiers, X509V3_R_INVALID_ASNUMBER);
      X509V3_conf_err(val);
      goto err;
    }
    if ((s = strchr(val->value, '-')) == NULL) {
      max = NULL;
    } else if ((max = s2i_ASN1_INTEGER(NULL, s + 1)) == NULL) {
      X509V3err(X509V3_F_V2I_ASIdentifiers, X509V3_R_INVALID_ASRANGE);
      X509V3_conf_err(val);
      goto err;
    }
    if (!asid_add_id_or_range(choice, min, max)) {
      X509V3err(X509V3_F_V2I_ASIdentifiers, ERR_R_MALLOC_FAILURE);
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
  asid_cleanup(asid->asnum);
  asid->asnum = NULL;
  asid_cleanup(asid->rdi);
  asid->rdi = NULL;
  ASIdentifiers_free(asid);
  return NULL;
}

X509V3_EXT_METHOD v3_asid = {
  NID_ASIdentifiers,		/* nid */
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
