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
 * Implementation of RFC 3779 section 3.2.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "cryptlib.h"
#include <openssl/conf.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/bn.h>

/*
 * OpenSSL ASN.1 template translation of RFC 3779 3.2.3.
 */

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
    assert((*choice)->u.inherit == NULL);
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
    assert((*choice)->u.asIdsOrRanges == NULL);
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
    ASN1_INTEGER_free(aor->u.range->min);
    aor->u.range->min = min;
    ASN1_INTEGER_free(aor->u.range->max);
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
      assert(aor->u.range == NULL);
      if ((aor->u.range = ASRange_new()) == NULL) {
	ASIdOrRange_free(aor);
	goto err;
      }
      ASN1_INTEGER_free(aor->u.range->min);
      aor->u.range->min = a_min;
      ASN1_INTEGER_free(aor->u.range->max);
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
  int i;

  if ((asid = ASIdentifiers_new()) == NULL) {
    X509V3err(X509V3_F_V2I_ASIDENTIFIERS, ERR_R_MALLOC_FAILURE);
    return NULL;
  }

  for (i = 0; i < sk_CONF_VALUE_num(values); i++) {
    CONF_VALUE *val = sk_CONF_VALUE_value(values, i);
    ASIdentifierChoice **choice;
    ASN1_INTEGER *min = NULL, *max = NULL;
    int i1, i2, i3, is_range;

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
     * Number, range, or mistake, pick it apart and figure out which.
     */
    i1 = strspn(val->value, "0123456789");
    if (val->value[i1] == '\0') {
      is_range = 0;
    } else {
      is_range = 1;
      i2 = i1 + strspn(val->value + i1, " \t");
      if (val->value[i2] != '-') {
	X509V3err(X509V3_F_V2I_ASIDENTIFIERS, X509V3_R_INVALID_ASNUMBER);
	X509V3_conf_err(val);
	goto err;
      }
      i2++;
      i2 = i2 + strspn(val->value + i2, " \t");
      i3 = i2 + strspn(val->value + i2, "0123456789");
      if (val->value[i3] != '\0') {
	X509V3err(X509V3_F_V2I_ASIDENTIFIERS, X509V3_R_INVALID_ASRANGE);
	X509V3_conf_err(val);
	goto err;
      }
    }

    /*
     * Syntax is ok, read and add it.
     */
    if (!is_range) {
      if (!X509V3_get_value_int(val, &min)) {
	X509V3err(X509V3_F_V2I_ASIDENTIFIERS, ERR_R_MALLOC_FAILURE);
	goto err;
      }
    } else {
      char *s = BUF_strdup(val->value);
      if (s == NULL) {
	X509V3err(X509V3_F_V2I_ASIDENTIFIERS, ERR_R_MALLOC_FAILURE);
	goto err;
      }
      s[i1] = '\0';
      min = s2i_ASN1_INTEGER(NULL, s);
      max = s2i_ASN1_INTEGER(NULL, s + i2);
      OPENSSL_free(s);
      if (min == NULL || max == NULL) {
	ASN1_INTEGER_free(min);
	ASN1_INTEGER_free(max);
	X509V3err(X509V3_F_V2I_ASIDENTIFIERS, ERR_R_MALLOC_FAILURE);
	goto err;
      }
    }
    if (!asid_add_id_or_range(choice, min, max)) {
      ASN1_INTEGER_free(min);
      ASN1_INTEGER_free(max);
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

/*
 * Helper function to make asid_contains() more readable.
 */
static void asid_contains_helper(ASIdOrRange *a,
				 ASN1_INTEGER **min,
				 ASN1_INTEGER **max)
{
  assert(a != NULL && min != NULL && max != NULL);
  switch (a->type) {
  case ASIdOrRange_id:
    *min = a->u.id;
    *max = a->u.id;
    return;
  case ASIdOrRange_range:
    *min = a->u.range->min;
    *max = a->u.range->max;
    return;
  }
}

/*
 * Figure out whether parent contains child.
 */
static int asid_contains(ASIdOrRanges *parent, ASIdOrRanges *child)
{
  ASN1_INTEGER *p_min, *p_max, *c_min, *c_max;
  int p, c;

  if (child == NULL || parent == child)
    return 1;
  if (parent == NULL)
    return 0;

  p = 0;
  for (c = 0; c < sk_ASIdOrRange_num(child); c++) {
    asid_contains_helper(sk_ASIdOrRange_value(child, c), &c_min, &c_max);
    for (;; p++) {
      if (p >= sk_ASIdOrRange_num(parent))
	return 0;
      asid_contains_helper(sk_ASIdOrRange_value(parent, p), &p_min, &p_max);
      if (ASN1_INTEGER_cmp(p_max, c_max) < 0)
	continue;
      if (ASN1_INTEGER_cmp(p_min, c_min) > 0)
	return 0;
      break;
    }
  }
}

/*
 * Validation error handling via callback.
 */
#define validation_err(_err_)		\
  do {					\
    ctx->error = _err_;			\
    ctx->error_depth = i;		\
    ctx->current_cert = x;		\
    ret = ctx->verify_cb(0, ctx);	\
    if (!ret)				\
      goto done;			\
  } while (0)

/*
 * RFC 3779 3.3 path validation.  Intended to be called from X509_verify_cert().
 */
int v3_asid_validate_path(X509_STORE_CTX *ctx)
{
  ASIdOrRanges *parent_as = NULL, *parent_rdi = NULL;
  ASIdentifiers *asid = NULL;
  int i, has_ext, ret = 1;
  X509 *x;

  assert(ctx->verify_cb);

  /*
   * Start with the ancestral cert.  It can't inherit anything.
   */
  i = sk_X509_num(ctx->chain) - 1;
  x = sk_X509_value(ctx->chain, i);
  assert(x != NULL);
  asid = X509_get_ext_d2i(x, NID_sbgp_autonomousSysNum, NULL, NULL);
  has_ext = asid != NULL;
  if (has_ext) {
    if (asid->asnum != NULL) {
      switch (asid->asnum->type) {
      case ASIdentifierChoice_asIdsOrRanges:
	parent_as = asid->asnum->u.asIdsOrRanges;
	asid->asnum->u.asIdsOrRanges = NULL;
	break;
      case ASIdentifierChoice_inherit:
	validation_err(X509_V_ERR_UNNESTED_RESOURCE);
	goto done;		/* callback insists on continuing */
      }
    }
    if (asid->rdi != NULL) {
      switch (asid->rdi->type) {
      case ASIdentifierChoice_asIdsOrRanges:
	parent_rdi = asid->rdi->u.asIdsOrRanges;
	asid->rdi->u.asIdsOrRanges = NULL;
	break;
      case ASIdentifierChoice_inherit:
	validation_err(X509_V_ERR_UNNESTED_RESOURCE);
	goto done;		/* callback insists on continuing */
      }
    }
  }
  ASIdentifiers_free(asid);
  asid = NULL;

  /*
   * Now walk down the chain.  No cert may list resources that its
   * parent doesn't list.
   */
  while (--i >= 0) {
    x = sk_X509_value(ctx->chain, i);
    assert(x != NULL);

    assert(asid == NULL);
    asid = X509_get_ext_d2i(x, NID_sbgp_autonomousSysNum, NULL, NULL);
    if (asid == NULL) {
      has_ext = 0;
    } else if (!has_ext) {
      validation_err(X509_V_ERR_UNNESTED_RESOURCE);
      has_ext = 1;		/* callback insists on continuing */
    }

    if (has_ext) {
      if (asid->asnum != NULL &&
	  asid->asnum->type == ASIdentifierChoice_asIdsOrRanges) {
	if (!asid_contains(parent_as, asid->asnum->u.asIdsOrRanges))
	  validation_err(X509_V_ERR_UNNESTED_RESOURCE);
	sk_ASIdOrRange_pop_free(parent_as, ASIdOrRange_free);
	parent_as = asid->asnum->u.asIdsOrRanges;
	asid->asnum->u.asIdsOrRanges = NULL;
      }
      if (asid->rdi != NULL &&
	  asid->rdi->type == ASIdentifierChoice_asIdsOrRanges) {
	if (!asid_contains(parent_rdi, asid->rdi->u.asIdsOrRanges))
	  validation_err(X509_V_ERR_UNNESTED_RESOURCE);
	sk_ASIdOrRange_pop_free(parent_rdi, ASIdOrRange_free);
	parent_rdi = asid->rdi->u.asIdsOrRanges;
	asid->rdi->u.asIdsOrRanges = NULL;
      }
    }

    ASIdentifiers_free(asid);
    asid = NULL;
  }

 done:
  sk_ASIdOrRange_pop_free(parent_as, ASIdOrRange_free);
  sk_ASIdOrRange_pop_free(parent_rdi, ASIdOrRange_free);
  ASIdentifiers_free(asid);
  return ret;
}

#undef validation_err
