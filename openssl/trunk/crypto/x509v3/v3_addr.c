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
 * Initial attempt to implement RFC 3779 section 2.  I'd be very
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

ASN1_SEQUENCE(IPAddressRange) = {
  ASN1_SIMPLE(IPAddressRange, min, ASN1_BIT_STRING),
  ASN1_SIMPLE(IPAddressRange, max, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(IPAddressRange)

ASN1_CHOICE(IPAddressOrRange) = {
  ASN1_SIMPLE(IPAddressOrRange, u.addressPrefix, ASN1_BIT_STRING),
  ASN1_SIMPLE(IPAddressOrRange, u.addressRange,  IPAddressRange)
} ASN1_CHOICE_END(IPAddressOrRange)

ASN1_CHOICE(IPAddressChoice) = {
  ASN1_SIMPLE(IPAddressChoice,      u.inherit,           ASN1_NULL),
  ASN1_SEQUENCE_OF(IPAddressChoice, u.addressesOrRanges, IPAddressOrRange)
} ASN1_CHOICE_END(IPAddressChoice)

ASN1_SEQUENCE(IPAddressFamily) = {
  ASN1_SIMPLE(IPAddressFamily,      addressFamily,   ASN1_OCTET_STRING),
  ASN1_SEQUENCE_OF(IPAddressFamily, ipAddressChoice, IPAddressChoice)
} ASN1_SEQUENCE_END(IPAddressFamily)

ASN1_ITEM_TEMPLATE(IPAddrBlocks) = 
  ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0,
			IPAddrBlocks, IPAddressFamily)
ASN1_ITEM_TEMPLATE_END(IPAddrBlocks)

IMPLEMENT_ASN1_FUNCTIONS(IPAddressRange)
IMPLEMENT_ASN1_FUNCTIONS(IPAddressOrRange)
IMPLEMENT_ASN1_FUNCTIONS(IPAddressChoice)
IMPLEMENT_ASN1_FUNCTIONS(IPAddressFamily)
IMPLEMENT_ASN1_FUNCTIONS(IPAddrBlocks)

/*
 * How much buffer space do we need for a raw address?
 */
#define ADDR_RAW_BUF_LEN	16

/*
 * How much buffer space do we need for the text form of an address?
 * Output routines (inet_ntop() or whatever) must check for overflow.
 */
#define ADDR_TXT_BUF_LEN	48

/*
 * Expand the bitstring form of an address into a raw byte array.
 * At the moment this is coded for simplicity, not speed.
 */
static void addr_expand(unsigned char *addr,
			const ASN1_BIT_STRING *bs,
			const int length,
			const unsigned char fill)
{
  assert(bs->length >= 0 && bs->length <= length);
  memset(addr, fill, length);
  if (bs->length > 0) {
    memcpy(addr, bs->data, bs->length);
    if ((bs->flags & 7) != 0)
      addr[bs->length - 1] |= fill >> (8 - (bs->flags & 7));
  }
}

/*
 * Compare two addresses.
 * At the moment this is coded for simplicity, not for speed.
 *
 * Well, ok, this was simple until we had to check for adjacency.  The
 * idea is that, once we know that b is larger than a, we can subtract
 * one from b and check for equality to see if they're adjacent.  If
 * this hack offends you, feel free to recode this whole thing in
 * terms of the BN library....
 */
static int addr_cmp(const ASN1_BIT_STRING *a,
		    const ASN1_BIT_STRING *b,
		    const unsigned char fill_a,
		    const unsigned char fill_b,
		    const int length,
		    const int check_adjacent)
{
  int r;
  unsigned char a_[ADDR_RAW_BUF_LEN];
  unsigned char b_[ADDR_RAW_BUF_LEN];
  assert(length <= ADDR_RAW_BUF_LEN);
  addr_expand(a_, a, length, fill_a);
  addr_expand(b_, b, length, fill_b);
  r = memcmp(a, b, length);
  if (check_adjacent && r < 0) {
    int i = length - 1;
    while (i >= 0 && !b[i]--)
      i--;
    if (!memcmp(a, b, length))
      r = 0;
  }
  return r;
}

static int i2r_address(BIO *out,
		       unsigned afi,
		       unsigned char fill,
		       ASN1_BIT_STRING *bs)
{
  unsigned char addr[ADDR_RAW_BUF_LEN];
  char buf[ADDR_TXT_BUF_LEN];
  int i;

  switch (afi) {
  case IANA_AFI_IPV4:
    addr_expand(addr, bs, 4, fill);
    if (inet_ntop(AF_INET, addr, buf, sizeof(buf)) == NULL)
      return 0;
    BIO_puts(out, buf);
    break;
  case IANA_AFI_IPV6:
    addr_expand(addr, bs, 16, fill);
    if (inet_ntop(AF_INET6, addr, buf, sizeof(buf)) == NULL)
      return 0;
    BIO_puts(out, buf);
    break;
  default:
    for (i = 0; i < bs->length; i++)
      BIO_printf(out, "%s%02x", (i > 0 ? ":" : ""), bs->data[i]);
    BIO_printf(out, "[%d]", bs->flags & 7);
    break;
  }
  return 1;
}

static int i2r_IPAddressOrRange(BIO *out,
				int indent,
				IPAddressOrRanges *aors,
				unsigned afi)
{
  int i;
  for (i = 0; i < sk_IPAddressOrRange_num(aors); i++) {
    IPAddressOrRange *aor = sk_IPAddressOrRange_num(aors, i);
    BIO_printf(out, "%*s", indent, "");
    switch (aor->type) {
    case IPAddressOrRange_addressPrefix:
      if (!i2r_address(out, afi, 0x00, aor->u.addressPrefix))
	return 0;
      BIO_printf(out, "/%d\n", 
		 ((aor->u.addressPrefix->length * 8) -
		  (aor->u.addressPrefix->flags & 7)));
      continue;
    case IPAddressOrRange_addressRange:
      if (!i2r_address(out, afi, 0x00, aor->u.addressRange->min))
	return 0;
      BIO_puts(out, "-");
      if (!i2r_address(out, afi, 0xFF, aor->u.addressRange->max))
	return 0;
      BIO_puts(out, "\n");
      continue;
    }
  }
  return 1;
}

static int i2r_IPAddrBlocks(X509V3_EXT_METHOD *method,
			    void *ext, BIO *out, int indent)
{
  int i;
  for (i = 0; i < sk_IPAddrBlocks_num(ext); i++) {
    IPAddressFamily *f = sk_IPAddrBlocks_value(ext, i);
    unsigned afi = ((f->addressFamily->data[0] << 8) |
		    (f->addressFamily->data[1]));
    switch (afi) {
    case IANA_AFI_IPV4:
      BIO_printf(out, "%*sIPv4", indent, "");
      break;
    case IANA_AFI_IPV6:
      BIO_printf(out, "%*sIPv6", indent, "");
      break;
    default:
      BIO_printf(out, "%*sUnknown AFI %u", indent, "", afi);
      break;
    }
    if (f->addressFamily->length > 2) {
      switch (f->addressFamily->data[2]) {
      case   1:
	BIO_puts(out, " (Unicast)");
	break;
      case   2:
	BIO_puts(out, " (Multicast)");
	break;
      case   3:
	BIO_puts(out, " (Unicast/Multicast)");
	break;
      case   4:
	BIO_puts(out, " (MPLS)");
	break;
      case  64:
	BIO_puts(out, " (Tunnel)");
	break;
      case  65:
	BIO_puts(out, " (VPLS)");
	break;
      case  66:
	BIO_puts(out, " (BGP MDT)");
	break;
      case 128:
	BIO_puts(out, " (MPLS-labeled VPN)");
	break;
      default:  
	BIO_printf(out, " (Unknown SAFI %u)",
		   (unsigned) f->addressFamily->data[2]);
	break;
      }
    }
    switch (f->ipAddressChoice->type) {
    case IPAddressChoice_inherit:
      BIO_puts(out, ": inherit\n");
      break;
    case IPAddressChoice_addressesOrRanges:
      BIO_puts(out, ":\n");
      if (!i2r_IPAddressOrRanges(out,
				 indent + 2,
				 f->ipAddressChoice->u.asIdsOrRanges,
				 afi))
	return 0;
      break;
    }
  }
  return 1;
}

/*
 * Compare two IPAddressOrRanges elements.
 */
static int IPAddressOrRange_cmp(const IPAddressOrRange *a,
				const IPAddressOrRange *b,
				const int length)
{
  const ASN1_BIT_STRING *addr_a, *addr_b;
  unsigned prefixlen_a, prefixlen_b;
  int r;

  switch (a->type) {
  case IPAddressOrRange_addressPrefix:
    addr_a = a->u.addressPrefix;
    prefixlen_a = ((a->u.addressPrefix->length * 8) -
		   (a->u.addressPrefix->flags & 7));
    break;
  case IPAddressOrRange_addressRange:
    addr_a = a->u.addressRange->min;
    prefixlen_a = length * 8;
    break;
  }

  switch (b->type) {
  case IPAddressOrRange_addressPrefix:
    addr_b = b->u.addressPrefix;
    prefixlen_b = ((b->u.addressPrefix->length * 8) -
		   (b->u.addressPrefix->flags & 7));
    break;
  case IPAddressOrRange_addressRange:
    addr_b = b->u.addressRange->min;
    prefixlen_b = length * 8;
    break;
  }

  if ((r = addr_cmp(addr_a, addr_b, 0x00, 0x00, length, 0)) != 0)
    return r;
  else
    return prefixlen_a - prefixlen_b;
}

/*
 * Closures, since sk_sort() comparision routines are only allowed two
 * arguments, and have a weird double pointer type signature.
 */
static int v4IPAddressOrRange_cmp(const IPAddressOrRange * const *a,
				  const IPAddressOrRange * const *b)
{
  return IPAddressOrRange_cmp(*a, *b, 4);
}

static int v6IPAddressOrRange_cmp(const IPAddressOrRange * const *a,
				  const IPAddressOrRange * const *b)
{
  return IPAddressOrRange_cmp(*a, *b, 16);
}

/*
 * Whack an IPAddressOrRanges into canonical form.
 */
static int IPAddressOrRanges_canonize(IPAddressOrRanges *aors,
				      unsigned afi)
{
  int i, length;

  switch (afi) {
  case IANA_AFI_IPV4:
    length = 4;
    break;
  case IANA_AFI_IPV6:
    length = 16;
    break;
  }

  sk_IPAddressOrRange_sort(aors);

  /*
   * Resolve any duplicates or overlaps.
   */

  for (i = 0; i < sk_IPAddressOrRange_num(aors) - 1; i++) {
    IPAddressOrRange *a = sk_IPAddressOrRange_value(aors, i);
    IPAddressOrRange *b = sk_IPAddressOrRange_value(aors, i + 1);

    /*
     * Comparing prefix a with prefix b.  If they nest, a will contain
     * b due to the sorting rules, so we can just get rid of b.
     */
    if (a->type == IPAddressOrRange_addressPrefix &&
	b->type == IPAddressOrRange_addressPrefix &&
	addr_cmp(a->u.addressPrefix, b->u.addressPrefix,
		 0xFF, 0xFF, length, 0) >= 0) {
      sk_IPAddressOrRange_delete(aors, i + 1);
      ASN1_BIT_STRING_free(b->u.addressPrefix);
      IPAddressOrRange_free(b);
      i--;
      continue;
    }

    /*
     * Comparing prefix a with prefix b.  If they're adjacent, we need
     * to merge them into a range.
     */
    if (a->type == IPAddressOrRange_addressPrefix &&
	b->type == IPAddressOrRange_addressPrefix &&
	addr_cmp(a->u.addressPrefix, b->u.addressPrefix,
		 0xFF, 0xFF, length, 1) >= 0) {
      IPAddressRange *r = IPAddressRange_new();
      if (r == NULL)
	return 0;
      sk_IPAddressOrRange_delete(aors, i + 1);
      r->min = a->u.addressPrefix;
      r->max = b->u.addressPrefix;
      a->type = IPAddressOrRange_addressRange;
      a->u.addressRange = r;
      IPAddressOrRange_free(b);
      i--;
      continue;
    }

    if (a->type == IPAddressOrRange_addressPrefix &&
	b->type == IPAddressOrRange_addressPrefix)
      continue;

    /*
     * Comparing prefix a with range b.  If they overlap or are
     * adjacent, we merge them into a range.
     */
    if (a->type == IPAddressOrRange_addressPrefix &&
	addr_cmp(a->u.addressPrefix, b->u.addressRange->min,
		 0xFF, 0x00, length, 1) >= 0) {
      sk_IPAddressOrRange_delete(aors, i);
      ASN_BIT_STRING_free(b->u.addressRange->min);
      b->u.addressRange->min = a->u.addressPrefix;
      IPAddressRange_free(a->u.addressRange);
      IPAddressOrRange_free(a);
      i--;
      continue;
    }

    if (a->type == IPAddressOrRange_addressPrefix)
      continue;

    /*
     * Comparing range a with prefix b.  If they overlap or are
     * adjacent, we merge them into a range.
     */
    if (b->type == IPAddressOrRange_addressPrefix &&
	addr_cmp(a->u.addressRange->max, b->u.addressPrefix,
		 0xFF, 0x00, length, 1) >= 0) {
      sk_IPAddressOrRange_delete(aors, i + 1);
      ASN_BIT_STRING_free(a->u.addressRange->max);
      a->u.addressRange->max = b->u.addressPrefix;
      IPAddressRange_free(b->u.addressRange);
      IPAddressOrRange_free(b);
      i--;
      continue;
    }

    if (b->type == IPAddressOrRange_addressPrefix)
      continue;

    /*
     * Comparing range a with range b, remove b if contained in a.
     */
    if (addr_cmp(a->u.addressRange->max, b->u.addressRange->max,
		 0xFF, 0xFF, length, 0) >= 0) {
      sk_IPAddressOrRange_delete(aors, i + 1);
      ASN_BIT_STRING_free(b->u.addressRange->min);
      ASN_BIT_STRING_free(b->u.addressRange->max);
      IPAddressRange_free(b->u.addressRange);
      IPAddressOrRange_free(b);
      i--;
      continue;
    }

    /*
     * Comparing range a with range b, merge if they overlap or are
     * adjacent.
     */
    if (addr_cmp(a->u.addressRange->max, b->u.addressRange->min,
		 0xFF, 0x00, length, 1) >= 0) {
      sk_IPAddressOrRange_delete(aors, i);
      ASN_BIT_STRING_free(a->u.addressRange->max);
      ASN_BIT_STRING_free(b->u.addressRange->min);
      b->u.addressRange->min = a->u.addressRange->max;
      IPAddressRange_free(a->u.addressRange);
      IPAddressOrRange_free(a);
      i--;
      continue;
    }
  }

  /*
   * Convert ranges to prefixes where possible.
   */
  for (i = 0; i < sk_IPAddressOrRange_num(aors); i++) {
    IPAddressOrRange *a = sk_IPAddressOrRange_value(aors, i);
    if (a->type == IPAddressOrRange_addressRange &&
	addr_cmp(a->u.addressRange->min,a->u.addressRange->max,
		 0x00, 0x00, length, 0) == 0) {
      IPAddressRange *r = a->u.addressRange;
      a->type = IPAddressOrRange_addressPrefix;
      a->u.addressPrefix = r->min;
      ASN1_BIT_STRING_free(r->max);
      IPAddressRange_free(r);
    }
  }
}

#error still need insertion methods (see asid code)


static int IPAddressFamily_cmp(const IPAddressFamily * const *a,
			       const IPAddressFamily * const *b)
{
  return ASN1_OCTET_STRING_cmp(*a, *b);
}

static void *v2i_IPAddrBlocks(struct v3_ext_method *method,
			      struct v3_ext_ctx *ctx,
			      STACK_OF(CONF_VALUE) *values)
{
  IPAddrBlocks *addr = NULL;
  char *s;
  int i;
  
  if ((addr = sk_IPAddressFamily_new(IPAddressFamily_cmp)) == NULL) {
    X509V3err(X509V3_F_V2I_IPAddrBlocks, ERR_R_MALLOC_FAILURE);
    return NULL;
  }

  for (i = 0; i < sk_CONF_VALUE_num(values); i++) {
    CONF_VALUE *val = sk_CONF_VALUE_value(values, i);

    /*
     * Parsing stuff itself goes here.
     */

#error not finished
  }

  /*
   * Canonize the result, then we're done.
   */
  for (i = 0; i < sk_IPAddressFamily_num(addr); i++) {
    IPAddressFamily *f = sk_IPAddressFamily_value(addr, i);
    unsigned afi = ((f->addressFamily->data[0] << 8) |
		    (f->addressFamily->data[1]));
    if (f->ipAddressChoice->type == IPAddressChoice_addressesOrRanges &&
	!IPAddressOrRanges_canonize(f->ipAddressChoice->u.asIdsOrRanges, afi))
      goto err;
  }
  return addr;

 err:
#error not finished
  return NULL;
}

X509V3_EXT_METHOD v3_addr = {
  NID_IPAddrBlocks,		/* nid */
  0,				/* flags */
  ASN1_ITEM_ref(IPAddrBlocks),	/* template */
  0, 0, 0, 0,			/* old functions, ignored */
  0,				/* i2s */
  0,				/* s2i */
  0,				/* i2v */
  v2i_IPAddrBlocks,		/* v2i */
  i2r_IPAddrBlocks,		/* i2r */
  0,				/* r2i */
  NULL				/* extension-specific data */
};
