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
#include <stdlib.h>
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
 * Extract the prefix length from a bitstring.
 */
#define addr_prefixlen(bs) ((bs)->length * 8 - ((bs)->flags & 7))

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
      BIO_printf(out, "/%d\n", addr_prefixlen(aor->u.addressPrefix));
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
				 f->ipAddressChoice->u.addressesOrRanges,
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
    prefixlen_a = addr_prefixlen(a->u.addressPrefix);
    break;
  case IPAddressOrRange_addressRange:
    addr_a = a->u.addressRange->min;
    prefixlen_a = length * 8;
    break;
  }

  switch (b->type) {
  case IPAddressOrRange_addressPrefix:
    addr_b = b->u.addressPrefix;
    prefixlen_b = addr_prefixlen(b->u.addressPrefix);
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
 * Constructors.
 */

static int make_addressPrefix(IPAddressOrRange **result,
			      const unsigned char *addr,
			      const unsigned prefixlength)
{
  unsigned bytelen = (prefixlength + 7) / 8, bitlen = prefixlen % 8;
  IPAddressOrRange *aor = IPAddressOrRange_new();
  ASN1_BIT_STRING *bs = ASN1_BIT_STRING_new();
  if (aor == NULL || bs == NULL ||
      !ASN1_BIT_STRING_set(bs, addr, bytelen))
    goto err;
  bs->flags &= ~7;
  bs->flags |= ASN1_STRING_FLAG_BITS_LEFT;
  if (bitlen > 0) {
    bs->data[bytelen - 1] &= ~(0xFF >> bitlen);
    bs->flags |= 8 - bitlen;
  }
  aor->type = IPAddressOrRange_addressPrefix;
  aor->addressPrefix = bs;
  *result = aor;
  return 1;

 err:
  if (aor != NULL)
    IPAddressOrRange_free(aor);
  if (bs != NULL)
    ASN1_BIT_STRING_free(bs);
  return 0;
}

static int make_addressRange(IPAddressOrRange **result,
			     const unsigned char *min_,
			     const unsigned char *max_,
			     const unsigned length)
{
  IPAddressOrRange *aor = IPAddressOrRange_new();
  IPAddressRange *r = IPAddressRange_new();
  ASN1_BIT_STRING *min = ASN1_BIT_STRING_new();
  ASN1_BIT_STRING *max = ASN1_BIT_STRING_new();
  int i;

  if (aor == NULL || r == NULL || min == NULL || max == NULL)
    goto err;

  i = length;
  while (i > 0 && min_[i - 1] == 0x00)
    --i;
  if (!ASN1_BIT_STRING_set(min, min_, i))
    goto err;
  min->flags &= ~7;
  min->flags |= ASN1_STRING_FLAG_BITS_LEFT;
  if (i > 0) {
    unsigned char b = min_[i - 1];
    int j = 1;
    while (j < 8 && (b & (0xFF >> j)) != 0) 
      ++j;
    assert(j < 8);
    min->flags |= j;
  }

  i = length;
  while (i > 0 && max[i - 1] == 0xFF)
    --i;
  if (!ASN1_BIT_STRING_set(max, max_, i))
    goto err;
  max->flags &= ~7;
  max->flags |= ASN1_STRING_FLAG_BITS_LEFT;
  if (i > 0) {
    unsigned char b = max_[i - 1];
    int j = 1;
    while (j < 8 && (b & (0xFF >> j)) != (0xFF >> j))
      ++j;
    assert(j < 8);
    max->flags |= j;
  }

  r->min = min;
  r->max = max;
  aor->type = IPAddressOrRange_addressRange;
  aor->addressRange = r;
  *result = aor;
  return 1;

 err:
  if (aor != NULL)
    IPAddressOrRange_free(aor);
  if (r != NULL)
    IPAddressRange_free(r);
  if (min != NULL)
    ASN1_BIT_STRING_free(min);
  if (max != NULL)
    ASN1_BIT_STRING_free(max);
  return 0;
}

static IPAddressFamily *add_IPAddressFamily(IPAddrBlocks *addr,
					    unsigned afi,
					    unsigned has_safi,
					    unsigned safi)
{
  IPAddressFamily *f;
  unsigned char key[3];
  unsigned keylen = has_safi ? 3 : 2;
  int i;
  key[0] = (afi >> 8) & 0xFF;
  key[1] = afi & 0xFF;
  key[2] = safi & 0xFF;
  for (i = 0; i < sk_IPAddressFamily_num(addr); i++) {
    *f = sk_IPAddressFamily_value(addr, i);
    if (!memcmp(f->addressFamily, key, keylen))
      return f;
  }
  if ((f = IPAddressFamily_new()) == NULL)
    return NULL;
  memset(f, 0, sizeof(*f));
  if ((f->ipAddressChoice = IPAddressChoice_new()) == NULL ||
      (f->addressFamily = ASN1_OCTET_STRING_new()) == NULL ||
      !ASN1_OCTET_STRING_set(f->addressFamily, key, keylen))
    goto err;
  memset(f->ipAddressChoice, 0, sizeof(*f->ipAddressChoice));
  if (!sk_IPAddressFamily_push(addr, f))
    goto err;
  return f;

 err:
  if (f->ipAddressChoice != NULL)
    IPAddressChoice_free(f->ipAddressChoice);
  if (f->addressFamily == NULL)
    ASN1_OCTET_STRING_free(f->addressFamily);
  if (f != NULL)
    IPAddressFamily_free(f);
  return NULL;
}

static int addr_add_inherit(IPAddrBlocks *addr,
			    unsigned afi,
			    unsigned has_safi,
			    unsigned safi)
{
  IPAddressFamily *f = add_IPAddressFamily(addr, afi, has_safi, safi);
  if (f == NULL || f->ipAddressChoice == NULL ||
      (f->ipAddressChoice->type == IPAddressChoice_addressesOrRanges &&
       f->ipAddressChoice->u.addressesOrRanges != NULL))
    return 0;
  if (f->ipAddressChoice->type == IPAddressChoice_inherit &&
      f->ipAddressChoice->u.inherit != NULL)
    return 1;
  if ((f->ipAddressChoice->u.inherit = ASN1_NULL_new()) == NULL)
    return 0;
  f->ipAddressChoice->type = IPAddressChoice_inherit;
  return 1;
}

static IPAddressOrRanges *addr_add_prefix_or_range(IPAddrBlocks *addr,
						   unsigned afi,
						   unsigned has_safi,
						   unsigned safi)
{
  IPAddressFamily *f = add_IPAddressFamily(addr, afi, has_safi, safi);
  IPAddressOrRanges *aors = NULL;

  if (f == NULL || f->ipAddressChoice == NULL ||
      (f->ipAddressChoice->type == IPAddressChoice_inherit &&
       f->ipAddressChoice->u.inherit != NULL))
    return NULL;
  if (f->ipAddressChoice->type == IPAddressChoice_addressesOrRanges)
    aors = f->ipAddressChoice->u.addressesOrRanges;
  if (aors != NULL)
    return aors;
  if ((aors = sk_IPAddressOrRange_new_null()) == NULL)
    return NULL;
  switch (afi) {
  case IANA_AFI_IPV4:
    sk_IPAddressOrRange_set_cmp_func(aors, v4IPAddressOrRange_cmp);
    break;
  case IANA_AFI_IPV6:
    sk_IPAddressOrRange_set_cmp_func(aors, v6IPAddressOrRange_cmp);
    break;
  }
  f->ipAddressChoice->type = IPAddressChoice_addressesOrRanges;
  f->ipAddressChoice->u.addressesOrRanges = aors;
  return aors;
}

static int addr_add_prefix(IPAddrBlocks *addr,
			   unsigned afi,
			   unsigned has_safi,
			   unsigned safi,
			   unsigned char *addr,
			   unsigned prefixlen)
{
  IPAddressOrRanges *aors = addr_add_prefix_or_range(addr, afi, has_safi, safi);
  IPAddressOrRange *aor;
  if (aors == NULL ||
      !make_addressPrefix(&aor, addr, prefixlen))
    return 0;
  if (sk_IPAddressOrRange_push(aors, aor))
    return 1;
  assert(aor->type == IPAddressOrRange_addressPrefix);
  ASN1_BIT_STRING_free(aor->u.addressPrefix);
  IPAddressOrRange_free(aor);
  return 0;
}

static int addr_add_range(IPAddrBlocks *addr,
			  unsigned afi,
			  unsigned has_safi,
			  unsigned safi,
			  unsigned char *min,
			  unsigned char *max)
{
  IPAddressOrRanges *aors = addr_add_prefix_or_range(addr, afi, has_safi, safi);
  IPAddressOrRange *aor;
  unsigned length;
  if (aors == NULL)
    return 0;
  switch (afi) {
  case IANA_AFI_IPV4:
    length = 4;
    break;
  case IANA_AFI_IPV6:
    length = 16;
    break;
  }
  if (!make_addressRange(&aor, min, max, length))
    return 0;
  if (sk_IPAddressOrRange_push(aors, aor))
    return 1;
  assert(aor->type == IPAddressOrRange_addressRange);
  ASN1_BIT_STRING_free(aor->u.addressRange->min);
  ASN1_BIT_STRING_free(aor->u.addressRange->max);
  IPAddressRange_free(aor->u.addressRange);
  IPAddressOrRange_free(aor);
  return 0;
}

/*
 * Calculate whether a range should be collapsed to a prefix.
 * prefixlen is set on return to indicate the prefix length we found
 */
static int range_should_be_prefix(const IPAddressRange *r,
				  const int length,
				  unsigned *prefixlen)
{
  unsigned char mask, min[ADDR_RAW_BUF_LEN], max[ADDR_RAW_BUF_LEN];
  int p, i, j;
  addr_expand(min, r->min, length, 0x00);
  addr_expand(max, r->max, length, 0xFF);
  i = 0;
  while (i < length && min[i] == max[i])
    i++;
  j = length - 1;
  while (j >= 0 && min[j] == 0x00 && max[j] == 0xFF)
    j--;
  if (i < j)
    return 0;
  if (i > j) {
    *prefixlen = i * 8;
    return 1;
  }
  mask = min[i] ^ max[i];
  switch (mask) {
  case 0x01: p = 7; break;
  case 0x03: p = 6; break;
  case 0x07: p = 5; break;
  case 0x0F: p = 4; break;
  case 0x1F: p = 3; break;
  case 0x3F: p = 2; break;
  case 0x7F: p = 1; break;
  default:   return 0;
  }
  if (min[i] & mask != 0 || max[i] & mask != mask)
    return 0;
  *prefixlen = i * 8 + p;
  return 1;
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

  /*
   * Start by sorting the IPAddressOrRanges sequence.
   */
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
#error This may leave an ill-formed range, need to regenerate
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
#error This may leave an ill-formed range, need to regenerate
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
#error This may leave an ill-formed range, need to regenerate
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
#error broken
  /*
   * This needs to be rewritten to use range_should_be_prefix(), or
   * needs to be combined with that code in a new function, or
   * something.  As it stands, this code does not work.  We can't just
   * reuse the bitstrings either, length might be wrong.  Best just
   * create a new one, since we need a method routine that does that
   * anyway.
   */
  for (i = 0; i < sk_IPAddressOrRange_num(aors); i++) {
    IPAddressOrRange *a = sk_IPAddressOrRange_value(aors, i);
    if (a->type == IPAddressOrRange_addressRange &&
	addr_cmp(a->u.addressRange->min,a->u.addressRange->max,
		 0x00, 0x00, length, 0) == 0) {
      IPAddressRange *r = a->u.addressRange;
      a->type = IPAddressOrRange_addressPrefix;
      if (addr_prefixlen(r->min) > addr_prefixlen(r->max)) {
	a->u.addressPrefix = r->min;
	ASN1_BIT_STRING_free(r->max);
      } else {
	a->u.addressPrefix = r->max;
	ASN1_BIT_STRING_free(r->min);
      }
      IPAddressRange_free(r);
    }
  }
}

static int IPAddressFamily_cmp(const IPAddressFamily * const *a,
			       const IPAddressFamily * const *b)
{
  return ASN1_OCTET_STRING_cmp((*a)->addressFamily,
			       (*b)->addressFamily);
}

static void *v2i_IPAddrBlocks(struct v3_ext_method *method,
			      struct v3_ext_ctx *ctx,
			      STACK_OF(CONF_VALUE) *values)
{
  IPAddrBlocks *addr = NULL;
  int i;
  
  if ((addr = sk_IPAddressFamily_new(IPAddressFamily_cmp)) == NULL) {
    X509V3err(X509V3_F_V2I_IPAddrBlocks, ERR_R_MALLOC_FAILURE);
    return NULL;
  }

  for (i = 0; i < sk_CONF_VALUE_num(values); i++) {
    CONF_VALUE *val = sk_CONF_VALUE_value(values, i);
    unsigned afi, safi, prefixlen, has_safi = 0;
    unsigned char min[ADDR_RAW_BUF_LEN], max[ADDR_RAW_BUF_LEN];
    char *s = val->value;
    int af;

    if (       !strcmp(val->name, "ipv4")) {
      afi = IANA_AFI_IPV4;
    } else if (!strcmp(val->name, "ipv6")) {
      afi = IANA_AFI_IPV6;
    } else if (!strcmp(val->name, "ipv4-safi")) {
      afi = IANA_AFI_IPV4;
      has_safi = 1;
    } else if (!strcmp(val->name, "ipv6-safi")) {
      afi = IANA_AFI_IPV6;
      has_safi = 1;
    } else {
      X509V3err(X509V3_F_V2I_IPAddrBlocks, X509V3_R_EXTENSION_NAME_ERROR);
      X509V3_conf_err(val);
      goto err;
    }

    if (has_safi) {
      safi = strtoul(val->value, &s, 0);
      s += strspn(s, " \t");
      if (safi > 0xFF || *s++ != ':') {
	X509V3err(X509V3_F_V2I_IPAddrBlocks, X509V3_R_EXTENSION_VALUE_ERROR);
	X509V3_conf_err(val);
	goto err;
      }
      s += strspn(s, " \t");
    }

    if (!strcmp(s, "inherit")) {
      if (addr_add_inherit(addr, afi, has_safi, safi))
	continue;
      X509V3err(X509V3_F_V2I_IPAddrBlocks, X509V3_R_INVALID_INHERITANCE);
      X509V3_conf_err(val);
      goto err;
    }

    switch (afi) {
    case IANA_AFI_IPV4:
      af = AF_INET;
      break;
    case IANA_AFI_IPV6:
      af = AF_INET6;
      break;
    }

#warning some of the following errors might be memory, not config

    if (inet_pton(af, s, min) != 1) {
      X509V3err(X509V3_F_V2I_IPAddrBlocks, X509V3_R_EXTENSION_VALUE_ERROR);
      X509V3_conf_err(val);
      goto err;
    }

    if ((s = strpbrk(s, "-/")) == NULL) {
      X509V3err(X509V3_F_V2I_IPAddrBlocks, X509V3_R_EXTENSION_VALUE_ERROR);
      X509V3_conf_err(val);
      goto err;
    }

    switch (*s++) {
    case '/':
      prefixlen = strtoul(s, &s, 10);
      if (*(s + strspn(s, " \t")) != '\0' ||
	  !addr_add_prefix(addr, afi, has_safi, safi, min, prefixlen)) {
	X509V3err(X509V3_F_V2I_IPAddrBlocks, X509V3_R_EXTENSION_VALUE_ERROR);
	X509V3_conf_err(val);
	goto err;
      }
      break;
    case '-':
      s += strspn(s, " \t");
      if (inet_pton(af, s, max) != 1 ||
	  *(s + strspn(s, " \t")) != '\0' ||
	  !addr_add_range(addr, afi, has_safi, safi, min, max)) {
	X509V3err(X509V3_F_V2I_IPAddrBlocks, X509V3_R_EXTENSION_VALUE_ERROR);
	X509V3_conf_err(val);
	goto err;
      }
      break;
    }
  }

  /*
   * Canonize the result, then we're done.
   */
  for (i = 0; i < sk_IPAddressFamily_num(addr); i++) {
    IPAddressFamily *f = sk_IPAddressFamily_value(addr, i);
    unsigned afi = ((f->addressFamily->data[0] << 8) |
		    (f->addressFamily->data[1]));
    if (f->ipAddressChoice->type == IPAddressChoice_addressesOrRanges &&
	!IPAddressOrRanges_canonize(f->ipAddressChoice->u.addressesOrRanges,
				    afi))
      goto err;
  }
  sk_IPAddressFamily_sort(addr);
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
