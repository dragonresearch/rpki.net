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

/*
 * OpenSSL ASN.1 template translation of RFC 3779 2.2.3.
 */

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
  if (bs->length > 0) {
    memcpy(addr, bs->data, bs->length);
    if ((bs->flags & 7) != 0) {
      unsigned char mask = 0xFF >> (8 - (bs->flags & 7));
      if (fill == 0)
	addr[bs->length - 1] &= ~mask;
      else
	addr[bs->length - 1] |= mask;
    }
  }
  memset(addr + bs->length, fill, length - bs->length);
}

/*
 * Extract the prefix length from a bitstring.
 */
#define addr_prefixlen(bs) ((bs)->length * 8 - ((bs)->flags & 7))

/*
 * i2r handler for one address bitstring.
 */
static int i2r_address(BIO *out,
		       const unsigned afi,
		       const unsigned char fill,
		       const ASN1_BIT_STRING *bs)
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

/*
 * i2r handler for a sequence of addresses and ranges.
 */
static int i2r_IPAddressOrRanges(BIO *out,
				 const int indent,
				 const IPAddressOrRanges *aors,
				 const unsigned afi)
{
  int i;
  for (i = 0; i < sk_IPAddressOrRange_num(aors); i++) {
    const IPAddressOrRange *aor = sk_IPAddressOrRange_num(aors, i);
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

/*
 * i2r handler for an IPAddrBlocks extension.
 */
static int i2r_IPAddrBlocks(X509V3_EXT_METHOD *method,
			    const void *ext,
			    BIO *out,
			    const int indent)
{
  const IPAddrBlocks *addr = ext;
  int i;
  for (i = 0; i < sk_IPAddrBlocks_num(addr); i++) {
    const IPAddressFamily *f = sk_IPAddrBlocks_value(addr, i);
    const unsigned afi = ((f->addressFamily->data[0] << 8) |
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
 * Sort comparison function for a sequence of IPAddressOrRange
 * elements.
 */
static int IPAddressOrRange_cmp(const IPAddressOrRange *a,
				const IPAddressOrRange *b,
				const int length)
{
  unsigned char addr_a[ADDR_RAW_BUF_LEN], addr_b[ADDR_RAW_BUF_LEN];
  int prefixlen_a, prefixlen_b;
  int r;

  switch (a->type) {
  case IPAddressOrRange_addressPrefix:
    addr_expand(addr_a, a->u.addressPrefix, length, 0x00);
    prefixlen_a = addr_prefixlen(a->u.addressPrefix);
    break;
  case IPAddressOrRange_addressRange:
    addr_expand(addr_a, a->u.addressRange->min, length, 0x00);
    prefixlen_a = length * 8;
    break;
  }

  switch (b->type) {
  case IPAddressOrRange_addressPrefix:
    addr_expand(addr_b, b->u.addressPrefix, length, 0x00);
    prefixlen_b = addr_prefixlen(b->u.addressPrefix);
    break;
  case IPAddressOrRange_addressRange:
    addr_expand(addr_b, b->u.addressRange->min, length, 0x00);
    prefixlen_b = length * 8;
    break;
  }

  if ((r = memcmp(addr_a, addr_b, length)) != 0)
    return r;
  else
    return prefixlen_a - prefixlen_b;
}

/*
 * IPv4-specific closure over IPAddressOrRange_cmp, since sk_sort()
 * comparision routines are only allowed two arguments.
 */
static int v4IPAddressOrRange_cmp(const IPAddressOrRange * const *a,
				  const IPAddressOrRange * const *b)
{
  return IPAddressOrRange_cmp(*a, *b, 4);
}

/*
 * IPv6-specific closure over IPAddressOrRange_cmp, since sk_sort()
 * comparision routines are only allowed two arguments.
 */
static int v6IPAddressOrRange_cmp(const IPAddressOrRange * const *a,
				  const IPAddressOrRange * const *b)
{
  return IPAddressOrRange_cmp(*a, *b, 16);
}

/*
 * Calculate whether a range collapses to a prefix.
 * See last paragraph of RFC 3779 2.2.3.7.
 */
static int range_should_be_prefix(const unsigned char *min,
				  const unsigned char *max,
				  const int length)
{
  unsigned char mask;
  int i, j;

  for (i = 0; i < length && min[i] == max[i]; i++)
    ;
  for (j = length - 1; j >= 0 && min[j] == 0x00 && max[j] == 0xFF; j--)
    ;
  if (i < j)
    return -1;
  if (i > j)
    return i * 8;
  mask = min[i] ^ max[i];
  switch (mask) {
  case 0x01: j = 7; break;
  case 0x03: j = 6; break;
  case 0x07: j = 5; break;
  case 0x0F: j = 4; break;
  case 0x1F: j = 3; break;
  case 0x3F: j = 2; break;
  case 0x7F: j = 1; break;
  default:   return -1;
  }
  if (min[i] & mask != 0 || max[i] & mask != mask)
    return -1;
  else
    return i * 8 + j;
}

/*
 * Construct a prefix.
 */
static int make_addressPrefix(IPAddressOrRange **result,
			      const unsigned char *addr,
			      const int prefixlength)
{
  int bytelen = (prefixlength + 7) / 8, bitlen = prefixlen % 8;
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

/*
 * Construct a range.  If it can be expressed as a prefix,
 * return a prefix instead.  Doing this here simplifies
 * the rest of the code considerably.
 */
static int make_addressRange(IPAddressOrRange **result,
			     const unsigned char *min_,
			     const unsigned char *max_,
			     const unsigned length)
{
  IPAddressOrRange *aor = NULL;
  IPAddressRange *r = NULL;
  ASN1_BIT_STRING *min = NULL, *max = NULL;
  int i, prefixlen;

  if ((prefixlen = range_should_be_prefix(min_, max_, length)) >= 0)
    return make_addressPrefix(result, min_, prefixlen);

  if ((aor = IPAddressOrRange_new()) == NULL ||
      (r = IPAddressRange_new()) == NULL ||
      (min = ASN1_BIT_STRING_new()) == NULL ||
      (max = ASN1_BIT_STRING_new()) == NULL)
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

/*
 * Construct a new address family or find an existing one.
 */
static IPAddressFamily *make_IPAddressFamily(IPAddrBlocks *addr,
					     const unsigned afi,
					     const unsigned *safi)
{
  IPAddressFamily *f;
  unsigned char key[3];
  unsigned keylen = safi == NULL ? 2 : 3;
  int i;
  key[0] = (afi >> 8) & 0xFF;
  key[1] = afi & 0xFF;
  if (safi != NULL)
    key[2] = *safi & 0xFF;
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

/*
 * Add an inheritance element.
 */
static int addr_add_inherit(IPAddrBlocks *addr,
			    const unsigned afi,
			    const unsigned *safi)
{
  IPAddressFamily *f = make_IPAddressFamily(addr, afi, safi);
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

/*
 * Construct an IPAddressOrRanges sequence, or return an existing one.
 */
static IPAddressOrRanges *make_prefix_or_range(IPAddrBlocks *addr,
					       const unsigned afi,
					       const unsigned *safi)
{
  IPAddressFamily *f = make_IPAddressFamily(addr, afi, safi);
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

/*
 * Add a prefix.
 */
static int addr_add_prefix(IPAddrBlocks *addr,
			   const unsigned afi,
			   const unsigned *safi,
			   const unsigned char *addr,
			   const int prefixlen)
{
  IPAddressOrRanges *aors = make_prefix_or_range(addr, afi, safi);
  IPAddressOrRange *aor;
  if (aors == NULL || !make_addressPrefix(&aor, addr, prefixlen))
    return 0;
  if (sk_IPAddressOrRange_push(aors, aor))
    return 1;
  assert(aor->type == IPAddressOrRange_addressPrefix);
  ASN1_BIT_STRING_free(aor->u.addressPrefix);
  IPAddressOrRange_free(aor);
  return 0;
}

/*
 * Add a range.
 */
static int addr_add_range(IPAddrBlocks *addr,
			  const unsigned afi,
			  const unsigned *safi,
			  const unsigned char *min,
			  const unsigned char *max)
{
  IPAddressOrRanges *aors = make_prefix_or_range(addr, afi, safi);
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
 * Whack an IPAddressOrRanges into canonical form.
 */
static int IPAddressOrRanges_canonize(IPAddressOrRanges *aors,
				      const unsigned afi)
{
  int i, j, length;

  switch (afi) {
  case IANA_AFI_IPV4:
    length = 4;
    break;
  case IANA_AFI_IPV6:
    length = 16;
    break;
  }

  /*
   * Sort the IPAddressOrRanges sequence.
   */
  sk_IPAddressOrRange_sort(aors);

  /*
   * Resolve any duplicates or overlaps.
   */
  for (i = 0; i < sk_IPAddressOrRange_num(aors) - 1; i++) {
    IPAddressOrRange *a = sk_IPAddressOrRange_value(aors, i);
    IPAddressOrRange *b = sk_IPAddressOrRange_value(aors, i + 1);
    unsigned char a_min[ADDR_RAW_BUF_LEN], a_max[ADDR_RAW_BUF_LEN];
    unsigned char b_min[ADDR_RAW_BUF_LEN], b_max[ADDR_RAW_BUF_LEN];

    /*
     * Expand all the addresses once and get it over with.
     */
    switch (a->type) {
    case IPAddressOrRange_addressPrefix:
      addr_expand(a_min, a->u.addressPrefix, length, 0x00);
      addr_expand(a_max, a->u.addressPrefix, length, 0xFF);
      break;
    case IPAddressOrRange_addressRange:
      addr_expand(a_min, a->u.addressRange->min, length, 0x00);
      addr_expand(a_max, a->u.addressRange->max, length, 0xFF);
      break;
    }
    switch (b->type) {
    case IPAddressOrRange_addressPrefix:
      addr_expand(b_min, b->u.addressPrefix, length, 0x00);
      addr_expand(b_max, b->u.addressPrefix, length, 0xFF);
      break;
    case IPAddressOrRange_addressRange:
      addr_expand(b_min, b->u.addressRange->min, length, 0x00);
      addr_expand(b_max, b->u.addressRange->min, length, 0xFF);
      break;
    }

    /*
     * Make sure we're sorted properly (paranoia).
     */
    assert(memcmp(a_min, b_min, length) <= 0);

    /*
     * If a contains b, we can just get rid of b.
     */
    if (memcmp(a_max, b_max, length) >= 0) {
      sk_IPAddressOrRange_delete(aors, i + 1);
      aor_cleanup(b);
      --i;
      continue;
    }

    /*
     * If a and b are adjacent or overlap, merge them.  We check for
     * adjacency by subtracting one from b_min first.
     */
    for (j = length - 1; j >= 0 && b_min[j]-- == 0x00; j--)
      ;
    if (memcmp(a_max, b_min, length) >= 0) {
      IPAddressOrRange *merged;
      if (!make_addressRange(&merged, a_min, b_max, length))
	return 0;
      sk_IPAddressOrRange_set(aors, i, merged);
      sk_IPAddressOrRange_delete(aors, i + 1);
      aor_cleanup(a);
      aor_cleanup(b);
      --i;
      continue;
    }
  }

  return 1;
}

/*
 * Sort comparision function for a sequence of IPAddressFamily.
 */
static int IPAddressFamily_cmp(const IPAddressFamily * const *a,
			       const IPAddressFamily * const *b)
{
  return ASN1_OCTET_STRING_cmp((*a)->addressFamily,
			       (*b)->addressFamily);
}

/*
 * v2i handler for the IPAddrBlocks extension.
 */
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
    unsigned char min[ADDR_RAW_BUF_LEN], max[ADDR_RAW_BUF_LEN];
    unsigned afi, *safi = NULL, safi_;
    char *s = val->value;
    int prefixlen, af;

    if (       !strcmp(val->name, "ipv4")) {
      afi = IANA_AFI_IPV4;
    } else if (!strcmp(val->name, "ipv6")) {
      afi = IANA_AFI_IPV6;
    } else if (!strcmp(val->name, "ipv4-safi")) {
      afi = IANA_AFI_IPV4;
      safi = &safi_;
    } else if (!strcmp(val->name, "ipv6-safi")) {
      afi = IANA_AFI_IPV6;
      safi = &safi_;
    } else {
      X509V3err(X509V3_F_V2I_IPAddrBlocks, X509V3_R_EXTENSION_NAME_ERROR);
      X509V3_conf_err(val);
      goto err;
    }

    if (safi != NULL) {
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
      if (addr_add_inherit(addr, afi, safi))
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
      prefixlen = (int) strtoul(s, &s, 10);
      if (*(s + strspn(s, " \t")) != '\0' ||
	  !addr_add_prefix(addr, afi, safi, min, prefixlen)) {
	X509V3err(X509V3_F_V2I_IPAddrBlocks, X509V3_R_EXTENSION_VALUE_ERROR);
	X509V3_conf_err(val);
	goto err;
      }
      break;
    case '-':
      s += strspn(s, " \t");
      if (inet_pton(af, s, max) != 1 ||
	  *(s + strspn(s, " \t")) != '\0' ||
	  !addr_add_range(addr, afi, safi, min, max)) {
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

/*
 * OpenSSL dispatch
 */
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
