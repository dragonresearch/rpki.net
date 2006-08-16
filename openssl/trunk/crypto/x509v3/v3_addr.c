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
 * Implementation of RFC 3779 section 2.2.
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
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
  ASN1_SIMPLE(IPAddressFamily, addressFamily,   ASN1_OCTET_STRING),
  ASN1_SIMPLE(IPAddressFamily, ipAddressChoice, IPAddressChoice)
} ASN1_SEQUENCE_END(IPAddressFamily)

ASN1_ITEM_TEMPLATE(IPAddrBlocks) = 
  ASN1_EX_TEMPLATE_TYPE(ASN1_TFLG_SEQUENCE_OF, 0,
			IPAddrBlocks, IPAddressFamily)
ASN1_ITEM_TEMPLATE_END(IPAddrBlocks)

IMPLEMENT_ASN1_FUNCTIONS(IPAddressRange)
IMPLEMENT_ASN1_FUNCTIONS(IPAddressOrRange)
IMPLEMENT_ASN1_FUNCTIONS(IPAddressChoice)
IMPLEMENT_ASN1_FUNCTIONS(IPAddressFamily)

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
 * What's the address length associated with this AFI?
 */
static int length_from_afi(const unsigned afi)
{
  switch (afi) {
  case IANA_AFI_IPV4:
    return 4;
  case IANA_AFI_IPV6:
    return 16;
  default:
    return 0;
  }
}

/*
 * Extract the AFI from an IPAddressFamily.
 */
static unsigned afi_from_addressfamily(const IPAddressFamily *f)
{
  return ((f->addressFamily->data[0] << 8) |
	  (f->addressFamily->data[1]));
}

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
#define addr_prefixlen(bs) ((int) ((bs)->length * 8 - ((bs)->flags & 7)))

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
    if (!inet_ntop(AF_INET, addr, buf, sizeof(buf)))
      return 0;
    BIO_puts(out, buf);
    break;
  case IANA_AFI_IPV6:
    addr_expand(addr, bs, 16, fill);
    if (!inet_ntop(AF_INET6, addr, buf, sizeof(buf)))
      return 0;
    BIO_puts(out, buf);
    break;
  default:
    for (i = 0; i < bs->length; i++)
      BIO_printf(out, "%s%02x", (i > 0 ? ":" : ""), bs->data[i]);
    BIO_printf(out, "[%d]", (int) (bs->flags & 7));
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
    const IPAddressOrRange *aor = sk_IPAddressOrRange_value(aors, i);
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
			    void *ext,
			    BIO *out,
			    int indent)
{
  const IPAddrBlocks *addr = ext;
  int i;
  for (i = 0; i < sk_IPAddressFamily_num(addr); i++) {
    IPAddressFamily *f = sk_IPAddressFamily_value(addr, i);
    const unsigned afi = afi_from_addressfamily(f);
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
			      unsigned char *addr,
			      const int prefixlen)
{
  int bytelen = (prefixlen + 7) / 8, bitlen = prefixlen % 8;
  IPAddressOrRange *aor = IPAddressOrRange_new();

  if (aor == NULL)
    return 0;
  aor->type = IPAddressOrRange_addressPrefix;
  if (aor->u.addressPrefix == NULL &&
      (aor->u.addressPrefix = ASN1_BIT_STRING_new()) == NULL)
    goto err;
  if (!ASN1_BIT_STRING_set(aor->u.addressPrefix, addr, bytelen))
    goto err;
  aor->u.addressPrefix->flags &= ~7;
  aor->u.addressPrefix->flags |= ASN1_STRING_FLAG_BITS_LEFT;
  if (bitlen > 0) {
    aor->u.addressPrefix->data[bytelen - 1] &= ~(0xFF >> bitlen);
    aor->u.addressPrefix->flags |= 8 - bitlen;
  }
  
  *result = aor;
  return 1;

 err:
  IPAddressOrRange_free(aor);
  return 0;
}

/*
 * Construct a range.  If it can be expressed as a prefix,
 * return a prefix instead.  Doing this here simplifies
 * the rest of the code considerably.
 */
static int make_addressRange(IPAddressOrRange **result,
			     unsigned char *min,
			     unsigned char *max,
			     const int length)
{
  IPAddressOrRange *aor;
  int i, prefixlen;

  if ((prefixlen = range_should_be_prefix(min, max, length)) >= 0)
    return make_addressPrefix(result, min, prefixlen);

  if ((aor = IPAddressOrRange_new()) == NULL)
    return 0;
  aor->type = IPAddressOrRange_addressRange;
  assert(aor->u.addressRange == NULL);
  if ((aor->u.addressRange = IPAddressRange_new()) == NULL)
    goto err;
  if (aor->u.addressRange->min == NULL &&
      (aor->u.addressRange->min = ASN1_BIT_STRING_new()) == NULL)
    goto err;
  if (aor->u.addressRange->max == NULL &&
      (aor->u.addressRange->max = ASN1_BIT_STRING_new()) == NULL)
    goto err;

  for (i = length; i > 0 && min[i - 1] == 0x00; --i)
    ;
  if (!ASN1_BIT_STRING_set(aor->u.addressRange->min, min, i))
    goto err;
  aor->u.addressRange->min->flags &= ~7;
  aor->u.addressRange->min->flags |= ASN1_STRING_FLAG_BITS_LEFT;
  if (i > 0) {
    unsigned char b = min[i - 1];
    int j = 1;
    while ((b & (0xFFU >> j)) != 0) 
      ++j;
    aor->u.addressRange->min->flags |= 8 - j;
  }

  for (i = length; i > 0 && max[i - 1] == 0xFF; --i)
    ;
  if (!ASN1_BIT_STRING_set(aor->u.addressRange->max, max, i))
    goto err;
  aor->u.addressRange->max->flags &= ~7;
  aor->u.addressRange->max->flags |= ASN1_STRING_FLAG_BITS_LEFT;
  if (i > 0) {
    unsigned char b = max[i - 1];
    int j = 1;
    while ((b & (0xFFU >> j)) != (0xFFU >> j))
      ++j;
    aor->u.addressRange->max->flags |= 8 - j;
  }

  *result = aor;
  return 1;

 err:
  IPAddressOrRange_free(aor);
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
  unsigned keylen;
  int i;

  key[0] = (afi >> 8) & 0xFF;
  key[1] = afi & 0xFF;
  if (safi != NULL) {
    key[2] = *safi & 0xFF;
    keylen = 3;
  } else {
    keylen = 2;
  }

  for (i = 0; i < sk_IPAddressFamily_num(addr); i++) {
    f = sk_IPAddressFamily_value(addr, i);
    assert(f->addressFamily->data != NULL);
    if (f->addressFamily->length == keylen &&
	!memcmp(f->addressFamily->data, key, keylen))
      return f;
  }

  if ((f = IPAddressFamily_new()) == NULL)
    goto err;
  if (f->ipAddressChoice == NULL &&
      (f->ipAddressChoice = IPAddressChoice_new()) == NULL)
    goto err;
  if (f->addressFamily == NULL && 
      (f->addressFamily = ASN1_OCTET_STRING_new()) == NULL)
    goto err;
  if (!ASN1_OCTET_STRING_set(f->addressFamily, key, keylen))
    goto err;
  if (!sk_IPAddressFamily_push(addr, f))
    goto err;

  return f;

 err:
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
  if (f == NULL ||
      f->ipAddressChoice == NULL ||
      (f->ipAddressChoice->type == IPAddressChoice_addressesOrRanges &&
       f->ipAddressChoice->u.addressesOrRanges != NULL))
    return 0;
  if (f->ipAddressChoice->type == IPAddressChoice_inherit &&
      f->ipAddressChoice->u.inherit != NULL)
    return 1;
  if (f->ipAddressChoice->u.inherit == NULL &&
      (f->ipAddressChoice->u.inherit = ASN1_NULL_new()) == NULL)
    return 0;
  f->ipAddressChoice->type = IPAddressChoice_inherit;
  return 1;
}

/*
 * Construct an IPAddressOrRange sequence, or return an existing one.
 */
static IPAddressOrRanges *make_prefix_or_range(IPAddrBlocks *addr,
					       const unsigned afi,
					       const unsigned *safi)
{
  IPAddressFamily *f = make_IPAddressFamily(addr, afi, safi);
  IPAddressOrRanges *aors = NULL;

  if (f == NULL ||
      f->ipAddressChoice == NULL ||
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
			   unsigned char *a,
			   const int prefixlen)
{
  IPAddressOrRanges *aors = make_prefix_or_range(addr, afi, safi);
  IPAddressOrRange *aor;
  if (aors == NULL || !make_addressPrefix(&aor, a, prefixlen))
    return 0;
  if (sk_IPAddressOrRange_push(aors, aor))
    return 1;
  IPAddressOrRange_free(aor);
  return 0;
}

/*
 * Add a range.
 */
static int addr_add_range(IPAddrBlocks *addr,
			  const unsigned afi,
			  const unsigned *safi,
			  unsigned char *min,
			  unsigned char *max)
{
  IPAddressOrRanges *aors = make_prefix_or_range(addr, afi, safi);
  IPAddressOrRange *aor;
  int length = length_from_afi(afi);
  if (aors == NULL)
    return 0;
  if (!make_addressRange(&aor, min, max, length))
    return 0;
  if (sk_IPAddressOrRange_push(aors, aor))
    return 1;
  IPAddressOrRange_free(aor);
  return 0;
}

/*
 * Extract min and max values from an IPAddressOrRange.
 */
static void extract_min_max(IPAddressOrRange *aor,
				 unsigned char *min,
				 unsigned char *max,
				 int length)
{
  assert(aor != NULL && min != NULL && max != NULL);
  switch (aor->type) {
  case IPAddressOrRange_addressPrefix:
    addr_expand(min, aor->u.addressPrefix, length, 0x00);
    addr_expand(max, aor->u.addressPrefix, length, 0xFF);
    return;
  case IPAddressOrRange_addressRange:
    addr_expand(min, aor->u.addressRange->min, length, 0x00);
    addr_expand(max, aor->u.addressRange->max, length, 0xFF);
    return;
  }
}

/*
 * Whack an IPAddressOrRanges into canonical form.
 */
static int IPAddressOrRanges_canonize(IPAddressOrRanges *aors,
				      const unsigned afi)
{
  int i, j, length = length_from_afi(afi);

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

    extract_min_max(a, a_min, a_max, length);
    extract_min_max(b, b_min, b_max, length);

    /*
     * If a contains b, we can just get rid of b.
     */
    if (memcmp(a_max, b_max, length) >= 0) {
      sk_IPAddressOrRange_delete(aors, i + 1);
      IPAddressOrRange_free(b);
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
      IPAddressOrRange_free(a);
      IPAddressOrRange_free(b);
      --i;
      continue;
    }
  }

  return 1;
}

/*
 * Sort comparision function for a sequence of IPAddressFamily.
 *
 * The last paragraph of RFC 3779 2.2.3.3 is slightly ambiguous about
 * the ordering: I can read it as meaning that IPv6 without a SAFI
 * comes before IPv4 with a SAFI, which seems pretty weird.  The
 * examples in appendix B suggest that the author intended the
 * null-SAFI rule to apply only within a single AFI, which is what I
 * would have expected and is what the following code implements.
 */
static int IPAddressFamily_cmp(const IPAddressFamily * const *a_,
			       const IPAddressFamily * const *b_)
{
  const ASN1_OCTET_STRING *a = (*a_)->addressFamily;
  const ASN1_OCTET_STRING *b = (*b_)->addressFamily;
  int len = (( a->length <= b->length) ? a->length : b->length);
  int cmp = memcmp(a->data, b->data, len);
  return cmp ? cmp : a->length - b->length;
}

/*
 * v2i handler for the IPAddrBlocks extension.
 */
static void *v2i_IPAddrBlocks(struct v3_ext_method *method,
			      struct v3_ext_ctx *ctx,
			      STACK_OF(CONF_VALUE) *values)
{
  static const char v4addr_chars[] = "0123456789.";
  static const char v6addr_chars[] = "0123456789.:abcdefABCDEF";
  IPAddrBlocks *addr = NULL;
  char *s = NULL, *t;
  int i;
  
  if ((addr = sk_IPAddressFamily_new(IPAddressFamily_cmp)) == NULL) {
    X509V3err(X509V3_F_V2I_IPADDRBLOCKS, ERR_R_MALLOC_FAILURE);
    return NULL;
  }

  for (i = 0; i < sk_CONF_VALUE_num(values); i++) {
    CONF_VALUE *val = sk_CONF_VALUE_value(values, i);
    unsigned char min[ADDR_RAW_BUF_LEN], max[ADDR_RAW_BUF_LEN];
    unsigned afi, *safi = NULL, safi_;
    const char *addr_chars;
    int prefixlen, af, i1, i2, delim, host_prefixlength;

    if (       !name_cmp(val->name, "IPv4")) {
      afi = IANA_AFI_IPV4;
    } else if (!name_cmp(val->name, "IPv6")) {
      afi = IANA_AFI_IPV6;
    } else if (!name_cmp(val->name, "IPv4-SAFI")) {
      afi = IANA_AFI_IPV4;
      safi = &safi_;
    } else if (!name_cmp(val->name, "IPv6-SAFI")) {
      afi = IANA_AFI_IPV6;
      safi = &safi_;
    } else {
      X509V3err(X509V3_F_V2I_IPADDRBLOCKS, X509V3_R_EXTENSION_NAME_ERROR);
      X509V3_conf_err(val);
      goto err;
    }

    switch (afi) {
    case IANA_AFI_IPV4:
      af = AF_INET;
      host_prefixlength = 32;
      addr_chars = v4addr_chars;
      break;
    case IANA_AFI_IPV6:
      af = AF_INET6;
      host_prefixlength = 128;
      addr_chars = v6addr_chars;
      break;
    }

    /*
     * Handle SAFI, if any, and strdup() so we can null-terminate
     * the other input values.
     */
    if (safi != NULL) {
      *safi = strtoul(val->value, &t, 0);
      t += strspn(t, " \t");
      if (*safi > 0xFF || *t++ != ':') {
	X509V3err(X509V3_F_V2I_IPADDRBLOCKS, X509V3_R_INVALID_SAFI);
	X509V3_conf_err(val);
	goto err;
      }
      t += strspn(t, " \t");
      s = strdup(t);
    } else {
      s = strdup(val->value);
    }
    if (s == NULL) {
      X509V3err(X509V3_F_V2I_IPADDRBLOCKS, ERR_R_MALLOC_FAILURE);
      goto err;
    }

    /*
     * Check for inheritance.  Not worth additional complexity to
     * optimize this (seldom-used) case.
     */
    if (!strcmp(s, "inherit")) {
      if (!addr_add_inherit(addr, afi, safi)) {
	X509V3err(X509V3_F_V2I_IPADDRBLOCKS, X509V3_R_INVALID_INHERITANCE);
	X509V3_conf_err(val);
	goto err;
      }
      OPENSSL_free(s);
      s = NULL;
      continue;
    }

    i1 = strspn(s, addr_chars);
    i2 = i1 + strspn(s + i1, " \t");
    delim = s[i2++];
    s[i1] = '\0';

    if (inet_pton(af, s, min) != 1) {
      X509V3err(X509V3_F_V2I_IPADDRBLOCKS, X509V3_R_INVALID_IPADDRESS);
      X509V3_conf_err(val);
      goto err;
    }

    switch (delim) {
    case '/':
      prefixlen = (int) strtoul(s + i2, &t, 10);
      if (t == s + i2 || *t != '\0') {
	X509V3err(X509V3_F_V2I_IPADDRBLOCKS, X509V3_R_EXTENSION_VALUE_ERROR);
	X509V3_conf_err(val);
	goto err;
      }
      if (!addr_add_prefix(addr, afi, safi, min, prefixlen)) {
	X509V3err(X509V3_F_V2I_IPADDRBLOCKS, ERR_R_MALLOC_FAILURE);
	goto err;
      }
      break;
    case '-':
      i1 = i2 + strspn(s + i2, " \t");
      i2 = i1 + strspn(s + i1, addr_chars);
      if (i1 == i2 || s[i2] != '\0') {
	X509V3err(X509V3_F_V2I_IPADDRBLOCKS, X509V3_R_EXTENSION_VALUE_ERROR);
	X509V3_conf_err(val);
	goto err;
      }
      if (inet_pton(af, s + i1, max) != 1) {
	X509V3err(X509V3_F_V2I_IPADDRBLOCKS, X509V3_R_INVALID_IPADDRESS);
	X509V3_conf_err(val);
	goto err;
      }
      if (!addr_add_range(addr, afi, safi, min, max)) {
	X509V3err(X509V3_F_V2I_IPADDRBLOCKS, ERR_R_MALLOC_FAILURE);
	goto err;
      }
      break;
    case '\0':
      if (!addr_add_prefix(addr, afi, safi, min, host_prefixlength)) {
	X509V3err(X509V3_F_V2I_IPADDRBLOCKS, ERR_R_MALLOC_FAILURE);
	goto err;
      }
      break;
    default:
      X509V3err(X509V3_F_V2I_IPADDRBLOCKS, X509V3_R_EXTENSION_VALUE_ERROR);
      X509V3_conf_err(val);
      goto err;
    }

    OPENSSL_free(s);
    s = NULL;
  }

  /*
   * Canonize the result, then we're done.
   */
  for (i = 0; i < sk_IPAddressFamily_num(addr); i++) {
    IPAddressFamily *f = sk_IPAddressFamily_value(addr, i);
    if (f->ipAddressChoice->type == IPAddressChoice_addressesOrRanges &&
	!IPAddressOrRanges_canonize(f->ipAddressChoice->u.addressesOrRanges,
				    afi_from_addressfamily(f)))
      goto err;
  }
  sk_IPAddressFamily_sort(addr);
  return addr;

 err:
  OPENSSL_free(s);
  sk_IPAddressFamily_pop_free(addr, IPAddressFamily_free);
  return NULL;
}

/*
 * OpenSSL dispatch
 */
X509V3_EXT_METHOD v3_addr = {
  NID_sbgp_ipAddrBlock,		/* nid */
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

/*
 * Figure out whether parent contains child.
 */
static int addr_contains(IPAddressOrRanges *parent,
			 IPAddressOrRanges *child,
			 int length)
{
  unsigned char p_min[ADDR_RAW_BUF_LEN], p_max[ADDR_RAW_BUF_LEN];
  unsigned char c_min[ADDR_RAW_BUF_LEN], c_max[ADDR_RAW_BUF_LEN];
  int p, c;

  if (child == NULL || parent == child)
    return 1;
  if (parent == NULL)
    return 0;

  p = 0;
  for (c = 0; c < sk_IPAddressOrRange_num(child); c++) {
    extract_min_max(sk_IPAddressOrRange_value(child, c),
		    c_min, c_max, length);
    for (;; p++) {
      if (p >= sk_IPAddressOrRange_num(parent))
	return 0;
      extract_min_max(sk_IPAddressOrRange_value(parent, p),
		      p_min, p_max, length);
      if (memcmp(p_max, c_max, length) < 0)
	continue;
      if (memcmp(p_min, c_min, length) > 0)
	return 0;
      break;
    }
  }

  return 1;
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
 * RFC 3779 2.3 path validation.  Intended to be called from X509_verify_cert().
 */
int v3_addr_validate_path(X509_STORE_CTX *ctx)
{
  IPAddrBlocks *parent = NULL, *child = NULL;
  int i, j, has_ext, ret = 1;
  X509 *x;

  assert(ctx->verify_cb);

  /*
   * Start with the ancestral cert.  It can't inherit anything.
   */
  i = sk_X509_num(ctx->chain) - 1;
  x = sk_X509_value(ctx->chain, i);
  assert(x != NULL);
  parent = X509_get_ext_d2i(x, NID_sbgp_ipAddrBlock, NULL, NULL);
  has_ext = parent != NULL;
  if (has_ext) {
    for (j = 0; j < sk_IPAddressFamily_num(parent); j++) {
      IPAddressFamily *fp = sk_IPAddressFamily_value(parent, j);
      assert(fp != NULL && fp->ipAddressChoice != NULL);
      if (fp->ipAddressChoice->type == IPAddressChoice_inherit) {
	validation_err(X509_V_ERR_UNNESTED_RESOURCE);
	goto done;		/* callback insisted on continuing */
      }
    }
    sk_IPAddressFamily_set_cmp_func(parent, IPAddressFamily_cmp);
  }

  /*
   * Now walk down the chain.  No cert may list resources that its
   * parent doesn't list.
   */
  while (--i >= 0) {
    x = sk_X509_value(ctx->chain, i);
    assert(x != NULL);
    assert(child == NULL);
    child = X509_get_ext_d2i(x, NID_sbgp_ipAddrBlock, NULL, NULL);
    if (child == NULL) {
      has_ext = 0;
    } else if (!has_ext) {
      validation_err(X509_V_ERR_UNNESTED_RESOURCE);
      has_ext = 1;		/* callback insists on continuing */
    }

    if (has_ext) {
      /*
       * Clean out address families that child doesn't use.
       * (Need to do this before modifying child....)
       */
      sk_IPAddressFamily_set_cmp_func(child, IPAddressFamily_cmp);
      for (j = 0; j < sk_IPAddressFamily_num(parent); j++) {
	IPAddressFamily *fp = sk_IPAddressFamily_value(parent, j);
	if (sk_IPAddressFamily_find(child, fp) < 0) {
	  IPAddressFamily_free(fp);
	  sk_IPAddressFamily_delete(parent, j);
	  --j;
	}
      }
      /*
       * Check all remaining address families in child.
       */
      for (j = 0; j < sk_IPAddressFamily_num(child); j++) {
	IPAddressFamily *fc = sk_IPAddressFamily_value(child, j);
	int k = sk_IPAddressFamily_find(parent, fc);
	if (k < 0)
	  validation_err(X509_V_ERR_UNNESTED_RESOURCE);
	if (k >= 0 &&
	    fc->ipAddressChoice->type == IPAddressChoice_addressesOrRanges) {
	  IPAddressFamily *fp = sk_IPAddressFamily_value(parent, k);
	  if (!addr_contains(fp->ipAddressChoice->u.addressesOrRanges, 
			     fc->ipAddressChoice->u.addressesOrRanges,
			     length_from_afi(afi_from_addressfamily(fc))))
	    validation_err(X509_V_ERR_UNNESTED_RESOURCE);
	  IPAddressFamily_free(fp);
	  sk_IPAddressFamily_set(parent, k, fc);
	  sk_IPAddressFamily_delete(child, j);
	  --j;
	}
      }
    }
    sk_IPAddressFamily_pop_free(child, IPAddressFamily_free);
    child = NULL;
  }

 done:
  sk_IPAddressFamily_pop_free(parent, IPAddressFamily_free);
  sk_IPAddressFamily_pop_free(child, IPAddressFamily_free);
  return ret;
}

#undef validation_err
