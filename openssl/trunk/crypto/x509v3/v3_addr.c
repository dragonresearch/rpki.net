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

static const struct {
  unsigned length;
  int af;
  const char *description;
} afi_table[] = {
  {  0			 },
  {  4, AF_INET,  "IPv4" },
  { 16, AF_INET6, "IPv6" }
};

#define afi_index(x) \
	(x > 0 && x < sizeof(afi_table)/sizeof(*afi_table) ? x : 0)

static const char *safi_table[] = {
  0,
  "Unicast",
  "Multicast",
  "Unicast/Multicast",
  "MPLS"
};

#define safi_index(x) \
	(x > 0 && x < sizeof(safi_table)/sizeof(*safi_table) ? x : 0)

static int i2r_address(BIO *out, int afi, unsigned char fill,
		       ASN1_BIT_STRING *bs)
{
  if (afi_index(afi)) {
    /*
     * Known AFI, we can fill and format this properly.
     */
    int length = afi_table[afi_index(afi)].length;
    int af = afi_table[afi_index(afi)].af;
    unsigned char addr[16];
    char buf[48];

    assert(sizeof(addr) >= length);
    if (bs->length > length)
      return 0;
    memset(addr, fill, length);
    if (bs->length > 0) {
      memcpy(addr, bs->data, bs->length);
      if ((bs->flags & 7) != 0)
	addr[bs->length - 1] |= fill >> (8 - (bs->flags & 7));
    }
    if (inet_ntop(af, addr, buf, sizeof(buf)) == NULL)
      return 0;
    BIO_puts(out, buf);
  } else {
    /*
     * Unknown AFI, dump as hex.
     */
    int i;
    for (i = 0; i < bs->length; i++)
      BIO_printf(out, "%s%02x", (i > 0 ? ":" : ""), bs->data[i]);
    BIO_printf(out, "[%d]", bs->flags & 7);
  }
  return 1;
}

static int i2r_IPAddressOrRange(BIO *out, int indent,
				IPAddressOrRanges *aors, int afi)
{
  int i;
  for (i = 0; i < sk_IPAddressOrRange_num(aors); i++) {
    IPAddressOrRange *aor = sk_IPAddressOrRange_num(aors, i);
    BIO_printf(out, "%*s", indent, "");
    switch (aor->type) {
    case IPAddressOrRange_addressPrefix:
      if (!i2r_address(out, afi, 0x00, aor->addressPrefix))
	return 0;
      BIO_printf(out, "/%d\n", 
		 aor->addressPrefix->length * 8 -
		 (aor->addressPrefix->flags & 7));
      continue;
    case IPAddressOrRange_addressRange:
      if (!i2r_address(out, afi, 0x00, aor->addressRange->min))
	return 0;
      BIO_puts(out, "-");
      if (!i2r_address(out, afi, 0xFF, aor->addressRange->max))
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
    int afi = (f->addressFamily->data[0] << 8) | f->addressFamily->data[1];
    if (afi_index(afi))
      BIO_printf(out, "%*s%s", indent, "",
		 afi_table[afi_index(afi)].description);
    else
      BIO_printf(out, "%*sUnknown AFI %i", indent, "", afi);
    if (f->addressFamily->length > 2) {
      int safi = f->addressFamily->data[2];
      if (safi_index(safi))
	BIO_printf(out, " (%s)", safi_table[safi_index(safi)]);
      else
	BIO_printf(out, " (Unknown SAFI %d)", safi);
    }
    switch (f->ipAddressChoice->type) {
    case IPAddressChoice_inherit:
      BIO_puts(out, ": inherit\n");
      break;
    case IPAddressChoice_addressesOrRanges:
      BIO_puts(out, ":\n");
      if (!i2r_IPAddressOrRanges(out, indent + 2,
				 f->ipAddressChoice->u.asIdsOrRanges, afi))
	return 0;
      break;
    }
  }
  return 1;
}

typedef struct addr_canonize_st {
  unsigned char min[16], max[16];
  IPAddressOrRange *aor;
  int prefixlen;
} addr_canonize;

DECLARE_STACK_OF(addr_canonize)

static int canonize_addrs(IPAddressOrRanges *aors, int afi)
{
  STACK_OF(addr_canonize) *acs = sk_addr_canonize_new(addr_cononize_cmp);
  int i, length = afi_table[afi_index(afi)].length;

  while (sk_IPAddressOrRange_num(aors) > 0) {
    addr_canonize *ac = OPENSSL_malloc(sizeof(addr_canonize));
    if (ac == NULL)
      goto err;
    memset(ac, 0, sizeof(*ac));
    sk_addr_canonize_push(acs, ac);
    ac->aor = sk_IPAddressOrRange_pop(aors);
    switch (ac->aor->type) {
    case IPAddressOrRange_addressPrefix:
      if (!addr_expand(ac->min, ac->aor->addressPrefix, length, 0x00))
	goto err;
      if (!addr_expand(ac->max, ac->aor->addressPrefix, length, 0xFF))
	goto err;
      ac->prefixlen = (ac->aor->addressPrefix->length * 8 -
		       (ac->aor->addressPrefix->flags & 7));
      break;
    case IPAddressOrRange_addressRange:
      if (!addr_expand(ac->min, ac->aor->addressRange->min, length, 0x00))
	goto err;
      if (!addr_expand(ac->min, ac->aor->addressRange->max, length, 0xFF))
	goto err;
      ac->prefixlen = ac->aor->addressPrefix->length * 8;
      break;
    }
  }

  sk_sort(acs);

  for (i = 0; i < sk_addr_canonize_num(acs); i++) {
#error not finished
    /* do the merge check here (see asid code) */
  }

  for (i = 0; i < sk_addr_canonize_num(acs); i++) {
#error not finished
    /*
     * Convert ranges to prefixes where possible
     * and convert back to IPAddressOrRanges.
     */
  }
  
#error not finished
 err:
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
