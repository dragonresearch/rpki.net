/*
 * Copyright (C) 2006--2008  American Registry for Internet Numbers ("ARIN")
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

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <limits.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/safestack.h>
#include <openssl/conf.h>
#include <openssl/rand.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/cms.h>

#ifndef FILENAME_MAX
#define	FILENAME_MAX		1024
#endif

#ifndef ADDR_RAW_BUF_LEN
#define ADDR_RAW_BUF_LEN	16
#endif



/*
 * ASN.1 templates.  Not sure that ASN1_EXP_OPT() is the right macro
 * for these defaulted "version" fields, but it's what the examples
 * for this construction use.  Probably doesn't matter since this
 * program only decodes manifests, never encodes them.
 */

typedef struct ROAIPAddress_st {
  ASN1_BIT_STRING *IPAddress;
  ASN1_INTEGER *maxLength;
} ROAIPAddress;

DECLARE_STACK_OF(ROAIPAddress)

ASN1_SEQUENCE(ROAIPAddress) = {
  ASN1_SIMPLE(ROAIPAddress, IPAddress, ASN1_BIT_STRING),
  ASN1_EXP_OPT(ROAIPAddress, maxLength, ASN1_INTEGER, 0)
} ASN1_SEQUENCE_END(ROAIPAddress)

typedef struct ROAIPAddressFamily_st {
  ASN1_OCTET_STRING *addressFamily;
  STACK_OF(ROAIPAddress) *addresses;
} ROAIPAddressFamily;

DECLARE_STACK_OF(ROAIPAddressFamily)

ASN1_SEQUENCE(ROAIPAddressFamily) = {
  ASN1_SIMPLE(ROAIPAddressFamily, addressFamily, ASN1_OCTET_STRING),
  ASN1_SEQUENCE_OF(ROAIPAddressFamily, addresses, ROAIPAddress)
} ASN1_SEQUENCE_END(ROAIPAddressFamily)

typedef struct ROA_st {
  ASN1_INTEGER *version, *asID;
  STACK_OF(ROAIPAddressFamily) *ipAddrBlocks;
} ROA;

ASN1_SEQUENCE(ROA) = {
  ASN1_EXP_OPT(ROA, version, ASN1_INTEGER, 0),
  ASN1_SIMPLE(ROA, asID, ASN1_INTEGER),
  ASN1_SEQUENCE_OF(ROA, ipAddrBlocks, ROAIPAddressFamily)
} ASN1_SEQUENCE_END(ROA)

DECLARE_ASN1_FUNCTIONS(ROAIPAddress)
DECLARE_ASN1_FUNCTIONS(ROAIPAddressFamily)
DECLARE_ASN1_FUNCTIONS(ROA)

IMPLEMENT_ASN1_FUNCTIONS(ROAIPAddress)
IMPLEMENT_ASN1_FUNCTIONS(ROAIPAddressFamily)
IMPLEMENT_ASN1_FUNCTIONS(ROA)

#define sk_ROAIPAddress_new(st)				SKM_sk_new(ROAIPAddress, (st))
#define sk_ROAIPAddress_new_null()			SKM_sk_new_null(ROAIPAddress)
#define sk_ROAIPAddress_free(st)			SKM_sk_free(ROAIPAddress, (st))
#define sk_ROAIPAddress_num(st)				SKM_sk_num(ROAIPAddress, (st))
#define sk_ROAIPAddress_value(st, i)			SKM_sk_value(ROAIPAddress, (st), (i))
#define sk_ROAIPAddress_set(st, i, val)			SKM_sk_set(ROAIPAddress, (st), (i), (val))
#define sk_ROAIPAddress_zero(st)			SKM_sk_zero(ROAIPAddress, (st))
#define sk_ROAIPAddress_push(st, val)			SKM_sk_push(ROAIPAddress, (st), (val))
#define sk_ROAIPAddress_unshift(st, val)		SKM_sk_unshift(ROAIPAddress, (st), (val))
#define sk_ROAIPAddress_find(st, val)			SKM_sk_find(ROAIPAddress, (st), (val))
#define sk_ROAIPAddress_find_ex(st, val)		SKM_sk_find_ex(ROAIPAddress, (st), (val))
#define sk_ROAIPAddress_delete(st, i)			SKM_sk_delete(ROAIPAddress, (st), (i))
#define sk_ROAIPAddress_delete_ptr(st, ptr)		SKM_sk_delete_ptr(ROAIPAddress, (st), (ptr))
#define sk_ROAIPAddress_insert(st, val, i)		SKM_sk_insert(ROAIPAddress, (st), (val), (i))
#define sk_ROAIPAddress_set_cmp_func(st, cmp)		SKM_sk_set_cmp_func(ROAIPAddress, (st), (cmp))
#define sk_ROAIPAddress_dup(st)				SKM_sk_dup(ROAIPAddress, st)
#define sk_ROAIPAddress_pop_free(st, free_func)		SKM_sk_pop_free(ROAIPAddress, (st), (free_func))
#define sk_ROAIPAddress_shift(st)			SKM_sk_shift(ROAIPAddress, (st))
#define sk_ROAIPAddress_pop(st)				SKM_sk_pop(ROAIPAddress, (st))
#define sk_ROAIPAddress_sort(st)			SKM_sk_sort(ROAIPAddress, (st))
#define sk_ROAIPAddress_is_sorted(st)			SKM_sk_is_sorted(ROAIPAddress, (st))

#define sk_ROAIPAddressFamily_new(st)			SKM_sk_new(ROAIPAddressFamily, (st))
#define sk_ROAIPAddressFamily_new_null()		SKM_sk_new_null(ROAIPAddressFamily)
#define sk_ROAIPAddressFamily_free(st)			SKM_sk_free(ROAIPAddressFamily, (st))
#define sk_ROAIPAddressFamily_num(st)			SKM_sk_num(ROAIPAddressFamily, (st))
#define sk_ROAIPAddressFamily_value(st, i)		SKM_sk_value(ROAIPAddressFamily, (st), (i))
#define sk_ROAIPAddressFamily_set(st, i, val)		SKM_sk_set(ROAIPAddressFamily, (st), (i), (val))
#define sk_ROAIPAddressFamily_zero(st)			SKM_sk_zero(ROAIPAddressFamily, (st))
#define sk_ROAIPAddressFamily_push(st, val)		SKM_sk_push(ROAIPAddressFamily, (st), (val))
#define sk_ROAIPAddressFamily_unshift(st, val)		SKM_sk_unshift(ROAIPAddressFamily, (st), (val))
#define sk_ROAIPAddressFamily_find(st, val)		SKM_sk_find(ROAIPAddressFamily, (st), (val))
#define sk_ROAIPAddressFamily_find_ex(st, val)		SKM_sk_find_ex(ROAIPAddressFamily, (st), (val))
#define sk_ROAIPAddressFamily_delete(st, i)		SKM_sk_delete(ROAIPAddressFamily, (st), (i))
#define sk_ROAIPAddressFamily_delete_ptr(st, ptr)	SKM_sk_delete_ptr(ROAIPAddressFamily, (st), (ptr))
#define sk_ROAIPAddressFamily_insert(st, val, i)	SKM_sk_insert(ROAIPAddressFamily, (st), (val), (i))
#define sk_ROAIPAddressFamily_set_cmp_func(st, cmp)	SKM_sk_set_cmp_func(ROAIPAddressFamily, (st), (cmp))
#define sk_ROAIPAddressFamily_dup(st)			SKM_sk_dup(ROAIPAddressFamily, st)
#define sk_ROAIPAddressFamily_pop_free(st, free_func)	SKM_sk_pop_free(ROAIPAddressFamily, (st), (free_func))
#define sk_ROAIPAddressFamily_shift(st)			SKM_sk_shift(ROAIPAddressFamily, (st))
#define sk_ROAIPAddressFamily_pop(st)			SKM_sk_pop(ROAIPAddressFamily, (st))
#define sk_ROAIPAddressFamily_sort(st)			SKM_sk_sort(ROAIPAddressFamily, (st))
#define sk_ROAIPAddressFamily_is_sorted(st)		SKM_sk_is_sorted(ROAIPAddressFamily, (st))



/*
 * Error handling.
 */

#define _lose(_msg_, _file_)							\
  do {										\
    if (_file_)									\
      fprintf(stderr, "%s:%d: %s: %s\n", __FILE__, __LINE__, _msg_, _file_);	\
    else									\
      fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, _msg_);		\
    fprintf(stderr, "%s: %s\n", _msg_, _file_);					\
  } while (0)

#define lose(_msg_, _file_)			\
  do {						\
    _lose(_msg_, _file_);			\
    goto done;					\
  } while (0)
 
#define lose_errno(_msg_, _file_)		\
  do {						\
    _lose(_msg_, _file_);			\
    perror(NULL);				\
    goto done;					\
  } while (0)
 
#define lose_openssl(_msg_, _file_)		\
  do {						\
    _lose(_msg_, _file_);			\
    ERR_print_errors_fp(stderr);		\
    goto done;					\
  } while (0)


/*
 * Extract a ROA prefix from the ASN.1 bitstring encoding.
 */
static int extract_roa_prefix(unsigned char *addr,
			      unsigned *prefixlen,
			      const ASN1_BIT_STRING *bs,
			      const unsigned afi)
{
  unsigned length;

  switch (afi) {
  case IANA_AFI_IPV4: length =  4; break;
  case IANA_AFI_IPV6: length = 16; break;
  default: return 0;
  }

  if (bs->length < 0 || bs->length > length)
    return 0;

  if (bs->length > 0) {
    memcpy(addr, bs->data, bs->length);
    if ((bs->flags & 7) != 0) {
      unsigned char mask = 0xFF >> (8 - (bs->flags & 7));
      addr[bs->length - 1] &= ~mask;
    }
  }

  memset(addr + bs->length, 0, length - bs->length);

  *prefixlen = (bs->length * 8) - (bs->flags & 7);

  return 1;
}

/*
 * Check str for a trailing suffix.
 */
static int has_suffix(const char *str, const char *suffix)
{
  size_t len_str, len_suffix;
  assert(str != NULL && suffix != NULL);
  len_str = strlen(str);
  len_suffix = strlen(suffix);
  return len_str >= len_suffix && !strcmp(str + len_str - len_suffix, suffix);
}

/*
 * Handle one object.
 */
static void file_handler(const char *filename, const unsigned prefix_afi, const unsigned char *prefix, const unsigned long prefixlen)
{
  unsigned char roa_prefix[ADDR_RAW_BUF_LEN];
  unsigned roa_prefixlen, roa_maxprefixlen, plen;
  CMS_ContentInfo *cms = NULL;
  BIO *b = NULL;
  ROA *r = NULL;
  int i, j, k, n;
  unsigned long asid;

  if (!(b = BIO_new_file(filename, "rb")))
    lose_openssl("Couldn't open CMS file", filename);

  if ((cms = d2i_CMS_bio(b, NULL)) == NULL)
    lose_openssl("Couldn't read CMS file", filename);

  BIO_free(b);

  if ((b = BIO_new(BIO_s_mem())) == NULL)
    lose_openssl("Couldn't open ROA", filename);

  if (CMS_verify(cms, NULL, NULL, NULL, b, CMS_NOCRL | CMS_NO_SIGNER_CERT_VERIFY | CMS_NO_ATTR_VERIFY | CMS_NO_CONTENT_VERIFY) <= 0)
    lose_openssl("Couldn't parse ROA CMS", filename);

  if ((r = ASN1_item_d2i_bio(ASN1_ITEM_rptr(ROA), b, NULL)) == NULL)
    lose_openssl("Couldn't parse ROA", filename);

  asid = (unsigned long) ASN1_INTEGER_get(r->asID);

  for (i = 0; i < sk_ROAIPAddressFamily_num(r->ipAddrBlocks); i++) {
    ROAIPAddressFamily *f = sk_ROAIPAddressFamily_value(r->ipAddrBlocks, i);

    /*
     * AFI must match, SAFI must be null
     */
    if (f->addressFamily->length != 2 ||
	prefix_afi != ((f->addressFamily->data[0] << 8) | (f->addressFamily->data[1])))
      continue;

    for (j = 0; j < sk_ROAIPAddress_num(f->addresses); j++) {
      ROAIPAddress *a = sk_ROAIPAddress_value(f->addresses, j);

      if (!extract_roa_prefix(roa_prefix, &roa_prefixlen, a->IPAddress, prefix_afi))
	lose("Malformed ROA", filename);

      /*
       * If the prefix we're looking for is bigger than the ROA
       * prefix, the ROA can't possibly cover.
       */
      if (prefixlen < roa_prefixlen)
	continue;

      if (a->maxLength)
	roa_maxprefixlen = ASN1_INTEGER_get(a->maxLength);
      else
	roa_maxprefixlen = roa_prefixlen;

      /*
       * If the prefix we're looking for is smaller than the smallest
       * allowed slice of the ROA prefix, the ROA can't possibly
       * cover.
       */
      if (prefixlen > roa_maxprefixlen)
	continue;

      /*
       * If we get this far, we have to compare prefixes.
       */
      assert(roa_prefixlen <= ADDR_RAW_BUF_LEN * 8);
      plen = prefixlen < roa_prefixlen ? prefixlen : roa_prefixlen;
      k = 0;
      while (plen >= 8 && prefix[k] == roa_prefix[k]) {
	plen -= 8;
	k++;
      }
      if (plen > 8 || ((prefix[k] ^ roa_prefix[k]) & (0xFF << (8 - plen))) != 0)
	continue;

      /*
       * If we get here, we have a match.
       */
      printf("ASN %lu prefix ", asid);
      switch (prefix_afi) {
      case IANA_AFI_IPV4:
	printf("%u.%u.%u.%u", prefix[0], prefix[1], prefix[2], prefix[3]);
	break;
      case IANA_AFI_IPV6:
	for (n = 16; n > 1 && prefix[n-1] == 0x00 && prefix[n-2] == 0x00; n -= 2)
	  ;
	for (k = 0; k < n; k += 2)
	  printf("%x%s", (prefix[k] << 8) | prefix[k+1], (k < 14 ? ":" : ""));
	if (k < 16)
	  printf(":");
	break;
      }
      printf("/%lu ROA %s\n", prefixlen, filename);
      goto done;
    }
  }

 done:
  BIO_free(b);
  CMS_ContentInfo_free(cms);
  ROA_free(r);
}

/*
 * Walk a directory tree
 */
static int handle_directory(const char *name, const unsigned prefix_afi, const unsigned char *prefix, const unsigned long prefixlen)
{
  char path[FILENAME_MAX];
  struct dirent *d;
  size_t len;
  DIR *dir;
  int ret = 0, need_slash;

  assert(name);
  len = strlen(name);
  assert(len > 0 && len < sizeof(path));
  need_slash = name[len - 1] != '/';

  if ((dir = opendir(name)) == NULL)
    lose_errno("Couldn't open directory", name);

  while ((d = readdir(dir)) != NULL) {
    if (!strcmp(d->d_name, ".") || !strcmp(d->d_name, ".."))
      continue;
    if (len + strlen(d->d_name) + need_slash >= sizeof(path))
      lose("Constructed path name too long", d->d_name);
    strcpy(path, name);
    if (need_slash)
      strcat(path, "/");
    strcat(path, d->d_name);
    switch (d->d_type) {
    case DT_DIR:
      if (!handle_directory(path, prefix_afi, prefix, prefixlen))
	lose("Directory walk failed", path);
      continue;
    default:
      if (has_suffix(path, ".roa"))
	file_handler(path, prefix_afi, prefix, prefixlen);
      continue;
    }
  }

  ret = 1;

 done:
  if (dir)
    closedir(dir);
  return ret;
}

int main (int argc, char *argv[])
{
  unsigned char prefix[ADDR_RAW_BUF_LEN];
  unsigned long prefixlen;
  unsigned afi;
  char *s = NULL, *p = NULL;
  int i, len, ret = 1;

  if (argc < 3) {
    fprintf(stderr, "usage: %s authtree prefix [prefix...]\n", argv[0]);
    return 1;
  }

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  for (i = 2; i < argc; i++) {

    if ((s = strdup(argv[i])) == NULL)
      lose("Couldn't strdup()", argv[i]);

    if ((p = strchr(s, '/')) != NULL)
      *p++ = '\0';

    len = a2i_ipadd(prefix, s);

    switch (len) {
    case  4: afi = IANA_AFI_IPV4; break;
    case 16: afi = IANA_AFI_IPV6; break;
    default: lose("Unknown AFI", argv[i]);
    }

    if (p) {
      if (*p == '\0' ||
	  (prefixlen = strtoul(p, &p, 10)) == ULONG_MAX ||
	  *p != '\0' || 
	  prefixlen > ADDR_RAW_BUF_LEN * 8)
	lose("Bad prefix length", argv[i]);
    } else  {
      prefixlen = len * 8;
    }

    assert(prefixlen <= ADDR_RAW_BUF_LEN * 8);

    free(s);
    p = s = NULL;

    if (!handle_directory(argv[1], afi, prefix, prefixlen))
      goto done;

  }

  ret = 0;

 done:
  if (s)
    free(s);
  return ret;
}
