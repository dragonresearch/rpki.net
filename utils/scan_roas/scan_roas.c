/*
 * Copyright (C) 2011  Internet Systems Consortium ("ISC")
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 * Portions copyright (C) 2008  American Registry for Internet Numbers ("ARIN")
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
 * Decoder test for ROAs.
 *
 * NB: This does -not- check the CMS signatures, just the encoding.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>

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

#include <rpki/roa.h>

/*
 * How much buffer space do we need for a raw address?
 */
#define ADDR_RAW_BUF_LEN	16

/*
 * How long can a filesystem path be?
 */
#define	PATH_MAX		2048



/*
 * Extract signing time from CMS message.
 */

static char *
extract_signingTime(CMS_ContentInfo *cms, char *buffer, size_t buflen)
{
  STACK_OF(CMS_SignerInfo) *sis = NULL;
  CMS_SignerInfo *si = NULL;
  X509_ATTRIBUTE *xa = NULL;
  ASN1_TYPE *so = NULL;
  int i = -1;

  if (cms == NULL ||
      buffer == NULL ||
      buflen < sizeof("20010401123456Z") ||
      (sis = CMS_get0_SignerInfos(cms)) == NULL ||
      sk_CMS_SignerInfo_num(sis) != 1 ||
      (si = sk_CMS_SignerInfo_value(sis, 0)) < 0 ||
      (i = CMS_signed_get_attr_by_NID(si, NID_pkcs9_signingTime, -1)) < 0 ||
      (xa = CMS_signed_get_attr(si, i)) == NULL ||
      xa->single ||
      sk_ASN1_TYPE_num(xa->value.set) != 1 ||
      (so = sk_ASN1_TYPE_value(xa->value.set, 0)) == NULL)
    return NULL;

  assert(buflen > 2);
  buffer[buflen - 1] = '\0';

  switch (so->type) {
  case V_ASN1_UTCTIME:
    strcpy(buffer, (so->value.utctime->data[0] >= '5') ? "19" : "20");
    return strncpy(buffer + 2, so->value.utctime->data, buflen - 3);
  case V_ASN1_GENERALIZEDTIME:
    return strncpy(buffer, so->value.generalizedtime->data, buflen - 1);
  default:
    return NULL;
  }
}



/*
 * Expand the bitstring form of an address into a raw byte array.
 * At the moment this is coded for simplicity, not speed.
 */
static void addr_expand(unsigned char *addr,
			const ASN1_BIT_STRING *bs,
			const int length)
{
  assert(bs->length >= 0 && bs->length <= length);
  if (bs->length > 0) {
    memcpy(addr, bs->data, bs->length);
    if ((bs->flags & 7) != 0) {
      unsigned char mask = 0xFF >> (8 - (bs->flags & 7));
      addr[bs->length - 1] &= ~mask;
    }
  }
  memset(addr + bs->length, 0, length - bs->length);
}

/*
 * Extract the prefix length from a bitstring.
 */
#define addr_prefixlen(bs) ((int) ((bs)->length * 8 - ((bs)->flags & 7)))

/*
 * Read ROA (CMS object) in DER format.
 *
 * NB: When invoked this way, CMS_verify() does -not- verify, it just decodes the ASN.1.
 */
static int read_roa(const char *filename)
{
  char buffer[sizeof("20010401123456Z")], *b;
  unsigned char addr[ADDR_RAW_BUF_LEN];
  CMS_ContentInfo *cms = NULL;
  const ASN1_OBJECT *oid = NULL;
  ROA *r = NULL;
  char buf[512];
  BIO *bio;
  int i, j, k, n, ok;

  if ((bio = BIO_new_file(filename, "r")) == NULL ||
      (cms = d2i_CMS_bio(bio, NULL)) == NULL)
    goto done;
  BIO_free(bio);

  if ((bio = BIO_new(BIO_s_mem())) == NULL ||
      CMS_verify(cms, NULL, NULL, NULL, bio, CMS_NOCRL | CMS_NO_SIGNER_CERT_VERIFY | CMS_NO_ATTR_VERIFY | CMS_NO_CONTENT_VERIFY) <= 0 ||
      (r = ASN1_item_d2i_bio(ASN1_ITEM_rptr(ROA), bio, NULL)) == NULL)
    goto done;

  if (!extract_signingTime(cms, buffer, sizeof(buffer)))
    goto done;
  printf("%s ", buffer);

  printf("%ld", ASN1_INTEGER_get(r->asID));

  for (i = 0; i < sk_ROAIPAddressFamily_num(r->ipAddrBlocks); i++) {

    ROAIPAddressFamily *f = sk_ROAIPAddressFamily_value(r->ipAddrBlocks, i);

    unsigned afi = (f->addressFamily->data[0] << 8) | (f->addressFamily->data[1]);

    for (j = 0; j < sk_ROAIPAddress_num(f->addresses); j++) {
      ROAIPAddress *a = sk_ROAIPAddress_value(f->addresses, j);

      printf(" ");

      switch (afi) {

      case IANA_AFI_IPV4:
	addr_expand(addr, a->IPAddress, 4);
	printf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3]);
	break;

      case IANA_AFI_IPV6:
	addr_expand(addr, a->IPAddress, 16);
	for (n = 16; n > 1 && addr[n-1] == 0x00 && addr[n-2] == 0x00; n -= 2)
	  ;
	for (k = 0; k < n; k += 2)
	  printf("%x%s", (addr[k] << 8) | addr[k+1], (k < 14 ? ":" : ""));
	if (k < 16)
	  printf(":");
	if (k == 0)
	  printf(":");
	break;

      default:
	break;
      }

      printf("/%u", addr_prefixlen(a->IPAddress));

      if (a->maxLength)
	printf("-%ld", ASN1_INTEGER_get(a->maxLength));
    }
  }
  printf("\n");

 done:
  ok = r != NULL;

  if (ERR_peek_error())
    ERR_print_errors_fp(stderr);
  BIO_free(bio);
  CMS_ContentInfo_free(cms);
  ROA_free(r);

  return ok;
}



/**
 * Check str for a trailing suffix.
 */
static int endswith(const char *str, const char *suffix)
{
  size_t len_str, len_suffix;
  assert(str != NULL && suffix != NULL);
  len_str = strlen(str);
  len_suffix = strlen(suffix);
  return len_str >= len_suffix && !strcmp(str + len_str - len_suffix, suffix);
}



/**
 * Walk directory tree, looking for ROAs.
 */
static int walk(const char *name)
{
  int need_slash, ok = 1;
  char path[PATH_MAX];
  struct dirent *d;
  size_t len;
  DIR *dir;

  assert(name);
  len = strlen(name);

  assert(len > 0 && len < sizeof(path));
  need_slash = name[len - 1] != '/';

  if ((dir = opendir(name)) == NULL)
    return 0;

  while ((d = readdir(dir)) != NULL) {
    if (!strcmp(d->d_name, ".") ||
	!strcmp(d->d_name, ".."))
      continue;
    if (len + strlen(d->d_name) + need_slash >= sizeof(path)) {
      ok = 0;
      goto done;
    }
    strcpy(path, name);
    if (need_slash)
      strcat(path, "/");
    strcat(path, d->d_name);
    switch (d->d_type) {
    case DT_DIR:
      ok &= walk(path);
      continue;
    default:
      if (endswith(path, ".roa"))
	ok &= read_roa(path);
      continue;
    }
  }

 done:
  closedir(dir);
}



/*
 * Main program.
 */
int main (int argc, char *argv[])
{
  int i, ok = 1;

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  for (i = 1; i < argc; i++)
    ok &= walk(argv[i]);

  return !ok;
}
