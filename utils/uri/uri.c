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

/*
 * Extract and test URIs from certificates.  This is a unit test of
 * rcynic code, a utility, or both, depending on how it turns out.
 *
 * NB: OpenSSL insures that IA5 strings are null-terminated, so it's safe
 * for us to ignore the length count.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/cms.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/safestack.h>

static const unsigned char id_ad_caIssuers[] =              {0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x30, 0x2}; /* 1.3.6.1.5.5.7.48.2 */
static const unsigned char id_ad_caRepository[] =           {0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x30, 0x5}; /* 1.3.6.1.5.5.7.48.5 */
static const unsigned char id_ad_signedObjectRepository[] = {0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x30, 0x9}; /* 1.3.6.1.5.5.7.48.9 */
static const unsigned char id_ad_rpkiManifest[] =           {0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x30, 0xa}; /* 1.3.6.1.5.5.7.48.10 */
static const unsigned char id_ad_signedObject[] =           {0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x30, 0xb}; /* 1.3.6.1.5.5.7.48.11 */

static X509 *read_cert(const char *filename, int format, int verbose)
{
  BIO *b = BIO_new_file(filename, "r");
  STACK_OF(X509) *certs = NULL;
  CMS_ContentInfo *cms = NULL;
  X509 *x = NULL;

  if (b == NULL)
    return NULL;

  switch (format) {
  case 'p':
    x = PEM_read_bio_X509(b, NULL, NULL, NULL);
    break;
  case 'd':
    x = d2i_X509_bio(b, NULL);
    break;
  }

  if (x == NULL) {
    BIO_reset(b);
    switch (format) {
    case 'p':
      cms = PEM_read_bio_CMS(b, NULL, NULL, NULL);
      break;
    case 'd':
      cms = d2i_CMS_bio(b, NULL);
      break;
    }
    if (cms != NULL && (certs = CMS_get1_certs(cms)) != NULL)
      x = sk_X509_shift(certs);
  }

  if (x != NULL && verbose) {
    X509_print_fp(stdout, x);
    printf("\n");
  }
  
  sk_X509_pop_free(certs, X509_free);
  CMS_ContentInfo_free(cms);
  BIO_free(b);
  return x;
}

enum decode_errors {
  decode_ok,
  decode_no_extension,
  decode_not_exactly_one_DistributionPointName,
  decode_has_reasons,
  decode_has_CRLissuer,
  decode_no_distributionPoint,
  decode_not_GeneralName,
  decode_not_URI,
};

static enum decode_errors decode_crldp(X509 *x, int verbose, int spaces)
{
  enum decode_errors err = decode_ok;
  STACK_OF(DIST_POINT) *ds = X509_get_ext_d2i(x, NID_crl_distribution_points, NULL, NULL);
  DIST_POINT *d;
  GENERAL_NAME *n;
  int i;

  if (!ds) {
    err = decode_no_extension;
  } else if (sk_DIST_POINT_num(ds) != 1) {
    err = decode_not_exactly_one_DistributionPointName;
  } else if ((d = sk_DIST_POINT_value(ds, 0))->reasons) {
    err = decode_has_reasons;
  } else if (d->CRLissuer) {
    err = decode_has_CRLissuer;
  } else if (!d->distpoint) {
    err = decode_no_distributionPoint;
  } else if (d->distpoint->type != 0) {
    err = decode_not_GeneralName;
  } else {
    for (i = 0; i < sk_GENERAL_NAME_num(d->distpoint->name.fullname); i++) {
      n = sk_GENERAL_NAME_value(d->distpoint->name.fullname, i);
      if (n->type != GEN_URI) {
	err = decode_not_GeneralName;
	break;
      }
      printf(" CRLDP: %s%s", n->d.uniformResourceIdentifier->data, spaces ? "" : "\n");
    }
  }

  sk_DIST_POINT_pop_free(ds, DIST_POINT_free);
  return err;
}

#define decode_xia(_x_, _v_, _s_, _tag_, _nid_, _oid_)  _decode_xia(_x_, _v_, _s_, _tag_, _nid_, _oid_, sizeof(_oid_))

static enum decode_errors _decode_xia(X509 *x,
				      int verbose,
				      int spaces,
				      char *tag,
				      int nid,
				      const unsigned char *oid,
				      int oidlen)
{
  enum decode_errors err = decode_ok;
  AUTHORITY_INFO_ACCESS *as = X509_get_ext_d2i(x, nid, NULL, NULL);
  ACCESS_DESCRIPTION *a;
  int i;

  if (!as) {
    err = decode_no_extension;
  } else {
    for (i = 0; i < sk_ACCESS_DESCRIPTION_num(as); i++) {
      a = sk_ACCESS_DESCRIPTION_value(as, i);
      if (a->location->type != GEN_URI) {
	err = decode_not_URI;
	break;
      }
      if (a->method->length == oidlen && !memcmp(a->method->data, oid, oidlen))
	printf(" %s: %s%s", tag, a->location->d.uniformResourceIdentifier->data, spaces ? "" : "\n");
    }
  }

  sk_ACCESS_DESCRIPTION_pop_free(as, ACCESS_DESCRIPTION_free);
  return err;
}

int main(int argc, char *argv[])
{
  int c, format = 'd', spaces = 0, ret = 0, verbose = 0;
  X509 *x;

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  while ((c = getopt(argc, argv, "pdsv")) > 0) {
    switch (c) {
    case 'v':
      verbose = 1;
      break;
    case 'p':
    case 'd':
      format = c;
      break;
    case 's':
      spaces = 1;
      break;
    default:
      ret = 1;
    }
  }

  if (argc == optind)
    ret = 1;

  if (ret != 0)
    fprintf(stderr, "usage: %s [-p | -d] cert [cert...]\n", argv[0]);

  if (ret == 0) {
    argc -= optind;
    argv += optind;

    while (argc-- > 0) {
      printf(spaces ? "%s" : "File: %s\n", *argv);
      if ((x = read_cert(*argv++, format, verbose)) == NULL) {
	printf("Couldn't read certificate, skipping\n");
	continue;
      }
      decode_xia(x, verbose, spaces, "AIA:caIssuers",              NID_info_access,  id_ad_caIssuers);
      decode_xia(x, verbose, spaces, "SIA:caRepository",           NID_sinfo_access, id_ad_caRepository);
      decode_xia(x, verbose, spaces, "SIA:signedObjectRepository", NID_sinfo_access, id_ad_signedObjectRepository);
      decode_xia(x, verbose, spaces, "SIA:rpkiManifest",           NID_sinfo_access, id_ad_rpkiManifest);
      decode_xia(x, verbose, spaces, "SIA:signedObject",           NID_sinfo_access, id_ad_signedObject);
      decode_crldp(x, verbose, spaces);
      if (spaces)
	putchar('\n');
      X509_free(x);
    }
  }

  EVP_cleanup();
  ERR_free_strings();
  return ret;
}
