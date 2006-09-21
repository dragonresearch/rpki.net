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
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/safestack.h>

static X509 *read_cert(const char *filename, int format, int verbose)
{
  X509 *x = NULL;
  BIO *b;

  if ((b = BIO_new_file(filename, "r")) == NULL)
    goto done;

  switch (format) {
  case 'p':
    x = PEM_read_bio_X509_AUX(b, NULL, NULL, NULL);
    break;
  case 'd':
    x = d2i_X509_bio(b, NULL);
    break;
  }

  if (verbose && x != NULL) {
    X509_print_fp(stdout, x);
    printf("\n");
  }


 done:
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
  decode_wrong_method
};

#define	lose(_err_) do { err = _err_; goto done; } while (0)

static enum decode_errors decode_crldp(X509 *x, int verbose)
{
  enum decode_errors err = decode_ok;
  STACK_OF(DIST_POINT) *ds = X509_get_ext_d2i(x, NID_crl_distribution_points, NULL, NULL);
  DIST_POINT *d;
  GENERAL_NAME *n;
  int i;

  if (!ds)
    lose(decode_no_extension);

  if (sk_DIST_POINT_num(ds) != 1)
    lose(decode_not_exactly_one_DistributionPointName);

  d = sk_DIST_POINT_value(ds, 0);

  if (d->reasons)
    lose(decode_has_reasons);

  if (d->CRLissuer)
    lose(decode_has_CRLissuer);

  if (!d->distpoint)
    lose(decode_no_distributionPoint);

  if (d->distpoint->type != 0)
    lose(decode_not_GeneralName);

  for (i = 0; i < sk_GENERAL_NAME_num(d->distpoint->name.fullname); i++) {
    n = sk_GENERAL_NAME_value(d->distpoint->name.fullname, i);
    if (n->type != GEN_URI) 
      lose(decode_not_GeneralName);
    if (!strncmp(n->d.uniformResourceIdentifier->data,
		 "rsync://", sizeof("rsync://") - 1)) {
      printf("CRL: %s\n", n->d.uniformResourceIdentifier->data);
      goto done;
    }
  }

 done:
  sk_DIST_POINT_pop_free(ds, DIST_POINT_free);
  return err;
}

static enum decode_errors decode_access(X509 *x, int verbose, char *tag,
					int nid, unsigned char *oid,
					int oidlen)
{
  enum decode_errors err = decode_ok;
  AUTHORITY_INFO_ACCESS *as = X509_get_ext_d2i(x, nid, NULL, NULL);
  ACCESS_DESCRIPTION *a;
  int i;

  if (!as)
    lose(decode_no_extension);

  for (i = 0; i < sk_ACCESS_DESCRIPTION_num(as); i++) {
    a = sk_ACCESS_DESCRIPTION_value(as, i);
    if (a->location->type != GEN_URI)
      lose(decode_not_URI);
    if (a->method->length == oidlen &&
	!memcmp(a->method->data, oid, oidlen) &&
	!strncmp(a->location->d.uniformResourceIdentifier->data,
		 "rsync://", sizeof("rsync://") - 1)) {
      printf("%s: %s\n", tag, a->location->d.uniformResourceIdentifier->data);
      goto done;
    }
  }

 done:
  sk_ACCESS_DESCRIPTION_pop_free(as, ACCESS_DESCRIPTION_free);
  return err;
}

static void decode_aia(X509 *x, int verbose)
{
  static unsigned char oid[] = {0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x30, 0x2};
  decode_access(x, verbose, "AIA", NID_info_access, oid, sizeof(oid));
}

static void decode_sia(X509 *x, int verbose)
{
  static unsigned char oid[] = {0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x30, 0x5};
  decode_access(x, verbose, "SIA", NID_sinfo_access, oid, sizeof(oid));
}

int main(int argc, char *argv[])
{
  int c, format = 'p', ret = 0, verbose = 0;
  X509 *x;

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  while ((c = getopt(argc, argv, "pdv")) > 0) {
    switch (c) {
    case 'v':
      verbose = 1;
      break;
    case 'p':
    case 'd':
      format = c;
      break;
    default:
      fprintf(stderr, "usage: %s [-p | -d] cert [cert...]\n", argv[0]);
      ret = 1;
      goto done;
    }
  }

  argc -= optind;
  argv += optind;

  while (argc-- > 0) {
    printf("File %s\n", *argv);
    if ((x = read_cert(*argv++, format, verbose)) == NULL) {
      printf("Couldn't read certificate, skipping\n");
      continue;
    }
    decode_aia(x, verbose);
    decode_sia(x, verbose);
    decode_crldp(x, verbose);
    X509_free(x);
  }

 done:
  EVP_cleanup();
  ERR_free_strings();
  return ret;
}
