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

#define	lose(msg) do { printf("Lost: %s\n", msg); goto done; } while (0)

static void decode_crldp(X509 *x, int verbose)
{
  STACK_OF(DIST_POINT) *ds = X509_get_ext_d2i(x, NID_crl_distribution_points, NULL, NULL);
  DIST_POINT *d;
  GENERAL_NAME *n;
  char *s;
  int i;

  if (!ds)
    lose("No CRLDP sequence");

  if (sk_DIST_POINT_num(ds) != 1)
    lose("CRLDP sequence does not have exactly one member");

  d = sk_DIST_POINT_value(ds, 0);

  if (d->reasons)
    lose("CRLDP has reasons");

  if (d->CRLissuer)
    lose("CRLDP has CRLissuer");

  if (!d->distpoint)
    lose("CRLDP has no distributionPoint");

  if (d->distpoint->type != 0)
    lose("CRLDP does not contain general names");

  for (i = 0; i < sk_GENERAL_NAME_num(d->distpoint->name.fullname); i++) {
    n = sk_GENERAL_NAME_value(d->distpoint->name.fullname, i);
    if (n->type != GEN_URI) {
      printf("CRDLP name %d is type %d, not URI, skipping\n", i, n->type);
      continue;
    }
    s = n->d.uniformResourceIdentifier->data;
    if (strncmp(s, "rsync://", sizeof("rsync://") - 1)) {
      printf("CRLDP name %d is not an rsync URI, skipping\n", i);
      continue;
    }
    printf("CRLDP name %d: \"%s\"\n", i, s);
  }

 done:
  sk_DIST_POINT_pop_free(ds, DIST_POINT_free);
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
#if 0
    decode_aia(x, verbose);
    decode_sia(x, verbose);
#endif
    decode_crldp(x, verbose);
    X509_free(x);
  }

 done:
  EVP_cleanup();
  ERR_free_strings();
  return ret;
}
