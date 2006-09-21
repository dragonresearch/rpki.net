/* $Id$ */

#include <stdio.h>
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

#if 0

  if (x->rfc3779_addr == NULL)
    x->rfc3779_addr = X509_get_ext_d2i(x, NID_sbgp_ipAddrBlock,
				       NULL, NULL);

  if (x->rfc3779_asid == NULL)
    x->rfc3779_asid = X509_get_ext_d2i(x, NID_sbgp_autonomousSysNum,
				       NULL, NULL);

#else

  /*
   * We run this for the side-effect of calling x509v3_cache_extensions()
   */
  X509_check_ca(x);

#endif

 done:
  BIO_free(b);
  return x;
}

static void *parse_resource_set(int nid, char *text, int verbose)
{
  X509_EXTENSION *ext;
  void *result;

  if ((ext = X509V3_EXT_conf_nid(NULL, NULL, nid, text)) == NULL)
    return NULL;

  if (verbose) {
    printf("Parsed resource set:\n");
    X509V3_EXT_print_fp(stdout, ext, 0, 3);
    printf("\n");
  }

  result = X509V3_EXT_d2i(ext);
  X509_EXTENSION_free(ext);
  return result;
}

#define lose(_msg_)					\
  do {							\
    if (_msg_)						\
      fprintf(stderr, "%s: %s\n", argv[0], _msg_);	\
    ret = 1;						\
    goto done;						\
  } while(0)

int main(int argc, char *argv[])
{
  STACK_OF(X509) *chain = NULL;
  ASIdentifiers *asid = NULL;
  IPAddrBlocks *addr = NULL;
  int c, ret = 0, verbose = 0;
  X509 *x;

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  if ((chain = sk_X509_new_null()) == NULL)
    lose("Couldn't allocate X509 stack");

  while ((c = getopt(argc, argv, "p:d:a:i:v")) > 0) {
    switch (c) {
    case 'v':
      verbose = 1;
      break;
    case 'p':
    case 'd':
      if ((x = read_cert(optarg, c, verbose)) == NULL)
	lose("Couldn't read certificate");
      sk_X509_push(chain, x);
      break;
    case 'a':
      if (asid != NULL)
	lose("Can't specify more than one ASIdentifier");
      if ((asid = parse_resource_set(NID_sbgp_autonomousSysNum, optarg, verbose)) == NULL)
	lose("Couldn't read ASIdentifier");
      break;
    case 'i':
      if (addr != NULL)
	lose("Can't specify more than one IPAddrBlock");
      if ((addr = parse_resource_set(NID_sbgp_ipAddrBlock, optarg, verbose)) == NULL)
	lose("Couldn't read IPAddrBlock");
      break;
    default:
      fprintf(stderr, "usage: %s"
	      " [-i IPAddrBlock] [-a ASIdentifier]"
	      " [-p PEM-certfile] [-d DER-certfile]\n", argv[0]);
      ret = 1;
      goto done;
    }
  }

  printf("Checking ASIdentifier coverage...");
  if (v3_asid_validate_resource_set(chain, asid, 0))
    printf("covered\n");
  else
    printf("NOT covered\n");
  
  printf("Checking IPAddrBlock coverage...");
  if (v3_addr_validate_resource_set(chain, addr, 0))
    printf("covered\n");
  else
    printf("NOT covered\n");

 done:
  sk_X509_pop_free(chain, X509_free);
  EVP_cleanup();
  ERR_free_strings();
  return ret;
}
