/*
 * Copyright (C) 2008  American Registry for Internet Numbers ("ARIN")
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
 * Decoder test for RPKI manifests.
 *
 * NB: This does -not- check the CMS signatures, just the encoding.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>

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

/*
 * ASN.1 templates for signed manifests.  Not sure that ASN1_EXP_OPT()
 * is the right macro for "version", but it's what the examples for
 * this construction use.  Probably doesn't matter since this program
 * only decodes manifests, never encodes them.
 */

typedef struct FileAndHash_st {
  ASN1_IA5STRING *file;
  ASN1_BIT_STRING *hash;
} FileAndHash;

ASN1_SEQUENCE(FileAndHash) = {
  ASN1_SIMPLE(FileAndHash, file, ASN1_IA5STRING),
  ASN1_SIMPLE(FileAndHash, hash, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(FileAndHash)

DECLARE_STACK_OF(FileAndHash)
DECLARE_ASN1_FUNCTIONS(FileAndHash)

#define sk_FileAndHash_num(st)		SKM_sk_num(FileAndHash, (st))
#define sk_FileAndHash_value(st, i)	SKM_sk_value(FileAndHash, (st), (i))

typedef struct Manifest_st {
  ASN1_INTEGER *version, *manifestNumber;
  ASN1_GENERALIZEDTIME *thisUpdate, *nextUpdate;
  ASN1_OBJECT *fileHashAlg;
  STACK_OF(FileAndHash) *fileList;
} Manifest;

ASN1_SEQUENCE(Manifest) = {
  ASN1_EXP_OPT(Manifest, version, ASN1_INTEGER, 0),
  ASN1_SIMPLE(Manifest, manifestNumber, ASN1_INTEGER),
  ASN1_SIMPLE(Manifest, thisUpdate, ASN1_GENERALIZEDTIME),
  ASN1_SIMPLE(Manifest, nextUpdate, ASN1_GENERALIZEDTIME),
  ASN1_SIMPLE(Manifest, fileHashAlg, ASN1_OBJECT),
  ASN1_SEQUENCE_OF(Manifest, fileList, FileAndHash)
} ASN1_SEQUENCE_END(Manifest)

/*
 * Read manifest (CMS object) in DER format.
 *
 * NB: When invoked this way, CMS_verify() does -not- verify, it just decodes the ASN.1.
 */
static const Manifest *read_manifest(const char *filename, const int print_cms, const int print_manifest, const int print_signerinfo)
{
  CMS_ContentInfo *cms = NULL;
  const ASN1_OBJECT *oid = NULL;
  const Manifest *m = NULL;
  char buf[512];
  BIO *b;
  int i, j;

  if ((b = BIO_new_file(filename, "r")) == NULL ||
      (cms = d2i_CMS_bio(b, NULL)) == NULL)
    goto done;
  BIO_free(b);

  if (print_signerinfo) {
    STACK_OF(CMS_SignerInfo) *signerInfos = CMS_get0_SignerInfos(cms);
    for (i = 0; i < sk_CMS_SignerInfo_num(signerInfos); i++) {
      ASN1_OCTET_STRING *hash = NULL;
      if (CMS_SignerInfo_get0_signer_id(sk_CMS_SignerInfo_value(signerInfos, i), &hash, NULL, NULL)) {
	printf("SignerId[%d]:    ", i);
	for (j = 0; j < hash->length; j++)
	  printf("%02x%s", hash->data[j], j == hash->length - 1 ? "\n" : ":");
      }
    }
  }

  if (print_cms) {
    if ((b = BIO_new(BIO_s_fd())) == NULL)
      goto done;
    BIO_set_fd(b, 1, BIO_NOCLOSE);
    CMS_ContentInfo_print_ctx(b, cms, 0, NULL);
    BIO_free(b);
  }

  if ((b = BIO_new(BIO_s_mem())) == NULL ||
      CMS_verify(cms, NULL, NULL, NULL, b, CMS_NOCRL | CMS_NO_SIGNER_CERT_VERIFY | CMS_NO_ATTR_VERIFY | CMS_NO_CONTENT_VERIFY) <= 0 ||
      (m = ASN1_item_d2i_bio(ASN1_ITEM_rptr(Manifest), b, NULL)) == NULL)
    goto done;

  if (print_manifest) {

    if ((oid = CMS_get0_eContentType(cms)) == NULL)
      goto done;
    OBJ_obj2txt(buf, sizeof(buf), oid, 0);
    printf("eContentType:   %s\n", buf);

    if (m->version)
      printf("version:        %ld\n", ASN1_INTEGER_get(m->version));
    else
      printf("version:        0 [defaulted]\n");
    printf("manifestNumber: %ld\n", ASN1_INTEGER_get(m->manifestNumber));
    printf("thisUpdate:     %s\n", m->thisUpdate->data);
    printf("nextUpdate:     %s\n", m->nextUpdate->data);
    OBJ_obj2txt(buf, sizeof(buf), m->fileHashAlg, 0);
    printf("fileHashAlg:    %s\n", buf);

    for (i = 0; i < sk_FileAndHash_num(m->fileList); i++) {
      FileAndHash *fah = sk_FileAndHash_value(m->fileList, i);
      printf("fileList[%3d]:  ", i);
      for (j = 0; j < fah->hash->length; j++)
	printf("%02x%s", fah->hash->data[j], j == fah->hash->length - 1 ? " " : ":");
      printf(" %s\n", fah->file->data);
    }

    if (X509_cmp_current_time(m->nextUpdate) < 0)
      printf("MANIFEST HAS EXPIRED\n");
  }

 done:
  if (ERR_peek_error())
    ERR_print_errors_fp(stderr);
  BIO_free(b);
  CMS_ContentInfo_free(cms);
  return m;
}

/*
 * Main program.
 */
int main (int argc, char *argv[])
{
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  return read_manifest(argv[1], 0, 1, 1) == NULL;
}
