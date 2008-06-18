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
 * Test of using BIO_f_md() filter BIO to calculate hash while reading.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

int main (int argc, char *argv[])
{
  BIO *b1 = NULL, *b2 = NULL;
  X509 *x = NULL;
  unsigned char buf[EVP_MAX_MD_SIZE];
  unsigned i, n;

  if ((b1 = BIO_new_file(argv[1], "rb")) == NULL)
    goto done;

  if ((b2 = BIO_new(BIO_f_md())) == NULL)
    goto done;

  if (!BIO_set_md(b2, EVP_sha256()))
    goto done;

  BIO_push(b2, b1);
  
  if ((x = d2i_X509_bio(b2, NULL)) == NULL)
    goto done;

  if (X509_print_fp(stdout, x) < 0)
    goto done;

  if ((n = BIO_gets(b2, buf, sizeof(buf))) > 0) {
    printf("\nsha26[%u]: ", n);
    for (i = 0; i < n; i++) {
      printf("%02x%s", buf[i], i == n - 1 ? "\n" : ":");
    }
  }
  
 done:
  if (ERR_peek_error())
    ERR_print_errors_fp(stderr);

  BIO_free_all(b2);

  return 0;
}
