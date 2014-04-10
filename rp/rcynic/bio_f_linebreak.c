/* $Id$ */

/** @file bio_f_linebreak.c
 *
 * This implements a trivial filter BIO (see OpenSSL manual) which
 * does one rather silly thing: on read, it inserts line break into
 * the input stream at regular intervals.
 *
 * You might reasonably ask why anyone would want such a thing.  The
 * answer is that OpenSSL's Base64 filter BIO has two input modes,
 * neither of which is really useful for reading generalized Base64
 * input.  In one mode, it requires line breaks at most every 79
 * characters; in the other mode, it requires that there to be no
 * whitespace of any kind at all.  These modes work for the things
 * that OpenSSL itself does with Base64 decoding, but fail miserably
 * when used to read free-form Base64 text.
 *
 * The real solution would be to rewrite OpenSSL's Base64 filter to
 * support a third mode in which it accepts generalized Base64 text,
 * but that's been suggested before and nothing has been done about
 * it, probably because OpenSSL's Base64 implementation is completely
 * line-oriented and rather nasty.
 *
 * So this filter is a stop-gap to let us get the job done.  Since it
 * uses a (relatively) well-defined OpenSSL internal API, it should be
 * reasonably stable.
 *
 * 98% of the code in this module is derived from "null filter" BIO
 * that ships with OpenSSL (BIO_TYPE_NULL_FILTER), so I consider this
 * to be a derivative work, thus am leaving it under OpenSSL's license.
 */

/* Original crypto/bio/bf_null.c code was:
 *
 * Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <openssl/bio.h>

#include "bio_f_linebreak.h"

#ifndef BIO_TYPE_LINEBREAK_FILTER
#define	BIO_TYPE_LINEBREAK_FILTER	(99 | BIO_TYPE_FILTER)
#endif

#ifndef LINEBREAK_MAX_LINE
#define	LINEBREAK_MAX_LINE	72	/* We break anything longer than this */
#endif

static int linebreak_new(BIO *b)
{
  b->init = 1;
  b->ptr = NULL;
  b->flags = 0;
  b->num = 0;
  return 1;
}

static int linebreak_free(BIO *b)
{
  return b != NULL;
}

static int linebreak_read(BIO *b, char *out, int outl)
{
  int ret = 0, want, n, i;

  if (out == NULL || b->next_bio == NULL || outl <= 0)
    return 0;

  while (outl > 0) {

    if (b->num >= LINEBREAK_MAX_LINE) {
      b->num = 0;
      *out++ = '\n';
      outl--;
      ret++;
      continue;
    }

    want = LINEBREAK_MAX_LINE - b->num;
    if (want > outl)
      want = outl;

    n = BIO_read(b->next_bio, out, want);

    BIO_clear_retry_flags(b);
    BIO_copy_next_retry(b);

    if (n > 0) {
      for (i = n - 1; i >= 0; i--)
	if (out[i] == '\n')
	  break;
      if (i >= 0)
	b->num = n - i - 1;
      else
	b->num += n;
      out += n;
      outl -= n;
      ret += n;
      continue;
    }

    if (ret == 0)
      ret = n;
    break;
  }

  return ret;
}

static int linebreak_write(BIO *b, const char *in, int inl)
{
  int ret = 0;

  if (in == NULL || inl <= 0 || b->next_bio == NULL)
    return 0;

  ret = BIO_write(b->next_bio, in, inl);

  BIO_clear_retry_flags(b);
  BIO_copy_next_retry(b);

  return ret;
}

static long linebreak_ctrl(BIO *b, int cmd, long num, void *ptr)
{
  long ret;

  if (b->next_bio == NULL)
    return 0;

  switch (cmd) {

  case BIO_C_DO_STATE_MACHINE:
    BIO_clear_retry_flags(b);
    ret = BIO_ctrl(b->next_bio, cmd, num, ptr);
    BIO_copy_next_retry(b);
    return ret;

  case BIO_CTRL_DUP:
    return 0;

  default:
    return BIO_ctrl(b->next_bio, cmd, num, ptr);

  }
}

static long linebreak_callback_ctrl(BIO *b, int cmd, bio_info_cb *cb)
{
  if (b->next_bio == NULL)
    return 0;
  else
    return BIO_callback_ctrl(b->next_bio, cmd, cb);
}

static int linebreak_puts(BIO *b, const char *str)
{
  if (b->next_bio == NULL)
    return 0;
  else
    return BIO_puts(b->next_bio, str);
}

static BIO_METHOD methods_linebreak = {
  BIO_TYPE_LINEBREAK_FILTER,
  "Linebreak filter",
  linebreak_write,
  linebreak_read,
  linebreak_puts,
  NULL,				/* No linebreak_gets() */
  linebreak_ctrl,
  linebreak_new,
  linebreak_free,
  linebreak_callback_ctrl,
};

BIO_METHOD *BIO_f_linebreak(void)
{
  return &methods_linebreak;
}


#ifdef __BIO_F_LINEBREAK_UNIT_TEST__

int main (int argc, char *argv[])
{
  BIO *ich = BIO_new_fd(0, 1);
  BIO *och = BIO_new_fd(1, 1);
  BIO *fch = BIO_new(BIO_f_linebreak());
  char buffer[4098];
  int n;

  if (ich == NULL || och == NULL || fch == NULL)
    return 1;

  BIO_push(fch, ich);
  ich = fch;
  fch = NULL;

  while ((n = BIO_read(ich, buffer, sizeof(buffer))) > 0)
    BIO_write(och, buffer, n);

  BIO_free_all(ich);
  BIO_free_all(och);
  return 0;
}

#endif
