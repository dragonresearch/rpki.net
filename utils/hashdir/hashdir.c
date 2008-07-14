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
 * Read a directory tree of DER certificates and CRLs and copy
 * them into a PEM format directory with names in the hash format
 * that OpenSSL's lookup routines expect.
 */

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
#include <openssl/x509.h>

#ifndef FILENAME_MAX
#define	FILENAME_MAX	1024
#endif

static int verbose = 1;

/*
 * Error handling.
 */

#define _lose(_msg_, _file_)			\
  do {						\
    fprintf(stderr, "%s: %s\n", _msg_, _file_);	\
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
static void file_handler(const char *filename, const char *targetdir)
{
  char path[FILENAME_MAX];
  unsigned long hash;
  const char *fmt;
  X509_CRL *crl = NULL;
  X509 *cer = NULL;
  BIO *b = NULL;
  int i, is_crl;

  if (has_suffix(filename, ".cer"))
    is_crl = 0;
  else if (has_suffix(filename, ".crl"))
    is_crl = 1;
  else
    return;			/* Ignore if neither certificate nor CRL */

  if (verbose)
    printf("Reading %s\n", filename);

  if (!(b = BIO_new_file(filename, "rb")))
    lose_openssl("Couldn't open input file", filename);

  if (is_crl
      ? !(crl = d2i_X509_CRL_bio(b, NULL))
      : !(cer = d2i_X509_bio(b, NULL)))
    lose_openssl("Couldn't read DER object", filename);

  BIO_free(b);
  b = NULL;

  if (is_crl) {
    hash = X509_NAME_hash(X509_CRL_get_issuer(crl));
    fmt = "%s/%08lx.r%d";
  } else {
    hash = X509_subject_name_hash(cer);
    fmt = "%s/%08lx.%d";
  }

  for (i = 0; i < INT_MAX; i++)
    if (snprintf(path, sizeof(path), fmt, targetdir, hash, i) == sizeof(path))
      lose("Path too long", filename);
    else if (access(path, F_OK))
      break;
  if (i == INT_MAX)
    lose("No pathname available", filename);

  if (verbose)
    printf("Writing %s\n", path);

  if (!(b = BIO_new_file(path, "w")))
    lose_openssl("Couldn't open output file", path);

  if (is_crl
      ? !PEM_write_bio_X509_CRL(b, crl)
      : !PEM_write_bio_X509(b, cer))
    lose_openssl("Couldn't write PEM object", path);

 done:
  X509_free(cer);
  X509_CRL_free(crl);
  BIO_free(b);
}

/*
 * Walk a directory tree
 */
static int handle_directory(const char *name, const char *targetdir)
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
      if (!handle_directory(path, targetdir))
	lose("Directory walk failed", path);
      continue;
    default:
      file_handler(path, targetdir);
      continue;
    }
  }

  ret = 1;

 done:
  if (dir)
    closedir(dir);
  return ret;
}

int main(int argc, char *argv[])
{
  if (argc != 3) {
    fprintf(stderr, "usage: %s input-directory output-directory\n", argv[0]);
    return 1;
  }

  return !handle_directory(argv[1], argv[2]);
}
