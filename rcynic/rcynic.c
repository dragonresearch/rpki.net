/*
 * Copyright (C) 2006  American Registry for Internet Numbers ("ARIN")
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
 * "Cynical rsync": Recursively walk RPKI tree using rsync to pull
 * data from remote sites, validating certificates and CRLs as we go.
 *
 * I'll probably end up breaking this up into multiple smaller files,
 * but it's easiest to put everything in a single mongo file initially.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/file.h>
#include <errno.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <time.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/safestack.h>

typedef struct rpki_cert {
  int ca, ta;
  char *uri, *file, *sia, *aia, *crldp;
  X509 *x;
} rpki_cert_t;

static char *jane;

static STACK *rsync_cache;



/*
 * Logging functions.
 */

static void vlogmsg(char *fmt, va_list ap)
{
  char tad[30];
  time_t tad_time = time(0);
  struct tm *tad_tm = localtime(&tad_time);

  strftime(tad, sizeof(tad), "%H:%M:%S", tad_tm);
  printf("%s: ", tad);
  if (jane)
    printf("%s: ", jane);
  vprintf(fmt, ap);
  putchar('\n');
}

static void logmsg(char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  vlogmsg(fmt, ap);
  va_end(ap);
}

static void fatal(int retval, char *fmt, ...)
{
  int child = retval < 0;
  va_list ap;

  if (child)
    retval = -retval;

  if (fmt) {
    va_start(ap, fmt);
    vlogmsg(fmt, ap);
    va_end(ap);
    logmsg("Last system error: %s", strerror(errno));
    logmsg("exiting with status %d", retval);
  }

  if (child)
    _exit(retval);
  else
    exit(retval);
}



/*
 * Make a directory if it doesn't already exist.
 */

static int mkdir_maybe(char *name)
{
  char *b, buffer[FILENAME_MAX];

  assert(name != NULL);
  if (snprintf(buffer, sizeof(buffer), "%s/.", name) >= sizeof(buffer))
    return 0;
  if (access(buffer, F_OK) == 0)
    return 1;
  if ((b = strrchr(strrchr(buffer, '/'), '/')) != 0) {
    *b = '\0';
    if (!mkdir_maybe(buffer))
      return 0;
  }
  return mkdir(name, 0777) == 0;
}

/*
 * Convert an rsync URI to a filename, checking for evil character
 * sequences.
 */

static char *uri_to_filename(char *name)
{
  int n;

  if (!name || strncmp(name, "rsync://", sizeof("rsync://") - 1))
    return 0;
  name += sizeof("rsync://") - 1;
  
  if (name[0] == '/' || name[0] == '.' || !strcmp(name, "../") ||
      strstr(name, "//") || strstr(name, "/../") ||
      ((n = strlen(name)) >= 3 && !strcmp(name + n - 3, "/..")))
    return 0;

  return strdup(name);
}



/*
 * Run rsync.
 *
 * This probably isn't paranoid enough.  Should use select() to do
 * some kind of timeout when rsync is taking too long.  Breaking the
 * log stream into lines without fgets() is a pain, maybe setting
 * nonblocking I/O before calling fdopen() would suffice to let us use
 * select()?  If we time out, we need to kill() the rsync process.
 */

static char *rsync_cmd[] = {
  "rsync", "--update", "--times", "--copy-links", "--itemize-changes"
};

static int rsync_cmp(const char * const *a, const char * const *b)
{
  return strcmp(*a, *b);
}

static int rsync(char *args, ...)
{
  char *uri = 0, *path, *s, *argv[100], buffer[2000];
  int argc, pipe_fds[2], n, pid_status = -1;
  va_list ap;
  pid_t pid;
  FILE *f;

  for (argc = 0; argc < sizeof(rsync_cmd)/sizeof(*rsync_cmd); argc++)
    argv[argc] = rsync_cmd[argc];
  argv[argc] = args;
  va_start(ap, args);
  while (argv[argc++]) {
    assert(argc < sizeof(argv)/sizeof(*argv));
    argv[argc] = va_arg(ap, char *);
    if (!uri && argv[argc] && *argv[argc] != '-')
      uri = argv[argc];
  }
  va_end(ap);

  if (!uri) {
    logmsg("Couldn't extract URI from rsync command");
    return 0;
  }

  if ((path = uri_to_filename(uri)) == NULL) {
    logmsg("Couldn't extract filename from URI for rsync cache");
    return 0;
  }
    
  assert(rsync_cache != NULL);
  if ((s = sk_value(rsync_cache, sk_find(rsync_cache, path))) != NULL &&
      !strncmp(s, path, strlen(s))) {
    logmsg("Cache hit %s for URI %s, skipping rsync", s, uri);
    free(path);
    return 1;
  }

  if (pipe(pipe_fds) < 0) {
    logmsg("pipe() failed");
    return 0;
  }

  if ((f = fdopen(pipe_fds[0], "r")) == NULL) {
    logmsg("Couldn't fdopen() rsync's output stream");
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    return 0;
  }

  switch ((pid = vfork())) {
  case -1:
     logmsg("vfork() failed");
     fclose(f);
     close(pipe_fds[1]);
     return 0;
  case 0:
    close(pipe_fds[0]);
    if (dup2(pipe_fds[1], 1) < 0)
      fatal(-2, "dup2(1) failed");
    if (dup2(pipe_fds[1], 2) < 0)
      fatal(-3, "dup2(2) failed");
    execvp(argv[0], argv);
    fatal(-4, "execvp() failed");
  }

  close(pipe_fds[1]);

  while (fgets(buffer, sizeof(buffer), f)) {
    char *s = strchr(buffer, '\n');
    if (s)
      *s = '\0';
    logmsg("%s", buffer);
  }

  sk_push(rsync_cache, path);

  waitpid(pid, &pid_status, 0);

  if (WEXITSTATUS(pid_status)) {
    logmsg("rsync exited with status %d", pid_status);
    return 0;
  } else {
    return 1;
  }
}



/*
 * Extract URIs from certificate extensions.
 */

static char *extract_crldp_uri(STACK_OF(DIST_POINT) *crldp)
{
  DIST_POINT *d;
  int i;

  if (!crldp || sk_DIST_POINT_num(crldp) != 1)
    return NULL;

  d = sk_DIST_POINT_value(crldp, 0);

  if (d->reasons || d->CRLissuer || !d->distpoint || d->distpoint->type != 0)
    return NULL;

  for (i = 0; i < sk_GENERAL_NAME_num(d->distpoint->name.fullname); i++) {
    GENERAL_NAME *n = sk_GENERAL_NAME_value(d->distpoint->name.fullname, i);
    assert(n != NULL);
    if (n->type != GEN_URI)
      return NULL;
    if (!strncmp(n->d.uniformResourceIdentifier->data,
		 "rsync://", sizeof("rsync://") - 1))
      return strdup(n->d.uniformResourceIdentifier->data);
  }

  return NULL;
}

static char *extract_access_uri(AUTHORITY_INFO_ACCESS *xia,
				unsigned char *oid, int oidlen)
{
  int i;

  if (!xia)
    return NULL;

  for (i = 0; i < sk_ACCESS_DESCRIPTION_num(xia); i++) {
    ACCESS_DESCRIPTION *a = sk_ACCESS_DESCRIPTION_value(xia, i);
    assert(a != NULL);
    if (a->location->type != GEN_URI)
      return NULL;
    if (a->method->length == oidlen &&
	!memcmp(a->method->data, oid, oidlen) &&
	!strncmp(a->location->d.uniformResourceIdentifier->data,
		 "rsync://", sizeof("rsync://") - 1))
      return strdump(a->location->d.uniformResourceIdentifier->data);
  }
}



/*
 * Read certificate in DER format.
 */

static X509 *read_cert(const char *filename)
{
  X509 *x = NULL;
  BIO *b;

  if ((b = BIO_new_file(filename, "r")) != NULL)
    x = d2i_X509_bio(b, NULL);

  BIO_free(b);
  return x;
}

static void rpki_cert_free(rpki_cert_t *c)
{
  if (!c)
    return;
  X509_free(c->x);
  
}

static rpki_cert_t *rpki_cert_read(const char *filename)
{
  static unsigned char aia_oid[] = {0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x30, 0x2};
  static unsigned char sia_oid[] = {0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x30, 0x5};
  STACK_OF(DIST_POINT) *crldp;
  AUTHORITY_INFO_ACCESS *xia;
  rpki_cert_t *c;

  if ((c = malloc(sizeof(*c))) == NULL)
    return NULL;
  memset(c, 0, sizeof(*c));

  if ((c->x = read-cert(filename)) == NULL) {
    rpki_cert_free(c);
    return NULL;
  }

  c->ca = X509_check_ca(c->x) == 1;

  if ((xia = X509_get_ext_d2i(c->x, NID_info_access, NULL, NULL)) != NULL) {
    c->aia = extract_access_uri(xia, aia_oid, sizeof(aia_oid));
    sk_ACCESS_DESCRIPTION_pop_free(xia, ACCESS_DESCRIPTION_free);
  }

  if ((xia = X509_get_ext_d2i(c->x, NID_sinfo_access, NULL, NULL)) != NULL) {
    c->sia = extract_access_uri(xia, sia_oid, sizeof(sia_oid));
    sk_ACCESS_DESCRIPTION_pop_free(xia, ACCESS_DESCRIPTION_free);
  }

  if ((crldp = X509_get_ext_d2i(c->x, NID_crl_distribution_points,
				NULL, NULL)) != NULL) {
    c->crldp = extract_crldp_uri(crldp);
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
  }

  return c;
}
