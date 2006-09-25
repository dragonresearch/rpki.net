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
#include <dirent.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/safestack.h>

#ifndef FILENAME_MAX
#define	FILENAME_MAX	1024
#endif

#define	SIZEOF_RSYNC	(sizeof("rsync://") - 1)

#define	URI_MAX		(FILENAME_MAX + SIZEOF_RSYNC)

typedef struct certinfo {
  int ca, ta;
  char file[FILENAME_MAX];
  char uri[URI_MAX], sia[URI_MAX], aia[URI_MAX], crldp[URI_MAX];
} certinfo_t;

/*
 * Working directories, including trailing slashes.  Make these
 * configurable eventually (at which point the config code should
 * insure the trailing slashes...).
 */
static const char trust_anchor_tree[]	= "rcynic-trust-anchors/";
static const char authenticated[]	= "rcynic-data/authenticated/";
static const char old_authenticated[]	= "rcynic-data/authenticated.old/";
static const char unauthenticated[]	= "rcynic-data/unauthenticated/";

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
  if (strlen(name) >= sizeof(buffer))
    return 0;
  strcpy(buffer, name);
  if ((b = strrchr(buffer, '/')) == NULL)
    return 1;
  *b = '\0';
  if (!access(buffer, F_OK))
    return 1;
  if (!mkdir_maybe(buffer))
    return 0;
  return mkdir(name, 0777) == 0;
}

/*
 * Is string an rsync URI?
 */

static int is_rsync(const char *s)
{
  return s && !strncmp(s, "rsync://", SIZEOF_RSYNC);
}

/*
 * Convert an rsync URI to a filename, checking for evil character
 * sequences.
 */

static int uri_to_filename(const char *name,
			   char *buffer,
			   const size_t buflen,
			   const char *prefix)
{
  int n;

  if (!is_rsync(name))
    return 0;

  name += SIZEOF_RSYNC;
  n = strlen(name);
  
  if (name[0] == '/' || name[0] == '.' || strstr(name, "//") ||
      strstr(name, "/../") || (n >= 3 && !strcmp(name + n - 3, "/..")))
    return 0;

  if (prefix)
    n += strlen(prefix);

  if (n >= buflen)
    return 0;

  if (prefix) {
    strcpy(buffer, prefix);
    strcat(buffer, name);
  } else {
    strcpy(buffer, name);
  }

  return 1;
}

/*
 * Install an object.  It'd be nice if we could just use link(), but
 * that would require us to trust rsync never to do anything bad.  For
 * now we just copy in the simplest way possible.  Come back to this
 * if profiling shows a hotspot here.
 */

static int install_object(const char *uri, const char *source)
{
  char target[FILENAME_MAX];
  FILE *in, *out;
  int c;

  if (!uri_to_filename(uri, target, sizeof(target), authenticated)) {
    logmsg("Couldn't generate installation name for URI %s", uri);
    return 0;
  }

  if (!mkdir_maybe(target)) {
    logmsg("Couldn't create directory for %s", target);
    return 0;
  }

  if ((in = fopen(source, "rb")) == NULL) {
    logmsg("Couldn't open %s", source);
    return 0;
  }

  if ((out = fopen(target, "rb")) == NULL) {
    logmsg("Couldn't open %s", target);
    fclose(in);
    return 0;
  }

  while ((c = getc(in)) != EOF) {
    if (putc(c, out) == EOF) {
      logmsg("Couldn't write to %s", target);
      break;
    }
  }

  if (fclose(in) == EOF || fclose(out) == EOF) {
    logmsg("Trouble closing %s and %s", source, target);
    return 0;
  }

  return 1;
}

/*
 * Get next URI in an SIA collection.
 * dir should be null when first called.
 */

static int next_uri(const char *base_uri, const char *prefix,
		    char *uri, int urilen, DIR **dir)
{
  char path[FILENAME_MAX];
  struct dirent *d;
  int remaining;

  assert(base_uri && prefix && uri && dir);

  if (*dir == NULL &&
      ((!uri_to_filename(base_uri, path, sizeof(path), prefix)) ||
       ((*dir = opendir(path)) == NULL)))
    return 0;

  remaining = urilen - strlen(base_uri);

  while ((d = readdir(*dir)) != NULL) {
    if (d->d_type != DT_REG || d->d_name[0] == '.' ||
	d->d_namlen < 4 || strcmp(d->d_name + d->d_namlen - 4, ".cer"))
      continue;
    if (strlen(d->d_name) >= remaining) {
      logmsg("URI %s%s too long, skipping", base_uri, d->d_name);
      continue;
    }
    strcpy(uri, base_uri);
    strcat(uri, d->d_name);
    return 1;
  }

  closedir(*dir);
  *dir = NULL;
  return 0;
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
  char *s, *argv[100], buffer[2000], *uri = 0, path[FILENAME_MAX];
  int argc, pipe_fds[2], pid_status = -1;
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

  if (!uri_to_filename(uri, path, sizeof(path), unauthenticated)) {
    logmsg("Couldn't extract filename from URI: %s", uri);
    return 0;
  }

  assert(argc < sizeof(argv)/sizeof(*argv));
  argv[argc++] = path;

  assert(rsync_cache != NULL);
  if ((s = sk_value(rsync_cache, sk_find(rsync_cache, path))) != NULL &&
      !strncmp(s, path, strlen(s))) {
    logmsg("Cache hit %s for URI %s, skipping rsync", s, uri);
    free(path);
    return 1;
  }

  if (!mkdir_maybe(path)) {
    logmsg("Couldn't make target directory: %s", path);
    return 0;
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

/*
 * Read CRL in DER format.
 */

static X509_CRL *read_crl(const char *filename)
{
  X509_CRL *crl = NULL;
  BIO *b;

  if ((b = BIO_new_file(filename, "r")) != NULL)
    crl = d2i_X509_CRL_bio(b, NULL);

  BIO_free(b);
  return crl;
}



/*
 * Parse interesting stuff from a certificate.
 */

static void extract_crldp_uri(STACK_OF(DIST_POINT) *crldp,
			      char *uri, int urilen)
{
  DIST_POINT *d;
  int i;

  if (!crldp || sk_DIST_POINT_num(crldp) != 1)
    return;

  d = sk_DIST_POINT_value(crldp, 0);

  if (d->reasons || d->CRLissuer || !d->distpoint || d->distpoint->type != 0)
    return;

  for (i = 0; i < sk_GENERAL_NAME_num(d->distpoint->name.fullname); i++) {
    GENERAL_NAME *n = sk_GENERAL_NAME_value(d->distpoint->name.fullname, i);
    assert(n != NULL);
    if (n->type != GEN_URI)
      return;
    if (is_rsync(n->d.uniformResourceIdentifier->data) &&
	urilen > n->d.uniformResourceIdentifier->length) {
      strcpy(uri, n->d.uniformResourceIdentifier->data);
      return;
    }
  }
}

static void extract_access_uri(AUTHORITY_INFO_ACCESS *xia,
			       unsigned char *oid, int oidlen,
			       char *uri, int urilen)
{
  int i;

  if (!xia)
    return;

  for (i = 0; i < sk_ACCESS_DESCRIPTION_num(xia); i++) {
    ACCESS_DESCRIPTION *a = sk_ACCESS_DESCRIPTION_value(xia, i);
    assert(a != NULL);
    if (a->location->type != GEN_URI)
      return;
    if (a->method->length == oidlen &&
	!memcmp(a->method->data, oid, oidlen) &&
	is_rsync(a->location->d.uniformResourceIdentifier->data) &&
	urilen > a->location->d.uniformResourceIdentifier->length) {
      strcpy(uri, a->location->d.uniformResourceIdentifier->data);
      return;
    }
  }
}

static void parse_cert(X509 *x, certinfo_t *c)
{
  static unsigned char aia_oid[] = {0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x30, 0x2};
  static unsigned char sia_oid[] = {0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x30, 0x5};
  STACK_OF(DIST_POINT) *crldp;
  AUTHORITY_INFO_ACCESS *xia;

  assert(x != NULL && c != NULL);
  memset(c, 0, sizeof(*c));

  c->ca = X509_check_ca(x) == 1;

  if ((xia = X509_get_ext_d2i(x, NID_info_access, NULL, NULL)) != NULL) {
    extract_access_uri(xia, aia_oid, sizeof(aia_oid), c->aia, sizeof(c->aia));
    sk_ACCESS_DESCRIPTION_pop_free(xia, ACCESS_DESCRIPTION_free);
  }

  if ((xia = X509_get_ext_d2i(x, NID_sinfo_access, NULL, NULL)) != NULL) {
    extract_access_uri(xia, sia_oid, sizeof(sia_oid), c->sia, sizeof(c->sia));
    sk_ACCESS_DESCRIPTION_pop_free(xia, ACCESS_DESCRIPTION_free);
  }

  if ((crldp = X509_get_ext_d2i(x, NID_crl_distribution_points,
				NULL, NULL)) != NULL) {
    extract_crldp_uri(crldp, c->crldp, sizeof(c->crldp));
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
  }
}



/*
 * Functions I'll probably need for the rest of this:
 *
 * X509_verify()	verify cert against a key (no chain)
 * X509_CRL_verify()	verify CRL against a key
 * X509_verify_cert()	verify cert against X509_STORE_CTX
 * 			(but ctx points to X509_STORE,
 * 			which points to X509_VERIFY_PARAM, ...)
 * X509_get_pubkey()	extract pubkey from cert for *_verify()
 * X509_STORE_CTX_init()	initialize ctx
 * X509_STORE_CTX_trusted_stack()  stack of trusted certs instead of
 * 				   bothering with X509_STORE
 * X509_STORE_CTX_set0_crls()	set crls
 * X509_STORE_get_by_subject()	find object in ctx/store
 *
 * We probably can't use the lookup method stuff because we're using
 * URI naming, so just load everything ourselves and don't specify any
 * lookup methods, either it works or it doesn't.  Hmm, looks like
 * X509_STORE_CTX_trusted_stack() was written for apps like this.
 *
 * Maybe we can restore stack state by using sk_dup() to save then
 * swapping to the saved stack?  Still need to clean up objects on the
 * stack, though, sk_pop_free() will get rid of everything which is
 * not what we want unless the reference counting thing bails us out.
 * Don't think the reference counts work this way.
 */



/*
 * Check whether we already have a particular CRL, attempt to get it
 * if we don't.
 */

static X509_CRL *check_crl_1(const char *uri, char *path, int pathlen,
			     const char *prefix, STACK_OF(X509) *trusted_certs)
{
  X509_STORE_CTX ctx;
  X509_OBJECT xobj;
  EVP_PKEY *pkey;
  X509_CRL *crl;
  int ret;

  assert(uri && path && trusted_certs);

  memset(&ctx, 0, sizeof(ctx));

  if (!uri_to_filename(uri, path, pathlen, prefix) || 
      (crl = read_crl(path)) == NULL)
    return NULL;

  if (!X509_STORE_CTX_init(&ctx, NULL, NULL, NULL))
    goto punt;
  X509_STORE_CTX_trusted_stack(&ctx, trusted_certs);

  if (X509_STORE_get_by_subject(&ctx, X509_LU_X509,
				X509_CRL_get_issuer(crl), &xobj) <= 0)
    goto punt;
  
  pkey = X509_get_pubkey(xobj.data.x509);
  X509_OBJECT_free_contents(&xobj);
  if (!pkey)
    goto punt;

  ret = X509_CRL_verify(crl, pkey);
  EVP_PKEY_free(pkey);
  if (ret <= 0)
    goto punt;

  X509_STORE_CTX_cleanup(&ctx);
  return crl;

 punt:
  X509_STORE_CTX_cleanup(&ctx);
  X509_CRL_free(crl);
  return NULL;
}

static int check_crl(char *uri,
		     STACK_OF(X509) *trusted_certs,
		     STACK_OF(X509_CRL) *crl_cache)
{
  char path[FILENAME_MAX];
  X509_CRL *crl;

  if (uri_to_filename(uri, path, sizeof(path), authenticated) && 
      !access(path, R_OK))
    return 1;

  rsync(uri);

  if ((crl = check_crl_1(uri, path, sizeof(path),
			 unauthenticated, trusted_certs)) ||
      (crl = check_crl_1(uri, path, sizeof(path),
			 old_authenticated, trusted_certs))) {
    install_object(uri, path);
    if (!crl_cache || !sk_X509_CRL_push(crl_cache, crl))
      X509_CRL_free(crl);
    return 1;
  }

  return 0;
}



/*
 * Next task is check_cert().  The innermost loop of walk_cert() from
 * the perl program should also be here, which will make walk_cert() a
 * lot shorter.  The check_cert() / check_cert_1() design used above
 * with check_crl() should work well here too, since it's the same
 * basic problem: load and check from unauth, if that fails load and
 * check from old_auth, if that fails, give up.
 */

static X509 *check_cert_1(const char *uri,
			  char *path, int pathlen,
			  const char *prefix,
			  STACK_OF(X509) *certs,
			  STACK_OF(X509_CRL) *crls,
			  certinfo_t *issuer,
			  certinfo_t *subj)
{
  X509_STORE_CTX ctx;
  X509 *x;

  assert(uri && path && certs && crls && issuer && subj);

  memset(&ctx, 0, sizeof(ctx));

  if (!uri_to_filename(uri, path, pathlen, prefix)) {
    logmsg("Can't convert URI %s to filename", uri);
    return NULL;
  }

  if (access(path, R_OK))
    return NULL;

  if ((x = read_cert(path)) == NULL) {
    logmsg("Can't read certificate %s", path);
    return NULL;
  }

  parse_cert(x, subj);

  if (subj->sia[0] && subj->sia[strlen(subj->sia) - 1] != '/') {
    logmsg("Malformed SIA %s for URI %s, skipping", subj->sia, uri);
    goto punt;
  }

  if (!subj->aia[0]) {
    logmsg("AIA missing for URI %s, skipping", uri);
    goto punt;
  }

  if (!issuer->ta && strcmp(issuer->uri, subj->aia)) {
    logmsg("AIA of %s doesn't match parent, skipping", uri);
    goto punt;
  }

  if (subj->ca && !subj->sia[0]) {
    logmsg("CA certificate %s without SIA extension, skipping", uri);
    goto punt;
  }

  if (!subj->ca && subj->sia[0]) {
    logmsg("EE certificate %s with SIA extension, skipping", uri);
    goto punt;
  }

  if (!subj->crldp[0]) {
    logmsg("CRLDP missing for %s, skipping", uri);
    goto punt;
  }

  if (!X509_STORE_CTX_init(&ctx, NULL, x, NULL))
    goto punt;
  X509_STORE_CTX_trusted_stack(&ctx, certs);
  X509_STORE_CTX_set0_crls(&ctx, crls);

  /*
   * This is where we'd check the issuer's signature over the cert if
   * either (a) we wanted to be really paranoid (check sig before
   * fetching CRL), or (b) we wanted to try to check each signature
   * only once by doing the signatures here and faking out the
   * signature checks in X509_verify_cert().  Ignore all this for now.
   */

  if (!check_crl(subj->crldp, certs, crls)) {
    logmsg("Bad CRL for %s, skipping", uri);
    goto punt;
  }

  X509_VERIFY_PARAM_set_flags(ctx.param,
			      X509_V_FLAG_CRL_CHECK |
			      X509_V_FLAG_CRL_CHECK_ALL |
			      X509_V_FLAG_POLICY_CHECK |
			      X509_V_FLAG_EXPLICIT_POLICY |
			      X509_V_FLAG_X509_STRICT);

  X509_VERIFY_PARAM_add0_policy(ctx.param,
				/* {0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0xe, 0x2} */
				OBJ_txt2obj("1.3.6.1.5.5.7.14.2", 0));

  /*
   * Might want to set a verify callback handler here.
   */

 if (X509_verify_cert(&ctx) <= 0) {
    logmsg("I don't think X509_verify_cert() was happy with %s", uri);
    goto punt;
  }

  X509_STORE_CTX_cleanup(&ctx);
  return x;

 punt:
  X509_STORE_CTX_cleanup(&ctx);
  X509_free(x);
  return NULL;
}

static int check_cert(char *uri,
		      STACK_OF(X509) *certs,
		      STACK_OF(X509_CRL) *crls,
		      certinfo_t *issuer,
		      certinfo_t *subj,
		      const char *prefix)
{
  char path[FILENAME_MAX];
  X509 *x;

  if (uri_to_filename(uri, path, sizeof(path), authenticated) && 
      !access(path, R_OK))
    return 0;			/* Already seen, don't walk it again */

  rsync(uri);

  assert(certs);

  if ((x = check_cert_1(uri, path, sizeof(path), prefix,
			certs, crls, issuer, subj))) {
    install_object(uri, path);
    if (!sk_X509_push(certs, x))
      X509_free(x);
    return 1;			/* New cert, need to walk it */
  }

  return 0;			/* Nothing to walk */
}



/*
 * Recursive walk of certificate hierarchy (core of the program).
 */

static void walk_cert(certinfo_t *parent, STACK_OF(X509) *certs, STACK_OF(X509_CRL) *crls)
{
  assert(parent && certs && crls);

  logmsg("Starting walk of %s", parent->uri);

  if (parent->sia[0]) {
    int n_crl = sk_X509_CRL_num(crls);
    int n_cert = sk_X509_num(certs);
    char uri[URI_MAX];
    certinfo_t child;
    DIR *dir = NULL;

    rsync("--recursive", "--delete", parent->sia);

    while (next_uri(parent->sia, unauthenticated, uri, sizeof(uri), &dir))
      if (check_cert(uri, certs, crls, parent, &child, unauthenticated))
	walk_cert(&child, certs, crls);

    while (next_uri(parent->sia, old_authenticated, uri, sizeof(uri), &dir))
      if (check_cert(uri, certs, crls, parent, &child, old_authenticated))
	walk_cert(&child, certs, crls);

    while (sk_X509_num(certs) > n_cert)
      X509_free(sk_X509_pop(certs));
    while (sk_X509_CRL_num(crls) > n_crl)
      X509_CRL_free(sk_X509_CRL_pop(crls));
  }

  logmsg("Finished walk of %s", parent->uri);
}



/*
 * Main program (finally!).  getopt() to parse command line, unless
 * there's some clever OpenSSL equivalent that we should use instead.
 * OpenSSL config file contains most parameters, including filenames
 * of trust anchors.  getopt() should be mostly for things like
 * enabling debugging, disabling network, or changing location of
 * config file.
 *
 * Need a scheme for storing trust anchors in hierarchy we build?
 * Maybe we just leave them where we found them, but probably best to
 * install them so there will be copies with the tree derived from
 * them, as even trust anchors can change, and as applications will
 * need them anyway.  Collection under fake "host" TRUST-ANCHORS
 * perhaps?  Not an FQDN so relatively safe, could be made safer by
 * downcasing DNS name of rsync URIs and using uppercase for trust
 * anchor directory, or something like that.  Probably make name of
 * trust anchor directory configurable and default to TRUST-ANCHORS.
 * Not to be confused with where we -find- the trust anchors.
 */

int main(int argc, char *argv[])
{
  char *trust_anchor_name, *cfg_filename = "rcynic.conf";
  STACK_OF(X509_CRL) *crls = NULL;
  STACK_OF(X509) *certs = NULL;
  CONF *conf = NULL;
  int c, i, ret = 1;
  long eline;

  jane = argv[0];

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  if ((rsync_cache = sk_new(rsync_cmp)) == NULL) {
    logmsg("Couldn't allocate rsync_cache stack");
    goto done;
  }

  while ((c = getopt(argc, argv, "c:v")) > 0) {
    switch (c) {
    case 'v':
      verbose = 1;
      break;
    case 'c':
      cfg_filename = optarg;
      break;
    default:
      fprintf(stderr, "usage: %s [-c configfile] [-v]\n", jane);
      goto done;
    }
  }

  if ((conf = NCONF_new(NULL)) == NULL) {
    logmsg("Couldn't create CONF opbject");
    goto done;
  }

  if (NCONF_load(conf, cfg_filename, &eline) <= 0) {
    if (eline <= 0)
      logmsg("Couldn't load config file %s", cfg_filename);
    else
      logmsg("Error on line %ld of config file %s", eline, cfg_filename);
    goto done;
  }

  /*
   * perhaps this should specify "rcynic" instead of null, then read
   * section name from initial config section?  it's the openssl way
   * of doing things, but kind of confusing.
   */ 
  if (CONF_modules_load(conf, NULL, 0) <= 0) {
    logmsg("Couldn't configure OpenSSL");
    goto done;
  }

#error not finished
  /*
   * Start reading config file here.  One of:
   *
   *   s = NCONF_get_string(conf, "rcynic", whatever);
   *
   * or
   *
   *   conf_vals = NCONF_get_section(conf, "rcynic");
   *
   * (the latter returns (STACK_OF(CONF_VALUE) *), like an X509V3
   * method sees -- not sure how to free it, maybe just
   * sk_CONF_VALUE_pop_free(foo, free)?)
   */

  /*
   * At some point we're ready to start reading trust anchors.
   */

  while ((trust_anchor_name = find_another_trust_anchor_name()) != NULL) {
    crls;
    certs = ;
    certinfo_t ta_info;
    X509 *x;

    if ((certs = sk_X509_new_null()) == NULL) {
      logmsg("Couldn't allocate certificate stack");
      goto done;
    }

    if ((crls = sk_X509_CRL_new_null()) == NULL) {
      logmsg("Couldn't allocate CRL stack");
      goto done;
    }

    if ((x  = read_cert(trust_anchor_name)) == NULL) {
      logmsg("Couldn't read trust anchor %s", trust_anchor_name);
      goto done;
    }

    parse_cert(x, &ta_info);
    ta_info.ta = 1;
    sk_X509_push(certs, x);

    if (ta_info.crldp && !check_crl(ta_info.crldp, certs, crls)) {
      logmsg("Couldn't get CRL for trust anchor %s", trust_anchor_name);
      goto done;
    }

    walk_cert(&ta_info, certs, crls);

    sk_X509_pop_free(certs, X509_free);
    sk_X509_CRL_pop_free(crls, X509_CRL_free);
  }

  ret = 0;

 done:
  sk_X509_CRL_pop_free(crls, X509_CRL_free);
  sk_X509_pop_free(certs, X509_free);
  sk_pop_free(rsync_cache, free);
  NCONF_free(conf);
  EVP_cleanup();
  ERR_free_strings();
  return ret;
}
