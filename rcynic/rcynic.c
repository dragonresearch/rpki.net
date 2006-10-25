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
#include <limits.h>
#include <fcntl.h>
#include <signal.h>

#define SYSLOG_NAMES		/* defines CODE prioritynames[], facilitynames[] */
#include <syslog.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/safestack.h>
#include <openssl/conf.h>
#include <openssl/rand.h>

#ifndef FILENAME_MAX
#define	FILENAME_MAX	1024
#endif

#define	SIZEOF_RSYNC	(sizeof("rsync://") - 1)

#define	URI_MAX		(FILENAME_MAX + SIZEOF_RSYNC)

#define	KILL_MAX	10

/*
 * Logging levels.  Same general idea as syslog(), but our own
 * catagories based on what makes sense for this program.  Default
 * mappings to syslog() priorities are here because it's the easiest
 * way to make sure that we assign a syslog level to each of ours.
 */

#define LOG_LEVELS							\
  QQ(log_sys_err,	LOG_ERR)	/* Error from OS or library  */	\
  QQ(log_usage_err,	LOG_ERR)	/* Bad usage (local error)   */	\
  QQ(log_summary,	LOG_INFO)	/* Summary at end of run     */ \
  QQ(log_data_err,	LOG_NOTICE)	/* Bad data, no biscuit      */	\
  QQ(log_telemetry,	LOG_INFO)	/* Normal progress chatter   */	\
  QQ(log_verbose,	LOG_INFO)	/* Extra chatter             */ \
  QQ(log_debug,		LOG_DEBUG)	/* Only useful when debugging */

#define QQ(x,y)	x ,
typedef enum log_level { LOG_LEVELS LOG_LEVEL_T_MAX } log_level_t;
#undef	QQ

#define	QQ(x,y)	{ #x , x },
static const struct {
  const char *name;
  log_level_t value;
} log_levels[] = {
  LOG_LEVELS
};
#undef	QQ

/*
 * MIB counters
 */

#define MIB_COUNTERS							  \
  QQ(backup_cert_accepted,	"backup certificates accepted",	 "+bcer") \
  QQ(backup_cert_rejected,	"backup certificates rejected",	 "-bcer") \
  QQ(backup_crl_accepted,	"backup CRLs accepted",		 "+bcrl") \
  QQ(backup_crl_rejected,	"backup CRLs rejected",		 "-bcrl") \
  QQ(current_cert_accepted,	"current certificates accepted", " +cer") \
  QQ(current_cert_rejected,	"current certificates rejected", " -cer") \
  QQ(current_crl_accepted,	"current CRLs accepted",	 " +crl") \
  QQ(current_crl_rejected,	"current CRLs rejected",	 " -crl") \
  QQ(rsync_failed,		"rsync transfers failed",	 " -rsy") \
  QQ(rsync_succeeded,		"rsync transfers succeeded",	 " +rsy") \
  QQ(rsync_timed_out,		"rsync transfers timed out",	 " ?rsy") \
  QQ(stale_crl,			"stale CRLs",			 "stale") \
  QQ(malformed_sia,		"malformed SIA extensions",	 "badsi") \
  QQ(sia_missing,		"SIA extensions missing",	 "nosia") \
  QQ(aia_missing,		"AIA extensions missing",	 "noaia") \
  QQ(crldp_missing,		"CRLDP extensions missing",	 "nocrl") \
  QQ(aia_mismatch,		"mismatched AIA extensions",	 "badai")

#define QQ(x,y,z) x ,
typedef enum mib_counter { MIB_COUNTERS MIB_COUNTER_T_MAX } mib_counter_t;
#undef	QQ

#define QQ(x,y,z) y ,
static const char * const mib_counter_name[] = { MIB_COUNTERS NULL };
#undef	QQ

#define QQ(x,y,z) #x ,
static const char * const mib_counter_label[] = { MIB_COUNTERS NULL };
#undef	QQ

/*
 * Per-host MIB counter object.
 * hostname[] must be first element.
 */
typedef struct host_counter {
  char hostname[URI_MAX];
  unsigned long counters[MIB_COUNTER_T_MAX];
} host_mib_counter_t;

/*
 * Structure to hold data parsed out of a certificate.
 */
typedef struct certinfo {
  int ca, ta;
  char uri[URI_MAX], sia[URI_MAX], aia[URI_MAX], crldp[URI_MAX];
} certinfo_t;

/*
 * Program context that would otherwise be a mess of global variables.
 */
typedef struct rcynic_ctx {
  char *authenticated, *old_authenticated, *unauthenticated;
  char *jane, *rsync_program;
  STACK *rsync_cache, *host_counters;
  int indent, rsync_timeout, use_syslog, use_stdout, allow_stale_crl;
  int priority[LOG_LEVEL_T_MAX];
  log_level_t log_level;
  X509_STORE *x509_store;
} rcynic_ctx_t;

/*
 * Extended context for verify callbacks.  This is a wrapper around
 * OpenSSL's X509_STORE_CTX, and the embedded X509_STORE_CTX -must- be
 * the first element of this structure in order for the evil cast to
 * do the right thing.  This is ugly but safe, as the C language
 * promises us that the address of the first element of a structure is
 * the same as the address of the structure.
 */
typedef struct rcynic_x509_store_ctx {
  X509_STORE_CTX ctx;		/* Must be first */
  const rcynic_ctx_t *rc;
  const certinfo_t *subj;
} rcynic_x509_store_ctx_t;

static const char svn_id[] = "$Id$";



/*
 * Logging.
 */
static void logmsg(const rcynic_ctx_t *rc, 
		   const log_level_t level, 
		   const char *fmt, ...)
{
  va_list ap, aq;

  assert(rc && fmt);

  if (rc->log_level < level)
    return;

  if (rc->use_syslog && rc->use_stdout) {
    va_start(ap, fmt);
    va_copy(aq, ap);
  } else if (rc->use_syslog) {
    va_start(aq, fmt);
  } else {
    va_start(ap, fmt);
  }

  if (rc->use_stdout || !rc->use_syslog) {
    char tad[30];
    time_t tad_time = time(0);
    struct tm *tad_tm = localtime(&tad_time);

    strftime(tad, sizeof(tad), "%H:%M:%S", tad_tm);
    printf("%s: ", tad);
    if (rc->jane)
      printf("%s: ", rc->jane);
    if (rc->indent)
      printf("%*s", rc->indent, " ");
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
  }

  if (rc->use_syslog) {
    vsyslog(rc->priority[level], fmt, aq);
    va_end(aq);
  }
}

/*
 * Print OpenSSL library errors.
 */
static void log_openssl_errors(const rcynic_ctx_t *rc)
{
  const char *data, *file;
  unsigned long code;
  char error[256];
  int flags, line;

  if (!rc->log_level < log_verbose)
    return;

  while ((code = ERR_get_error_line_data(&file, &line, &data, &flags))) {
    ERR_error_string_n(code, error, sizeof(error));
    if (data && (flags & ERR_TXT_STRING))
      logmsg(rc, log_sys_err, "OpenSSL error %s:%d: %s", file, line, error, data);
    else
      logmsg(rc, log_sys_err, "OpenSSL error %s:%d", file, line, error);
    }
}

/*
 * Configure logging.
 */
static int configure_logmsg(rcynic_ctx_t *rc, const char *name)
{
  int i;

  assert(rc && name);

  for (i = 0; i < sizeof(log_levels)/sizeof(*log_levels); i++) {
    if (!strcmp(name, log_levels[i].name)) {
      rc->log_level = log_levels[i].value;
      return 1;
    }
  }

  logmsg(rc, log_usage_err, "Bad log level %s", name);
  return 0;
}

/*
 * Configure syslog.
 */
static int configure_syslog(const rcynic_ctx_t *rc, 
			    int *result,
			    const CODE *table,
			    const char *name)
{
  assert(result && table && name);

  while (table->c_name && strcmp(table->c_name, name))
    table++;

  if (table->c_name) {
    *result = table->c_val;
    return 1;
  } else {
    logmsg(rc, log_usage_err, "Bad syslog code %s", name);
    return 0;
  }
}

/*
 * Configure boolean variable.
 */
static int configure_boolean(const rcynic_ctx_t *rc,
			     int *result,
			     const char *val)
{
  assert(rc && result && val);

  switch (*val) {
  case 'y': case 'Y': case 't': case 'T': case '1':
    *result = 1;
    return 1;
  case 'n': case 'N': case 'f': case 'F': case '0':
    *result = 0;
    return 1;
  default:
    logmsg(rc, log_usage_err, "Bad boolean value %s", val);
    return 0;
  }
}

/*
 * Configure integer variable.
 */
static int configure_integer(const rcynic_ctx_t *rc,
			     int *result,
			     const char *val)
{
  long res;
  char *p;

  assert(rc && result && val);

  res = strtol(val, &p, 10);
  
  if (*val != '\0' && *p == '\0') {
    *result = (int) res;
    return 1;
  } else {
    logmsg(rc, log_usage_err, "Bad integer value %s", val);
    return 0;
  }
}



/*
 * Make a directory if it doesn't already exist.
 */
static int mkdir_maybe(const rcynic_ctx_t *rc, const char *name)
{
  char *b, buffer[FILENAME_MAX];

  assert(name != NULL);
  if (strlen(name) >= sizeof(buffer)) {
    logmsg(rc, log_data_err, "Pathname %s too long", name);
    return 0;
  }
  strcpy(buffer, name);
  b = buffer[0] == '/' ? buffer + 1 : buffer;
  if ((b = strrchr(b, '/')) == NULL)
    return 1;
  *b = '\0';
  if (!mkdir_maybe(rc, buffer)) {
    logmsg(rc, log_sys_err, "Failed to make directory %s", buffer);
    return 0;
  }
  if (!access(buffer, F_OK))
    return 1;
  logmsg(rc, log_verbose, "Creating directory %s", buffer);
  return mkdir(buffer, 0777) == 0;
}

/*
 * Is string an rsync URI?
 */
static int is_rsync(const char *uri)
{
  return uri && !strncmp(uri, "rsync://", SIZEOF_RSYNC);
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
  size_t n;

  buffer[0] = '\0';

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
 * Host MIB counter comparision.  This relies on hostname[] being the
 * first element of a host_mib_counter_t, hence the (unreadable, but
 * correct ANSI/ISO C) assertion.  Given all the icky casts involved
 * in using the raw stack functions, anything else we do here would be
 * more complicated without being significantly safer.
 */
static int host_counter_cmp(const char * const *a, const char * const *b)
{
  assert(!&((host_mib_counter_t*)0)->hostname);
  return strcasecmp(*a, *b);
}

/*
 * MIB counter manipulation.
 */
static void mib_increment(const rcynic_ctx_t *rc,
			  const char *uri,
			  const mib_counter_t counter)
{
  host_mib_counter_t *h = NULL;
  char hostname[URI_MAX];
  char *s;

  assert(rc && uri);

  if (!rc->host_counters)
    return;

  if (!uri_to_filename(uri, hostname, sizeof(hostname), NULL)) {
    logmsg(rc, log_data_err, "Couldn't convert URI %s to hostname", uri);
    return;
  }

  if ((s = strchr(hostname, '/')) != NULL)
    *s = '\0';

  if ((h = (void *) sk_value(rc->host_counters,
			     sk_find(rc->host_counters, hostname))) == NULL) {
    if ((h = malloc(sizeof(*h))) == NULL) {
      logmsg(rc, log_sys_err, "Couldn't allocate MIB counters for %s", uri);
      return;
    }
    memset(h, 0, sizeof(*h));
    strcpy(h->hostname, hostname);
    if (!sk_push(rc->host_counters, (void *) h)) {
      logmsg(rc, log_sys_err, "Couldn't store MIB counters for %s", uri);
      free(h);
      return;
    }
  }

  h->counters[counter]++;
}

/*
 * Install an object.  It'd be nice if we could just use link(), but
 * that would require us to trust rsync never to do anything bad.  For
 * now we just copy in the simplest way possible.  Come back to this
 * if profiling shows a hotspot here.
 */

static int cp(const char *source, const char *target)
{
  FILE *in = NULL, *out = NULL;
  int c, ret = 0;

  if ((in = fopen(source, "rb")) == NULL ||
      (out = fopen(target, "wb")) == NULL)
    goto done;

  while ((c = getc(in)) != EOF)
    if (putc(c, out) == EOF)
      goto done;

  ret = 1;

 done:
  ret &= !(in  != NULL && fclose(in)  == EOF);
  ret &= !(out != NULL && fclose(out) == EOF);
  return ret;
}

static int install_object(const rcynic_ctx_t *rc,
			  const char *uri,
			  const char *source,
			  const int space)
{
  char target[FILENAME_MAX];

  if (!uri_to_filename(uri, target, sizeof(target), rc->authenticated)) {
    logmsg(rc, log_data_err, "Couldn't generate installation name for %s", uri);
    return 0;
  }

  if (!mkdir_maybe(rc, target)) {
    logmsg(rc, log_sys_err, "Couldn't create directory for %s", target);
    return 0;
  }

  if (!cp(source, target)) {
    logmsg(rc, log_sys_err, "Couldn't copy %s to %s", source, target);
    return 0;
  }

  logmsg(rc, log_telemetry, "Accepted%*s%s", space, " ", uri);
  return 1;
}

/*
 * Iterator over URIs in our copy of a SIA collection.
 * dir should be NULL when first called.
 */
static int next_uri(const rcynic_ctx_t *rc, 
		    const char *base_uri,
		    const char *prefix,
		    char *uri, const size_t urilen,
		    DIR **dir)
{
  char path[FILENAME_MAX];
  struct dirent *d;
  size_t remaining, len;

  assert(base_uri && prefix && uri && dir);

  if (*dir == NULL &&
      ((!uri_to_filename(base_uri, path, sizeof(path), prefix)) ||
       ((*dir = opendir(path)) == NULL)))
    return 0;

  len = strlen(base_uri);
  if (len > urilen)
    return 0;
  remaining = urilen - len;

  while ((d = readdir(*dir)) != NULL) {
    if (d->d_type != DT_REG || d->d_name[0] == '.')
      continue;
    len = strlen(d->d_name);
    if (len < 4 || strcmp(d->d_name + len - 4, ".cer"))
      continue;
    if (len >= remaining) {
      logmsg(rc, log_data_err, "URI %s%s too long, skipping", base_uri, d->d_name);
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
 * Set a directory name, making sure it has the trailing slash we
 * require in various other routines.
 */
static void set_directory(char **out, const char *in)
{
  int need_slash;
  size_t n;
  char *s;

  assert(in && out);
  n = strlen(in);
  assert(n > 0);
  need_slash = in[n - 1] != '/';
  s = malloc(n + need_slash + 1);
  assert(s != NULL);
  strcpy(s, in);
  if (need_slash)
    strcat(s, "/");
  if (*out)
    free(*out);
  *out = s;
}

/*
 * Remove a directory tree, like rm -rf.
 */
static int rm_rf(const char *name)
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

  if (rmdir(name) == 0)
    return 1;

  switch (errno) {
  case ENOENT:
    return 1;
  case ENOTEMPTY:
    break;
  default:
    return 0;
  }

  if ((dir = opendir(name)) == NULL)
    return 0;

  while ((d = readdir(dir)) != NULL) {
    if (d->d_name[0] == '.' && (d->d_name[1] == '\0' || (d->d_name[1] == '.' && d->d_name[2] == '\0')))
      continue;
    if (len + strlen(d->d_name) + need_slash >= sizeof(path))
      goto done;
    strcpy(path, name);
    if (need_slash)
      strcat(path, "/");
    strcat(path, d->d_name);
    switch (d->d_type) {
    case DT_DIR:
      if (!rm_rf(path))
	goto done;
      continue;
    default:
      if (unlink(path) < 0)
	goto done;
      continue;
    }
  }

  ret = rmdir(name) == 0;

 done:
  closedir(dir);
  return !d;
}



/*
 * Run rsync.  This is fairly nasty, because we need to:
 *
 * (a) Construct the argument list for rsync;
 *
 * (b) Run rsync in a child process;
 *
 * (c) Sit listening to rsync's output, logging whatever we get;
 *
 * (d) Impose an optional time limit on rsync's execution time
 *
 * (e) Clean up from (b), (c), and (d); and
 *
 * (f) Keep track of which URIs we've already fetched, so we don't
 *     have to do it again.
 *
 * Taken all together, this is pretty icky.  Breaking it into separate
 * functions wouldn't help much.  Don't read this on a full stomach.
 */

static int rsync_cmp(const char * const *a, const char * const *b)
{
  return strcmp(*a, *b);
}

static int rsync(const rcynic_ctx_t *rc,
		 const char * const *args,
		 const char *uri)
{
  static char *rsync_cmd[] = {
    "rsync", "--update", "--times", "--copy-links", "--itemize-changes", NULL
  };

  const char *argv[100];
  char *s, buffer[URI_MAX * 4], path[FILENAME_MAX];
  int i, n, ret, pipe_fds[2], argc = 0, pid_status = -1;
  time_t now, deadline;
  struct timeval tv;
  pid_t pid, wpid;
  fd_set rfds;

  assert(rc && uri);

  memset(argv, 0, sizeof(argv));

  for (i = 0; rsync_cmd[i]; i++) {
    assert(argc < sizeof(argv)/sizeof(*argv));
    argv[argc++] = rsync_cmd[i];
  }
  if (args) {
    for (i = 0; args[i]; i++) {
      assert(argc < sizeof(argv)/sizeof(*argv));
      argv[argc++] = args[i];
    }
  }

  if (rc->rsync_program)
    argv[0] = rc->rsync_program;

  if (!uri_to_filename(uri, path, sizeof(path), rc->unauthenticated)) {
    logmsg(rc, log_data_err, "Couldn't extract filename from URI: %s", uri);
    return 0;
  }

  assert(argc < sizeof(argv)/sizeof(*argv));
  argv[argc++] = uri;

  assert(argc < sizeof(argv)/sizeof(*argv));
  argv[argc++] = path;

  assert(rc->rsync_cache != NULL);
  assert(sizeof(buffer) >= URI_MAX && strlen(uri) > SIZEOF_RSYNC);
  strcpy(buffer, uri);
  if ((s = strrchr(buffer + SIZEOF_RSYNC, '/')) != NULL && s[1] == '\0')
    *s = '\0';
  for (;;) {
    if (sk_find(rc->rsync_cache, buffer) >= 0) {
      logmsg(rc, log_verbose, "rsync cache hit for %s", uri);
      return 1;
    }
    if ((s = strrchr(buffer + SIZEOF_RSYNC, '/')) == NULL)
      break;
    *s = '\0';
  }

  if (!mkdir_maybe(rc, path)) {
    logmsg(rc, log_sys_err, "Couldn't make target directory: %s", path);
    return 0;
  }

  logmsg(rc, log_telemetry, "Fetching %s", uri);

  for (i = 0; i < argc; i++)
    logmsg(rc, log_verbose, "rsync argv[%d]: %s", i, argv[i]);

  if (pipe(pipe_fds) < 0) {
    logmsg(rc, log_sys_err, "pipe() failed: %s", strerror(errno));
    return 0;
  }

  if ((i = fcntl(pipe_fds[0], F_GETFL, 0)) == -1 ||
      fcntl(pipe_fds[0], F_SETFL, i | O_NONBLOCK) == -1) {
    logmsg(rc, log_sys_err,
	   "Couldn't set rsync's output stream non-blocking: %s",
	   strerror(errno));
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    return 0;
  }

  switch ((pid = vfork())) {
  case -1:
     logmsg(rc, log_sys_err, "vfork() failed: %s", strerror(errno));
     close(pipe_fds[0]);
     close(pipe_fds[1]);
     return 0;
  case 0:
#define whine(msg) write(2, msg, sizeof(msg) - 1)
    close(pipe_fds[0]);
    if (dup2(pipe_fds[1], 1) < 0)
      whine("dup2(1) failed\n");
    else if (dup2(pipe_fds[1], 2) < 0)
      whine("dup2(2) failed\n");
    else if (execvp(argv[0], (char * const *) argv) < 0)
      whine("execvp() failed\n");
    whine("last system error: ");
    write(2, strerror(errno), strlen(strerror(errno)));
    whine("\n");
    _exit(1);
#undef whine
  }

  close(pipe_fds[1]);

  deadline = time(0) + rc->rsync_timeout;

  i = 0;
  while ((wpid = waitpid(pid, &pid_status, WNOHANG)) == 0 &&
	 (!rc->rsync_timeout || (now = time(0)) < deadline)) {
    FD_ZERO(&rfds);
    FD_SET(pipe_fds[0], &rfds);
    if (rc->rsync_timeout) {
      tv.tv_sec = deadline - now;
      tv.tv_usec = 0;
      n = select(pipe_fds[0] + 1, &rfds, NULL, NULL, &tv);
    } else {
      n = select(pipe_fds[0] + 1, &rfds, NULL, NULL, NULL);
    }
    if (n == 0 || (n < 0 && errno == EINTR))
      continue;
    if (n < 0)
      break;
    while ((n = read(pipe_fds[0], buffer + i, sizeof(buffer) - i - 1)) > 0) {
      i += n;
      assert(i < sizeof(buffer));
      buffer[i] = '\0';
      while ((s = strchr(buffer, '\n'))) {
	*s++ = '\0';
	logmsg(rc, log_telemetry, "%s", buffer);
	i -= s - buffer;
	assert(i >= 0);
	if (i == 0)
	  break;
	memmove(buffer, s, i);
      }
      if (n < 0 && errno == EAGAIN)
	continue;
      if (n <= 0)
	break;
    }
  }
  
  close(pipe_fds[0]);

  assert(i >= 0 && i < sizeof(buffer));
  if (i) {
    buffer[i] = '\0';
    logmsg(rc, log_telemetry, "%s", buffer);
  }

  if (n < 0 && errno != EAGAIN)
    logmsg(rc, log_sys_err, "Problem reading rsync's output: %s",
	   strerror(errno));

  if (rc->rsync_timeout && now >= deadline)
    logmsg(rc, log_data_err,
	   "Fetch of %s took longer than %d seconds, terminating fetch",
	   uri, rc->rsync_timeout);

  assert(pid > 0);
  for (i = 0; i < KILL_MAX && wpid == 0; i++) {
    if ((wpid = waitpid(pid, &pid_status, 0)) != 0 && WIFEXITED(pid_status))
      break;
    kill(pid, SIGTERM);
  }

  if (WEXITSTATUS(pid_status)) {
    logmsg(rc, log_data_err, "rsync exited with status %d fetching %s",
	   WEXITSTATUS(pid_status), uri);
    ret = 0;
    mib_increment(rc, uri, (rc->rsync_timeout && now >= deadline
			    ? rsync_timed_out
			    : rsync_failed));
  } else {
    ret = 1;
    mib_increment(rc, uri, rsync_succeeded);
  }

  strcpy(buffer, uri);
  if ((s = strrchr(buffer + SIZEOF_RSYNC, '/')) != NULL && s[1] == '\0')
    *s = '\0';
  if ((s = strdup(buffer)) == NULL || !sk_push(rc->rsync_cache, s))
    logmsg(rc, log_sys_err, "Couldn't cache URI %s, blundering onward", uri);

  return ret;
}

static int rsync_crl(const rcynic_ctx_t *rc, const char *uri)
{
  return rsync(rc, NULL, uri);
}

static int rsync_sia(const rcynic_ctx_t *rc, const char *uri)
{
  static const char * const rsync_args[] = { "--recursive", "--delete", NULL };
  return rsync(rc, rsync_args, uri);
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

static void extract_crldp_uri(const STACK_OF(DIST_POINT) *crldp,
			      char *uri, const int urilen)
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
    if (is_rsync((char *) n->d.uniformResourceIdentifier->data) &&
	urilen > n->d.uniformResourceIdentifier->length) {
      strcpy(uri, (char *) n->d.uniformResourceIdentifier->data);
      return;
    }
  }
}

static void extract_access_uri(const AUTHORITY_INFO_ACCESS *xia,
			       const unsigned char *oid,
			       const int oidlen,
			       char *uri, const int urilen)
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
	is_rsync((char *) a->location->d.uniformResourceIdentifier->data) &&
	urilen > a->location->d.uniformResourceIdentifier->length) {
      strcpy(uri, (char *) a->location->d.uniformResourceIdentifier->data);
      return;
    }
  }
}

static void parse_cert(X509 *x, certinfo_t *c, const char *uri)
{
  static const unsigned char aia_oid[] =
    {0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x30, 0x2};
  static const unsigned char sia_oid[] =
    {0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x30, 0x5};

  STACK_OF(DIST_POINT) *crldp;
  AUTHORITY_INFO_ACCESS *xia;

  assert(x != NULL && c != NULL);
  memset(c, 0, sizeof(*c));

  c->ca = X509_check_ca(x) == 1;

  assert(strlen(uri) < sizeof(c->uri));
  strcpy(c->uri, uri);

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
 * Check whether we already have a particular CRL, attempt to fetch it
 * and check issuer's signature if we don't.
 */

static X509_CRL *check_crl_1(const char *uri,
			     char *path, const int pathlen,
			     const char *prefix,
			     X509 *issuer)
{
  X509_CRL *crl = NULL;
  EVP_PKEY *pkey;
  int ret;

  assert(uri && path && issuer);

  if (!uri_to_filename(uri, path, pathlen, prefix) || 
      (crl = read_crl(path)) == NULL)
    return NULL;

  if ((pkey = X509_get_pubkey(issuer)) == NULL)
    goto punt;
  ret = X509_CRL_verify(crl, pkey);
  EVP_PKEY_free(pkey);

  if (ret > 0)
    return crl;

 punt:
  X509_CRL_free(crl);
  return NULL;
}

static X509_CRL *check_crl(const rcynic_ctx_t *rc,
			   const char *uri,
			   X509 *issuer)
{
  char path[FILENAME_MAX];
  X509_CRL *crl;

  if (uri_to_filename(uri, path, sizeof(path), rc->authenticated) && 
      (crl = read_crl(path)) != NULL)
    return crl;

  logmsg(rc, log_telemetry, "Checking CRL %s", uri);

  rsync_crl(rc, uri);

  if ((crl = check_crl_1(uri, path, sizeof(path),
			 rc->unauthenticated, issuer))) {
    install_object(rc, uri, path, 5);
    mib_increment(rc, uri, current_crl_accepted);
    return crl;
  } else if (!access(path, F_OK)) {
    mib_increment(rc, uri, current_crl_rejected);
  }

  if ((crl = check_crl_1(uri, path, sizeof(path),
			 rc->old_authenticated, issuer))) {
    install_object(rc, uri, path, 5);
    mib_increment(rc, uri, backup_crl_accepted);
    return crl;
  } else if (!access(path, F_OK)) {
    mib_increment(rc, uri, backup_crl_rejected);
  }

  return NULL;
}



/*
 * Check a certificate, including all the crypto, path validation,
 * and checks for conformance to the RPKI certificate profile.
 */

static int check_cert_cb(int ok, X509_STORE_CTX *ctx)
{
  rcynic_x509_store_ctx_t *rctx = (rcynic_x509_store_ctx_t *) ctx;

  assert(rctx != NULL);

  switch (ctx->error) {
  case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
#if 0
  case X509_V_ERR_AKID_SKID_MISMATCH:
  case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
  case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
#endif
    /*
     * Informational events, not really errors.  ctx->check_issued()
     * is called in many places where failure to find an issuer is not
     * a failure for the calling function.  Just leave these alone.
     */
    break;
  case X509_V_ERR_CRL_HAS_EXPIRED:
    /*
     * This may not be an error at all.  CRLs don't really "expire",
     * although the signatures over them do.  What OpenSSL really
     * means by this error is just "it's now later than this source
     * said it intended to publish a new CRL.  Unclear whether this
     * should be an error; current theory is that it should not be.
     */
    logmsg(rctx->rc, log_telemetry, "Stale CRL %s while checking %s",
	   rctx->subj->crldp, rctx->subj->uri);
    mib_increment(rctx->rc, rctx->subj->uri, stale_crl);
    if (rctx->rc->allow_stale_crl)
      ok = 1;
    break;
  default:
  if (!ok)
    logmsg(rctx->rc, log_data_err,
	   "Callback depth %d error %d cert %p issuer %p crl %p: %s",
	   ctx->error_depth, ctx->error, ctx->current_cert,
	   ctx->current_issuer, ctx->current_crl,
	   X509_verify_cert_error_string(ctx->error));
  }

  return ok;
}

static int check_x509(const rcynic_ctx_t *rc,
		      STACK_OF(X509) *certs,
		      X509 *x,
		      const certinfo_t *subj)
{
  rcynic_x509_store_ctx_t rctx;
  STACK_OF(X509_CRL) *crls = NULL;
  EVP_PKEY *pkey = NULL;
  X509_CRL *crl = NULL;
  X509 *issuer;
  int ret = 0;

  assert(rc && certs && x && subj && subj->crldp[0]);

  issuer = sk_X509_value(certs, sk_X509_num(certs) - 1);
  assert(issuer != NULL);

  if (!X509_STORE_CTX_init(&rctx.ctx, rc->x509_store, x, NULL))
    return 0;
  rctx.rc = rc;
  rctx.subj = subj;

  if (!subj->ta &&
      ((pkey = X509_get_pubkey(issuer)) == NULL ||
       X509_verify(x, pkey) <= 0)) {
    logmsg(rc, log_data_err, "%s failed signature check prior to CRL fetch",
	   subj->uri);
    goto done;
  }

  if ((crl = check_crl(rc, subj->crldp, issuer)) == NULL) {
    logmsg(rc, log_data_err, "Bad CRL %s for %s", subj->crldp, subj->uri);
    goto done;
  }

  if ((crls = sk_X509_CRL_new_null()) == NULL ||
      !sk_X509_CRL_push(crls, crl)) {
    logmsg(rc, log_sys_err,
	   "Internal allocation error setting up CRL for validation");
    goto done;
  }
  crl = NULL;

  X509_STORE_CTX_trusted_stack(&rctx.ctx, certs);
  X509_STORE_CTX_set0_crls(&rctx.ctx, crls);
  X509_STORE_CTX_set_verify_cb(&rctx.ctx, check_cert_cb);

  X509_VERIFY_PARAM_set_flags(rctx.ctx.param,
			      X509_V_FLAG_CRL_CHECK |
			      X509_V_FLAG_POLICY_CHECK |
			      X509_V_FLAG_EXPLICIT_POLICY |
			      X509_V_FLAG_X509_STRICT);

  X509_VERIFY_PARAM_add0_policy(rctx.ctx.param,
				/* {0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0xe, 0x2} */
				OBJ_txt2obj("1.3.6.1.5.5.7.14.2", 0));

 if (X509_verify_cert(&rctx.ctx) <= 0) {
    logmsg(rc, log_data_err, "Validation failure for %s",
	   subj->uri[0] ? subj->uri : subj->ta ? "[Trust anchor]" : "[???]");
    goto done;
  }

 ret = 1;

 done:
  sk_X509_CRL_pop_free(crls, X509_CRL_free);
  X509_STORE_CTX_cleanup(&rctx.ctx);
  EVP_PKEY_free(pkey);
  X509_CRL_free(crl);

  return ret;
}

static X509 *check_cert_1(const rcynic_ctx_t *rc,
			  const char *uri,
			  char *path,
			  const int pathlen,
			  const char *prefix,
			  STACK_OF(X509) *certs,
			  const certinfo_t *issuer,
			  certinfo_t *subj)
{
  X509 *x = NULL;

  assert(uri && path && certs && issuer && subj);

  if (!uri_to_filename(uri, path, pathlen, prefix)) {
    logmsg(rc, log_data_err, "Can't convert URI %s to filename", uri);
    return NULL;
  }

  if (access(path, R_OK))
    return NULL;

  if ((x = read_cert(path)) == NULL) {
    logmsg(rc, log_sys_err, "Can't read certificate %s", path);
    return NULL;
  }

  parse_cert(x, subj, uri);

  if (subj->sia[0] && subj->sia[strlen(subj->sia) - 1] != '/') {
    logmsg(rc, log_data_err, "Malformed SIA %s for %s", subj->sia, uri);
    mib_increment(rc, uri, malformed_sia);
    goto punt;
  }

  if (!subj->aia[0]) {
    logmsg(rc, log_data_err, "AIA missing for %s", uri);
    mib_increment(rc, uri, aia_missing);
    goto punt;
  }

  if (!issuer->ta && strcmp(issuer->uri, subj->aia)) {
    logmsg(rc, log_data_err, "AIA %s of %s doesn't match parent",
	   subj->aia, uri);
    mib_increment(rc, uri, aia_mismatch);
    goto punt;
  }

  if (subj->ca && !subj->sia[0]) {
    logmsg(rc, log_data_err, "CA certificate %s without SIA extension", uri);
    mib_increment(rc, uri, sia_missing);
    goto punt;
  }

#if 0
  /*
   * Ongoing discussion about removing this restriction from the profile.
   */
  if (!subj->ca && subj->sia[0]) {
    logmsg(rc, log_data_err, "EE certificate %s with SIA extension", uri);
    goto punt;
  }
#endif

  if (!subj->crldp[0]) {
    logmsg(rc, log_data_err, "Missing CRLDP extension for %s", uri);
    mib_increment(rc, uri, crldp_missing);
    goto punt;
  }

  if (!check_x509(rc, certs, x, subj)) {
    logmsg(rc, log_data_err, "Certificate %s failed validation", uri);
    goto punt;
  }

  return x;

 punt:
  X509_free(x);
  return NULL;
}

static X509 *check_cert(rcynic_ctx_t *rc,
			char *uri,
			STACK_OF(X509) *certs,
			const certinfo_t *issuer,
			certinfo_t *subj,
			const char *prefix,
			const int backup)
{
  char path[FILENAME_MAX];
  X509 *x;

  assert(certs);

  if (uri_to_filename(uri, path, sizeof(path), rc->authenticated) && 
      !access(path, R_OK))
    return NULL;	       /* Already seen, don't walk it again */

  logmsg(rc, log_telemetry, "Checking cert %s", uri);

  rc->indent++;

  if ((x = check_cert_1(rc, uri, path, sizeof(path), prefix,
			certs, issuer, subj)) != NULL) {
    install_object(rc, uri, path, 5);
    mib_increment(rc, uri,
		  (backup ? backup_cert_accepted : current_cert_accepted));
  } else if (!access(path, F_OK)) {
    mib_increment(rc, uri,
		  (backup ? backup_cert_rejected : current_cert_rejected));
  }

  rc->indent--;

  return x;
}



/*
 * Recursive walk of certificate hierarchy (core of the program).  The
 * daisy chain recursion is to avoid having to duplicate the stack
 * manipulation and error handling.
 */

static void walk_cert(rcynic_ctx_t *rc,
		      const certinfo_t *parent,
		      STACK_OF(X509) *certs);

static void walk_cert_1(rcynic_ctx_t *rc,
			char *uri,
			STACK_OF(X509) *certs,
			const certinfo_t *issuer,
			certinfo_t *subj,
			const char *prefix,
			const int backup)
{
  X509 *x;

  if ((x = check_cert(rc, uri, certs, issuer, subj, prefix, backup)) == NULL)
    return;

  if (!sk_X509_push(certs, x)) {
    logmsg(rc, log_sys_err,
	   "Internal allocation failure recursing over certificate");
    return;
  }

  walk_cert(rc, subj, certs);
  X509_free(sk_X509_pop(certs));
}

static void walk_cert(rcynic_ctx_t *rc,
		      const certinfo_t *parent,
		      STACK_OF(X509) *certs)
{
  assert(parent && certs);

  if (parent->sia[0] && parent->ca) {
    int n_cert = sk_X509_num(certs);
    char uri[URI_MAX];
    certinfo_t child;
    DIR *dir = NULL;

    rc->indent++;

    rsync_sia(rc, parent->sia);

    while (next_uri(rc, parent->sia, rc->unauthenticated,
		    uri, sizeof(uri), &dir))
      walk_cert_1(rc, uri, certs, parent, &child, rc->unauthenticated, 0);

    while (next_uri(rc, parent->sia, rc->old_authenticated,
		    uri, sizeof(uri), &dir))
      walk_cert_1(rc, uri, certs, parent, &child, rc->old_authenticated, 1);

    assert(sk_X509_num(certs) == n_cert);

    rc->indent--;
  }
}



/*
 * Main program.  Parse command line, read config file, iterate over
 * trust anchors found via config file and do a tree walk for each
 * trust anchor.
 */
int main(int argc, char *argv[])
{
  int opt_jitter = 0, use_syslog = 0, syslog_facility = 0, syslog_perror = 0;
  int opt_syslog = 0, opt_stdout = 0, opt_level = 0, opt_perror = 0;
  char *cfg_file = "rcynic.conf", path[FILENAME_MAX];
  char *lockfile = NULL, *xmlfile = NULL;
  int c, i, j, ret = 1, jitter = 600, lockfd = -1, summary = 0, terse = 0;
  STACK_OF(CONF_VALUE) *cfg_section = NULL;
  STACK_OF(X509) *certs = NULL;
  CONF *cfg_handle = NULL;
  time_t start = 0, finish;
  unsigned long hash;
  rcynic_ctx_t rc;
  unsigned delay;
  long eline = 0;

  memset(&rc, 0, sizeof(rc));

  if ((rc.jane = strrchr(argv[0], '/')) == NULL)
    rc.jane = argv[0];
  else
    rc.jane++;

  set_directory(&rc.authenticated,	"rcynic-data/authenticated/");
  set_directory(&rc.old_authenticated,	"rcynic-data/authenticated.old/");
  set_directory(&rc.unauthenticated,	"rcynic-data/unauthenticated/");
  rc.log_level = log_telemetry;

#define QQ(x,y)   rc.priority[x] = y;
  LOG_LEVELS;
#undef QQ

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  while ((c = getopt(argc, argv, "c:l:stpj:")) > 0) {
    switch (c) {
    case 'c':
      cfg_file = optarg;
      break;
    case 'l':
      opt_level = 1;
      if (!configure_logmsg(&rc, optarg))
	goto done;
      break;
    case 's':
      use_syslog = opt_syslog = 1;
      break;
    case 't':
      rc.use_stdout = opt_stdout = 1;
      break;
    case 'p':
      syslog_perror = opt_perror = 1;
      break;
    case 'j':
      if (!configure_integer(&rc, &jitter, optarg))
	goto done;
      opt_jitter = 1;
      break;
    default:
      logmsg(&rc, log_usage_err,
	     "usage: %s [-c configfile] [-s] [-t] [-p] [-l loglevel]",
	     rc.jane);
      goto done;
    }
  }

  if ((cfg_handle = NCONF_new(NULL)) == NULL) {
    logmsg(&rc, log_sys_err, "Couldn't create CONF opbject");
    goto done;
  }
  
  if (NCONF_load(cfg_handle, cfg_file, &eline) <= 0) {
    if (eline <= 0)
      logmsg(&rc, log_usage_err, "Couldn't load config file %s", cfg_file);
    else
      logmsg(&rc, log_usage_err, "Error on line %ld of config file %s", eline, cfg_file);
    goto done;
  }

  if (CONF_modules_load(cfg_handle, NULL, 0) <= 0) {
    logmsg(&rc, log_sys_err, "Couldn't configure OpenSSL");
    goto done;
  }

  if ((cfg_section = NCONF_get_section(cfg_handle, "rcynic")) == NULL) {
    logmsg(&rc, log_usage_err, "Couldn't load rcynic section from config file");
    goto done;
  }

  for (i = 0; i < sk_CONF_VALUE_num(cfg_section); i++) {
    CONF_VALUE *val = sk_CONF_VALUE_value(cfg_section, i);

    assert(val && val->name && val->value);

    if (!name_cmp(val->name, "authenticated"))
    	set_directory(&rc.authenticated, val->value);

    else if (!name_cmp(val->name, "old-authenticated"))
    	set_directory(&rc.old_authenticated, val->value);

    else if (!name_cmp(val->name, "unauthenticated"))	
      set_directory(&rc.unauthenticated, val->value);

    else if (!name_cmp(val->name, "rsync-timeout") &&
	     !configure_integer(&rc, &rc.rsync_timeout, val->value))
	goto done;

    else if (!name_cmp(val->name, "rsync-program"))
      rc.rsync_program = strdup(val->value);

    else if (!name_cmp(val->name, "lockfile"))
      lockfile = strdup(val->value);

    else if (!opt_jitter &&
	     !name_cmp(val->name, "jitter") &&
	     !configure_integer(&rc, &jitter, val->value))
      goto done;

    else if (!opt_level &&
	     !name_cmp(val->name, "log-level") &&
	     !configure_logmsg(&rc, val->value))
      goto done;

    else if (!opt_syslog &&
	     !name_cmp(val->name, "use-syslog") &&
	     !configure_boolean(&rc, &use_syslog, val->value))
      goto done;

    else if (!opt_stdout &&
	     !name_cmp(val->name, "use-stdout") &&
	     !configure_boolean(&rc, &rc.use_stdout, val->value))
      goto done;

    else if (!opt_perror &&
	     !name_cmp(val->name, "syslog-perror") &&
	     !configure_boolean(&rc, &syslog_perror, val->value))
      goto done;

    else if (!name_cmp(val->name, "syslog-facility") &&
	     !configure_syslog(&rc, &syslog_facility,
			       facilitynames, val->value))
      goto done;

    else if (!name_cmp(val->name, "summary") &&
	     !configure_boolean(&rc, &summary, val->value))
      goto done;

    else if (!name_cmp(val->name, "terse-summary") &&
	     !configure_boolean(&rc, &terse, val->value))
      goto done;

    else if (!name_cmp(val->name, "xml-summary"))
      xmlfile = strdup(val->value);

    else if (!name_cmp(val->name, "allow-stale-crl") &&
	     !configure_boolean(&rc, &rc.allow_stale_crl, val->value))
      goto done;

    /*
     * Ugly, but the easiest way to handle all these strings.
     */

#define	QQ(x,y)							\
    else if (!name_cmp(val->name, "syslog-priority-" #x) &&	\
	     !configure_syslog(&rc, &rc.priority[x],		\
			       prioritynames, val->value))	\
      goto done;

    LOG_LEVELS;			/* the semicolon is for emacs */

#undef QQ

  }

  if ((rc.rsync_cache = sk_new(rsync_cmp)) == NULL) {
    logmsg(&rc, log_sys_err, "Couldn't allocate rsync_cache stack");
    goto done;
  }

  if ((summary || terse || xmlfile) &&
      (rc.host_counters = sk_new(host_counter_cmp)) == NULL) {
    logmsg(&rc, log_sys_err, "Couldn't allocate host_counters stack");
    goto done;
  }

  if ((certs = sk_X509_new_null()) == NULL) {
    logmsg(&rc, log_sys_err, "Couldn't allocate certificate stack");
    goto done;
  }

  if ((rc.x509_store = X509_STORE_new()) == NULL) {
    logmsg(&rc, log_sys_err, "Couldn't allocate X509_STORE");
    goto done;
  }

  if (rc.use_stdout && use_syslog && syslog_perror) {
    if (opt_stdout)
      syslog_perror = 0;
    else
      rc.use_stdout = 0;
  }

  rc.use_syslog = use_syslog;
  if (use_syslog)
    openlog(rc.jane,
	    LOG_PID | (syslog_perror ? LOG_PERROR : 0),
	    (syslog_facility ? syslog_facility : LOG_LOCAL0));

  if (jitter > 0) {
    if (RAND_bytes((unsigned char *) &delay, sizeof(delay)) <= 0) {
      logmsg(&rc, log_sys_err, "Couldn't read random bytes");
      goto done;
    }
    delay %= jitter;
    logmsg(&rc, log_telemetry, "Delaying %u seconds before startup", delay);
    while (delay > 0)
      delay = sleep(delay);      
  }

  if (lockfile &&
      ((lockfd = open(lockfile, O_RDWR|O_CREAT|O_NONBLOCK, 0666)) < 0 ||
       lockf(lockfd, F_TLOCK, 0) < 0)) {
    if (lockfd >= 0 && errno == EAGAIN)
      logmsg(&rc, log_telemetry, "Lock %s held by another process", lockfile);
    else
      logmsg(&rc, log_sys_err, "Problem locking %s: %s", lockfile, strerror(errno));
    goto done;
  }

  start = time(0);
  logmsg(&rc, log_telemetry, "Starting");

  if (!rm_rf(rc.old_authenticated)) {
    logmsg(&rc, log_sys_err, "Couldn't remove %s: %s",
	   rc.old_authenticated, strerror(errno));
    goto done;
  }

  if (rename(rc.authenticated, rc.old_authenticated) < 0 &&
      errno != ENOENT) {
    logmsg(&rc, log_sys_err, "Couldn't rename %s to %s: %s",
	   rc.old_authenticated, rc.authenticated, strerror(errno));
    goto done;
  }

  if (!access(rc.authenticated, F_OK) || !mkdir_maybe(&rc, rc.authenticated)) {
    logmsg(&rc, log_sys_err, "Couldn't prepare directory %s: %s",
	   rc.authenticated, strerror(errno));
    goto done;
  }

  for (i = 0; i < sk_CONF_VALUE_num(cfg_section); i++) {
    CONF_VALUE *val = sk_CONF_VALUE_value(cfg_section, i);
    certinfo_t ta_info;
    X509 *x;

    assert(val && val->name && val->value);

    if (name_cmp(val->name, "trust-anchor"))
      continue;
    
    logmsg(&rc, log_telemetry, "Processing trust anchor %s", val->value);

    if ((x = read_cert(val->value)) == NULL) {
      logmsg(&rc, log_usage_err, "Couldn't read trust anchor %s", val->value);
      goto done;
    }

    hash = X509_subject_name_hash(x);

    for (j = 0; j < INT_MAX; j++) {
      if (snprintf(path, sizeof(path), "%s%lx.%d.cer",
		   rc.authenticated, hash, j) == sizeof(path)) {
	logmsg(&rc, log_sys_err,
	       "Couldn't construct path name for trust anchor %s", val->value);
	goto done;
      }
      if (access(path, F_OK))
	break;
    }

    if (j == INT_MAX) {
      logmsg(&rc, log_sys_err,
	     "Couldn't find a free name for trust anchor %s", val->value);
      goto done;
    }

    logmsg(&rc, log_telemetry, "Copying trust anchor %s to %lx.%d.cer",
	   val->value, hash, j);

    if (!mkdir_maybe(&rc, rc.authenticated) ||
	!cp(val->value, path)) {
      logmsg(&rc, log_sys_err, "Couldn't copy trust anchor %s", val->value);
      goto done;
    }

    parse_cert(x, &ta_info, "");
    ta_info.ta = 1;
    sk_X509_push(certs, x);

    if (ta_info.crldp[0] && !check_x509(&rc, certs, x, &ta_info)) {
      logmsg(&rc, log_data_err, "Couldn't get CRL for trust anchor %s", val->value);
    } else {
      walk_cert(&rc, &ta_info, certs);
    }

    X509_free(sk_X509_pop(certs));
    assert(sk_X509_num(certs) == 0);
  }

  ret = 0;

 done:
  log_openssl_errors(&rc);

  if (sk_num(rc.host_counters) > 0) {

    if (terse) {
      /*
       * Macrology here is demented, don't read right after eating.
       */
      host_mib_counter_t *h;
      size_t hlen = sizeof("host") - 1;

      for (i = 0; i < sk_num(rc.host_counters); i++) {
	h = (void *) sk_value(rc.host_counters, i);
	assert(h);
	if (hlen < strlen(h->hostname))
	  hlen = strlen(h->hostname);
      }

#define QQ(x,y,z) " " z
      logmsg(&rc, log_summary, "%*s" MIB_COUNTERS, hlen, "host");
#undef	QQ

      for (i = 0; i < sk_num(rc.host_counters); i++) {
	h = (void *) sk_value(rc.host_counters, i);

	logmsg(&rc, log_summary,
#define QQ(x,y,z) " %*lu"
	       "%*s" MIB_COUNTERS,
#undef	QQ
#define	QQ(x,y,z) , sizeof(z) - 1 , h->counters[x]
	       hlen, h->hostname MIB_COUNTERS
#undef	QQ
	       );
      }
    }

    if (summary) {
      logmsg(&rc, log_summary, "Summary by repository host:");
      for (i = 0; i < sk_num(rc.host_counters); i++) {
	host_mib_counter_t *h = (void *) sk_value(rc.host_counters, i);
	assert(h);
	logmsg(&rc, log_summary, " %s:", h->hostname);
	for (j = 0; j < MIB_COUNTER_T_MAX; ++j)
	  if (h->counters[j])
	    logmsg(&rc, log_summary, "  %5lu %s",
		   h->counters[j], mib_counter_name[j]);
      }
    }

    if (xmlfile) {
      char tad[sizeof("2006-10-13T11:22:33Z") + 1];
      time_t tad_time = time(0);
      struct tm *tad_tm = gmtime(&tad_time);
      FILE *f = fopen(xmlfile, "w");
      int ok = f != NULL;

      strftime(tad, sizeof(tad), "%Y-%m-%dT%H:%M:%SZ", tad_tm);

      if (ok)
	logmsg(&rc, log_telemetry, "Writing XML summary to %s", xmlfile);

      if (ok)
	ok &= fprintf(f, "<?xml version=\"1.0\" ?>\n"
		      "<rcynic-summary date=\"%s\" rcynic-version=\"%s\">\n"
		      "  <labels>\n"
		      "    <hostname>Hostname</hostname>\n",
		      tad, svn_id) != EOF;

      for (j = 0; ok && j < MIB_COUNTER_T_MAX; ++j)
	ok &= fprintf(f, "    <%s>%s</%s>\n", mib_counter_label[j],
		      mib_counter_name[j], mib_counter_label[j]) != EOF;

      if (ok)
	ok &= fprintf(f, "  </labels>\n") != EOF;

      for (i = 0; ok && i < sk_num(rc.host_counters); i++) {
	host_mib_counter_t *h = (void *) sk_value(rc.host_counters, i);
	assert(h);

	if (ok)
	  ok &= fprintf(f, "  <host>\n    <hostname>%s</hostname>\n",
			h->hostname) != EOF;

	for (j = 0; ok && j < MIB_COUNTER_T_MAX; ++j)
	  ok &= fprintf(f, "    <%s>%lu</%s>\n", mib_counter_label[j],
			h->counters[j], mib_counter_label[j]) != EOF;

	if (ok)
	  ok &= fprintf(f, "  </host>\n") != EOF;
      }

      if (ok)
	ok &= fprintf(f, "</rcynic-summary>\n") != EOF;

      if (f)
	ok &= fclose(f) != EOF;

      if (!ok)
	logmsg(&rc, log_sys_err, "Couldn't write XML summary to %s: %s",
	       xmlfile, strerror(errno));
    }

  }

  /*
   * Do NOT free cfg_section, NCONF_free() takes care of that
   */
  sk_X509_pop_free(certs, X509_free);
  sk_pop_free(rc.rsync_cache, free);
  sk_pop_free(rc.host_counters, free);
  X509_STORE_free(rc.x509_store);
  NCONF_free(cfg_handle);
  CONF_modules_free();
  EVP_cleanup();
  ERR_free_strings();
  free(rc.authenticated);
  free(rc.old_authenticated);
  free(rc.unauthenticated);
  if (rc.rsync_program)
    free(rc.rsync_program);
  if (lockfile)
    free(lockfile);
  if (xmlfile)
    free(xmlfile);

  if (start) {
    finish = time(0);
    logmsg(&rc, (rc.host_counters ? log_summary : log_telemetry),
	   "Finished, elapsed time %d:%02d:%02d",
	   (finish - start) / 3600,
	   (finish - start) / 60 % 60,
	   (finish - start) % 60);
  }

  return ret;
}
