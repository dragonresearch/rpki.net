/*
 * Copyright (C) 2009--2011  Internet Systems Consortium ("ISC")
 * 
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 *
 * Portions copyright (C) 2006--2008  American Registry for Internet Numbers ("ARIN")
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

/**
 * @mainpage
 *
 * "Cynical rsync": Recursively walk RPKI tree using rsync to pull
 * data from remote sites, validating certificates and CRLs as we go.
 *
 * Doxygen doesn't quite know what to make of a one-file C program,
 * and ends up putting most of the interesting data @link rcynic.c
 * here. @endlink
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
#include <utime.h>
#include <glob.h>
#include <sys/param.h>

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
#include <openssl/asn1t.h>
#include <openssl/cms.h>

#include "bio_f_linebreak.h"

#include "defstack.h"
#include "defasn1.h"

#if !defined(FILENAME_MAX) && defined(PATH_MAX) && PATH_MAX > 1024
#define	FILENAME_MAX	PATH_MAX
#elif !defined(FILENAME_MAX)
#define	FILENAME_MAX	1024
#endif

#define	SCHEME_RSYNC	("rsync://")
#define	SIZEOF_RSYNC	(sizeof(SCHEME_RSYNC) - 1)

/**
 * Maximum length of an URI.
 */
#define	URI_MAX		(FILENAME_MAX + SIZEOF_RSYNC)

/**
 * Maximum number of times we try to kill an inferior process before
 * giving up.
 */
#define	KILL_MAX	10

#ifndef	HOSTNAME_MAX
#define	HOSTNAME_MAX	256
#endif

/**
 * Version number of XML summary output.
 */
#define	XML_SUMMARY_VERSION	1

/**
 * How much buffer space do we need for a raw address?
 */
#define ADDR_RAW_BUF_LEN	16

/**
 * Logging levels.  Same general idea as syslog(), but our own
 * catagories based on what makes sense for this program.  Default
 * mappings to syslog() priorities are here because it's the easiest
 * way to make sure that we assign a syslog level to each of ours.
 */

#define LOG_LEVELS							\
  QQ(log_sys_err,	LOG_ERR)	/* Error from OS or library  */	\
  QQ(log_usage_err,	LOG_ERR)	/* Bad usage (local error)   */	\
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

/**
 * MIB counters derived from OpenSSL.  Long list of validation failure
 * codes from OpenSSL (crypto/x509/x509_vfy.h).
 */

#define	MIB_COUNTERS_FROM_OPENSSL			\
  QV(X509_V_ERR_UNABLE_TO_GET_CRL)			\
  QV(X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE)	\
  QV(X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE)	\
  QV(X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY)	\
  QV(X509_V_ERR_CERT_SIGNATURE_FAILURE)			\
  QV(X509_V_ERR_CRL_SIGNATURE_FAILURE)			\
  QV(X509_V_ERR_CERT_NOT_YET_VALID)			\
  QV(X509_V_ERR_CERT_HAS_EXPIRED)			\
  QV(X509_V_ERR_CRL_NOT_YET_VALID)			\
  QV(X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD)		\
  QV(X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD)		\
  QV(X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD)		\
  QV(X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD)		\
  QV(X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)		\
  QV(X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)		\
  QV(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)	\
  QV(X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE)	\
  QV(X509_V_ERR_CERT_CHAIN_TOO_LONG)			\
  QV(X509_V_ERR_CERT_REVOKED)				\
  QV(X509_V_ERR_INVALID_CA)				\
  QV(X509_V_ERR_PATH_LENGTH_EXCEEDED)			\
  QV(X509_V_ERR_INVALID_PURPOSE)			\
  QV(X509_V_ERR_CERT_UNTRUSTED)				\
  QV(X509_V_ERR_CERT_REJECTED)				\
  QV(X509_V_ERR_AKID_SKID_MISMATCH)			\
  QV(X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH)		\
  QV(X509_V_ERR_KEYUSAGE_NO_CERTSIGN)			\
  QV(X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER)		\
  QV(X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION)		\
  QV(X509_V_ERR_KEYUSAGE_NO_CRL_SIGN)			\
  QV(X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION)	\
  QV(X509_V_ERR_INVALID_NON_CA)				\
  QV(X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED)		\
  QV(X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE)		\
  QV(X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED)		\
  QV(X509_V_ERR_INVALID_EXTENSION)			\
  QV(X509_V_ERR_INVALID_POLICY_EXTENSION)		\
  QV(X509_V_ERR_NO_EXPLICIT_POLICY)			\
  QV(X509_V_ERR_UNNESTED_RESOURCE)

/**
 * MIB counters specific to rcynic.
 */

#define MIB_COUNTERS							    \
  MIB_COUNTERS_FROM_OPENSSL						    \
  QB(aia_mismatch,			"Mismatched AIA extension")	    \
  QB(aia_missing,			"AIA extension missing")	    \
  QB(certificate_bad_crl,		"Bad certificate CRL")		    \
  QB(certificate_bad_signature,		"Bad certificate signature")	    \
  QB(certificate_digest_mismatch,	"Certificate digest mismatch")	    \
  QB(certificate_failed_validation,	"Certificate failed validation")    \
  QB(crl_digest_mismatch,		"CRL digest mismatch")		    \
  QB(crl_not_in_manifest,               "CRL not listed in manifest")	    \
  QB(crl_not_yet_valid,			"CRL not yet valid")		    \
  QB(crldp_mismatch,			"CRLDP doesn't match issuer's SIA") \
  QB(crldp_missing,			"CRLDP extension missing")	    \
  QB(disallowed_extension,		"Disallowed X.509v3 extension")     \
  QB(ghostbuster_bad_crl,		"Ghostbuster EE has bad CRL")	    \
  QB(ghostbuster_bad_econtenttype,	"Bad Ghostbuster eContentType")	    \
  QB(ghostbuster_digest_mismatch,	"Ghostbuster digest mismatch")	    \
  QB(ghostbuster_invalid_cms,		"Ghostbuster validation failure")   \
  QB(ghostbuster_invalid_ee,		"Invalid Ghostbuster certificate")  \
  QB(ghostbuster_missing_signer,	"Missing Ghostbuster signer")	    \
  QB(hash_too_long,			"Hash value is too long")	    \
  QB(malformed_crldp,			"Malformed CRDLP extension")	    \
  QB(malformed_roa_addressfamily,       "Malformed ROA addressFamily")	    \
  QB(malformed_sia,			"Malformed SIA extension")	    \
  QB(manifest_bad_econtenttype,		"Bad manifest eContentType")	    \
  QB(manifest_decode_error,		"Manifest decode error")	    \
  QB(manifest_invalid_cms,		"Manifest validation failure")	    \
  QB(manifest_invalid_ee,		"Invalid manifest certificate")	    \
  QB(manifest_malformed_crldp,          "Malformed manifest CRLDP")	    \
  QB(manifest_mismatch,			"Manifest doesn't match SIA")	    \
  QB(manifest_missing,			"Manifest pointer missing")	    \
  QB(manifest_missing_crldp,            "Missing manifest CRLDP")	    \
  QB(manifest_missing_signer,		"Missing manifest signer")	    \
  QB(manifest_not_yet_valid,		"Manifest not yet valid")	    \
  QB(manifest_wrong_version,            "Wrong manifest version")	    \
  QB(object_rejected,			"Object rejected")		    \
  QB(roa_bad_afi,			"ROA contains bad AFI value")	    \
  QB(roa_bad_crl,			"ROA EE has bad CRL")		    \
  QB(roa_bad_econtenttype,		"Bad ROA eContentType")		    \
  QB(roa_decode_error,			"ROA decode error")		    \
  QB(roa_digest_mismatch,		"ROA digest mismatch")		    \
  QB(roa_invalid_cms,			"ROA validation failure")	    \
  QB(roa_invalid_ee,			"Invalid ROA certificate")	    \
  QB(roa_missing_signer,		"Missing ROA signer")		    \
  QB(roa_not_nested,			"ROA resource not in EE")	    \
  QB(roa_resources_malformed,		"ROA resources malformed")	    \
  QB(roa_wrong_version,			"Wrong ROA version")		    \
  QB(rsync_failed,			"rsync transfer failed")	    \
  QB(rsync_timed_out,			"rsync transfer timed out")	    \
  QB(sia_missing,			"SIA extension missing")	    \
  QB(trust_anchor_key_mismatch,		"Trust anchor key mismatch")	    \
  QB(trust_anchor_with_crldp,		"Trust anchor can't have CRLDP")    \
  QB(unknown_verify_error,		"Unknown OpenSSL verify error")	    \
  QB(unreadable_trust_anchor,		"Unreadable trust anchor")	    \
  QB(unreadable_trust_anchor_locator,	"Unreadable trust anchor locator")  \
  QB(uri_too_long,			"URI too long")			    \
  QW(nonconformant_issuer_name,		"Nonconformant X.509 issuer name")  \
  QW(nonconformant_subject_name,	"Nonconformant X.509 subject name") \
  QW(rsync_skipped,			"rsync transfer skipped")	    \
  QW(stale_crl,				"Stale CRL")			    \
  QW(stale_manifest,			"Stale manifest")		    \
  QW(tainted_by_stale_crl,		"Tainted by stale CRL")		    \
  QW(tainted_by_stale_manifest,		"Tainted by stale manifest")	    \
  QW(tainted_by_not_being_in_manifest,	"Tainted by not being in manifest") \
  QW(trust_anchor_not_self_signed,	"Trust anchor not self-signed")	    \
  QW(unknown_object_type_skipped,	"Unknown object type skipped")	    \
  QG(current_cert_recheck,		"Certificate rechecked")	    \
  QG(object_accepted,			"Object accepted")		    \
  QG(rsync_succeeded,			"rsync transfer succeeded")	    \
  QG(validation_ok,			"OK")

#define QV(x) QB(mib_openssl_##x, 0)

static const char
  mib_counter_kind_good[] = "good",
  mib_counter_kind_warn[] = "warn",
  mib_counter_kind_bad[]  = "bad";

#define QG(x,y)	mib_counter_kind_good ,
#define QW(x,y) mib_counter_kind_warn ,
#define QB(x,y) mib_counter_kind_bad ,
static const char * const mib_counter_kind[] = { MIB_COUNTERS NULL };
#undef QB
#undef QW
#undef QG

#define	QG(x,y) QQ(x,y)
#define	QW(x,y) QQ(x,y)
#define QB(x,y) QQ(x,y)

#define QQ(x,y) x ,
typedef enum mib_counter { MIB_COUNTERS MIB_COUNTER_T_MAX } mib_counter_t;
#undef	QQ

#define QQ(x,y) y ,
static const char * const mib_counter_desc[] = { MIB_COUNTERS NULL };
#undef	QQ

#define QQ(x,y) #x ,
static const char * const mib_counter_label[] = { MIB_COUNTERS NULL };
#undef	QQ

#undef	QV

#define	QQ(x,y)	0 ,
#define	QV(x)   x ,
static const long mib_counter_openssl[] = { MIB_COUNTERS 0 };
#undef	QV
#undef	QQ

/**
 * Object sources.  We always try to get fresh copies of objects using
 * rsync, but if that fails we try using backup copies from what
 * worked the last time we were run.  This means that a URI
 * potentially represents two different objects, so we need to
 * distinguish them for tracking purposes in our validation log.
 */

#define OBJECT_GENERATIONS \
  QQ(null)	\
  QQ(current)	\
  QQ(backup)

#define	QQ(x)	object_generation_##x ,
typedef enum object_generation { OBJECT_GENERATIONS OBJECT_GENERATION_MAX } object_generation_t;
#undef	QQ

#define	QQ(x)	#x ,
static const char * const object_generation_label[] = { OBJECT_GENERATIONS NULL };
#undef	QQ

/**
 * Type-safe string wrapper for URIs.
 */
typedef struct { char s[URI_MAX]; } uri_t;

/**
 * Type-safe string wrapper for filename paths.
 */
typedef struct { char s[FILENAME_MAX]; } path_t;

/**
 * Type-safe string wrapper for hostnames.
 */
typedef struct { char s[HOSTNAME_MAX]; } hostname_t;

/**
 * Type-safe wrapper for hash buffers.
 */
typedef struct { unsigned char h[EVP_MAX_MD_SIZE]; } hashbuf_t;

/**
 * Per-URI validation status object.
 * uri must be first element.
 */
typedef struct validation_status {
  uri_t uri;
  object_generation_t generation;
  time_t timestamp;
  unsigned char events[(MIB_COUNTER_T_MAX + 7) / 8];
} validation_status_t;

DECLARE_STACK_OF(validation_status_t)

/**
 * Structure to hold data parsed out of a certificate.
 */
typedef struct certinfo {
  int ca, ta;
  object_generation_t generation;
  uri_t uri, sia, aia, crldp, manifest;
} certinfo_t;

typedef struct rcynic_ctx rcynic_ctx_t;

/**
 * States that a walk_ctx_t can be in.
 */
typedef enum {
  walk_state_initial,		/**< Initial state */
  walk_state_rsync,		/**< rsyncing certinfo.sia */
  walk_state_ready,		/**< Ready to traverse outputs */
  walk_state_current,		/**< prefix = rc->unauthenticated */
  walk_state_backup,		/**< prefix = rc->old_authenticated */
  walk_state_done		/**< Done walking this cert's outputs */
} walk_state_t;

/**
 * Context for certificate tree walks.  This includes all the stuff
 * that we would keep as automatic variables on the call stack if we
 * didn't have to use callbacks to support multiple rsync processes.
 */
typedef struct walk_ctx {
  unsigned refcount;
  certinfo_t certinfo;
  X509 *cert;
  Manifest *manifest;
  STACK_OF(OPENSSL_STRING) *filenames;
  int manifest_iteration, filename_iteration, stale_manifest;
  walk_state_t state;
} walk_ctx_t;

DECLARE_STACK_OF(walk_ctx_t)

/**
 * Return codes from rsync functions.
 */
typedef enum {
  rsync_status_done,		/* Request completed */
  rsync_status_failed,		/* Request failed */
  rsync_status_timed_out,	/* Request timed out */
  rsync_status_pending,		/* Request in progress */
  rsync_status_skipped		/* Request not attempted */
} rsync_status_t;

/**
 * Context for asyncronous rsync.
 */
typedef struct rsync_ctx {
  uri_t uri;
  void (*handler)(const rcynic_ctx_t *, const struct rsync_ctx *, const rsync_status_t, const uri_t *, STACK_OF(walk_ctx_t) *);
  STACK_OF(walk_ctx_t) *wsk;
  enum {
    rsync_state_initial,	/* Must be first */
    rsync_state_running,
    rsync_state_conflict_wait,
    rsync_state_retry_wait,
    rsync_state_terminating
  } state;
  enum {
    rsync_problem_none,		/* Must be first */
    rsync_problem_timed_out,
    rsync_problem_refused
  } problem;
  unsigned tries;
  pid_t pid;
  int fd;
  time_t started, deadline;
  char buffer[URI_MAX * 4];
  size_t buflen;
} rsync_ctx_t;

DECLARE_STACK_OF(rsync_ctx_t)

/**
 * Deferred task.
 */
typedef struct task {
  void (*handler)(rcynic_ctx_t *, STACK_OF(walk_ctx_t) *);
  STACK_OF(walk_ctx_t) *wsk;
} task_t;

DECLARE_STACK_OF(task_t)

/**
 * Extended context for verify callbacks.  This is a wrapper around
 * OpenSSL's X509_STORE_CTX, and the embedded X509_STORE_CTX @em must be
 * the first element of this structure in order for the evil cast to
 * do the right thing.  This is ugly but safe, as the C language
 * promises us that the address of the first element of a structure is
 * the same as the address of the structure.
 */
typedef struct rcynic_x509_store_ctx {
  X509_STORE_CTX ctx;		/* Must be first */
  const rcynic_ctx_t *rc;
  const certinfo_t *subject;
} rcynic_x509_store_ctx_t;

/**
 * Program context that would otherwise be a mess of global variables.
 */
struct rcynic_ctx {
  path_t authenticated, old_authenticated, new_authenticated, unauthenticated;
  char *jane, *rsync_program;
  STACK_OF(OPENSSL_STRING) *rsync_cache, *backup_cache, *dead_host_cache;
  STACK_OF(validation_status_t) *validation_status;
  STACK_OF(rsync_ctx_t) *rsync_queue;
  STACK_OF(task_t) *task_queue;
  int use_syslog, allow_stale_crl, allow_stale_manifest, use_links;
  int require_crl_in_manifest, rsync_timeout, priority[LOG_LEVEL_T_MAX];
  int allow_non_self_signed_trust_anchor, allow_object_not_in_manifest;
  int max_parallel_fetches, max_retries, retry_wait_min, run_rsync;
  log_level_t log_level;
  X509_STORE *x509_store;
};


/**
 * Subversion ID data.
 */
static const char svn_id[] = "$Id$";

/*
 * ASN.1 Object identifiers in form suitable for use with oid_cmp()
 */

/** 1.3.6.1.5.5.7.48.2 */
static const unsigned char id_ad_caIssuers[] =
  {0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x30, 0x2};

/** 1.3.6.1.5.5.7.48.5 */
static const unsigned char id_ad_caRepository[] =
  {0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x30, 0x5};

/** 1.3.6.1.5.5.7.48.10 */
static const unsigned char id_ad_rpkiManifest[] =
  {0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x30, 0xa};

/** 1.2.840.113549.1.9.16.1.24 */
static const unsigned char id_ct_routeOriginAttestation[] =
  {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x18};

/** 1.2.840.113549.1.9.16.1.26 */
static const unsigned char id_ct_rpkiManifest[] =
  {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x1a};

/** 1.2.840.113549.1.9.16.1.35 */
static const unsigned char id_ct_rpkiGhostbusters[] =
  {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x10, 0x01, 0x23};

/** 2.16.840.1.101.3.4.2.1 */
static const unsigned char id_sha256[] =
  {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};

/**
 * RPKI certificate policy OID in form suitable for use with
 * X509_VERIFY_PARAM_add0_policy().
 */
static const char rpki_policy_oid[] = "1.3.6.1.5.5.7.14.2";

/**
 * Suffix we use temporarily during the symlink shuffle.  Could be
 * almost anything, but we want to do the length check early, before
 * we waste a lot of work we'll just have to throw away, so we just
 * wire in something short and obvious.
 */
static const char authenticated_symlink_suffix[] = ".new";



/**
 * Type-safe wrapper around free() to keep safestack macros happy.
 */
static void OPENSSL_STRING_free(OPENSSL_STRING s)
{
  if (s)
    free(s);
}

/**
 * Wrapper around an idiom we use with OPENSSL_STRING stacks.  There's
 * a bug in the current sk_OPENSSL_STRING_delete() macro that casts
 * the return value to the wrong type, so we cast it to something
 * innocuous here and avoid using that macro elsewhere.
 */
static void sk_OPENSSL_STRING_remove(STACK_OF(OPENSSL_STRING) *sk, const char *str)
{
  OPENSSL_STRING_free((void *) sk_OPENSSL_STRING_delete(sk, sk_OPENSSL_STRING_find(sk, str)));
}

/**
 * Allocate a new validation_status_t object.
 */
static validation_status_t *validation_status_t_new(void)
{
  validation_status_t *v = malloc(sizeof(*v));
  if (v)
    memset(v, 0, sizeof(*v));
  return v;
}

/**
 * Type-safe wrapper around free() to keep safestack macros happy.
 */
static void validation_status_t_free(validation_status_t *v)
{
  if (v)
    free(v);
}



/*
 * GCC attributes to help catch format string errors.
 */

#ifdef __GNUC__

static void logmsg(const rcynic_ctx_t *rc, 
		   const log_level_t level, 
		   const char *fmt, ...)
     __attribute__ ((format (printf, 3, 4)));
#endif

/**
 * Logging.
 */
static void vlogmsg(const rcynic_ctx_t *rc, 
		    const log_level_t level, 
		    const char *fmt,
		    va_list ap)
{
  char tad[sizeof("00:00:00")+1];
  time_t tad_time;

  assert(rc && fmt);

  if (rc->log_level < level)
    return;

  if (rc->use_syslog) {
    vsyslog(rc->priority[level], fmt, ap);
  } else {
    time(&tad_time);
    strftime(tad, sizeof(tad), "%H:%M:%S", localtime(&tad_time));
    fprintf(stderr, "%s: ", tad);
    if (rc->jane)
      fprintf(stderr, "%s: ", rc->jane);
    vfprintf(stderr, fmt, ap);
    putc('\n', stderr);
  }
}

/**
 * Logging.
 */
static void logmsg(const rcynic_ctx_t *rc, 
		   const log_level_t level, 
		   const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  vlogmsg(rc, level, fmt, ap);
  va_end(ap);
}

/**
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
      logmsg(rc, log_sys_err, "OpenSSL error %s:%d: %s: %s", file, line, error, data);
    else
      logmsg(rc, log_sys_err, "OpenSSL error %s:%d: %s", file, line, error);
    }
}

/**
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

/**
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

/**
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

/**
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



/**
 * Make a directory if it doesn't already exist.
 */
static int mkdir_maybe(const rcynic_ctx_t *rc, const path_t *name)
{
  path_t path;
  char *s;

  assert(name != NULL);
  if (strlen(name->s) >= sizeof(path.s)) {
    logmsg(rc, log_data_err, "Pathname %s too long", name->s);
    return 0;
  }
  strcpy(path.s, name->s);
  s = path.s[0] == '/' ? path.s + 1 : path.s;
  if ((s = strrchr(s, '/')) == NULL)
    return 1;
  *s = '\0';
  if (!mkdir_maybe(rc, &path)) {
    logmsg(rc, log_sys_err, "Failed to make directory %s", path.s);
    return 0;
  }
  if (!access(path.s, F_OK))
    return 1;
  logmsg(rc, log_verbose, "Creating directory %s", path.s);
  return mkdir(path.s, 0777) == 0;
}

/**
 * strdup() a string and push it onto a stack.
 */
static int sk_OPENSSL_STRING_push_strdup(STACK_OF(OPENSSL_STRING) *sk, const char *str)
{
  OPENSSL_STRING s = strdup(str);

  if (s && sk_OPENSSL_STRING_push(sk, s))
    return 1;
  if (s)
    free(s);
  return 0;
}

/**
 * Compare two URI strings, for OpenSSL STACK operations.
 */

static int uri_cmp(const char * const *a, const char * const *b)
{
  return strcmp(*a, *b);
}

/**
 * Is string an rsync URI?
 */
static int is_rsync(const char *uri)
{
  return uri && !strncmp(uri, SCHEME_RSYNC, SIZEOF_RSYNC);
}

/**
 * Convert an rsync URI to a filename, checking for evil character
 * sequences.  NB: This routine can't call mib_increment(), because
 * mib_increment() calls it, so errors detected here only go into
 * the log, not the MIB.
 */
static int uri_to_filename(const rcynic_ctx_t *rc,
			   const uri_t *uri,
			   path_t *path,
			   const path_t *prefix)
{
  const char *u;
  size_t n;

  path->s[0] = '\0';

  if (!is_rsync(uri->s)) {
    logmsg(rc, log_telemetry, "%s is not an rsync URI, not converting to filename", uri->s);
    return 0;
  }

  u = uri->s + SIZEOF_RSYNC;
  n = strlen(u);
  
  if (u[0] == '/' || u[0] == '.' || strstr(u, "/../") ||
      (n >= 3 && !strcmp(u + n - 3, "/.."))) {
    logmsg(rc, log_data_err, "Dangerous URI %s, not converting to filename", uri->s);
    return 0;
  }

  if (prefix)
    n += strlen(prefix->s);

  if (n >= sizeof(path->s)) {
    logmsg(rc, log_data_err, "URI %s too long, not converting to filename", uri->s);
    return 0;
  }

  if (prefix) {
    strcpy(path->s, prefix->s);
    strcat(path->s, u);
  } else {
    strcpy(path->s, u);
  }

  return 1;
}

/**
 * Extract a hostname from a URI.
 */
static int uri_to_hostname(const uri_t *uri,
			   hostname_t *hostname)
{
  size_t n;

  if (!uri || !hostname || !is_rsync(uri->s) ||
      (n = strcspn(uri->s + SIZEOF_RSYNC, "/")) >= sizeof(hostname->s))
    return 0;

  strncpy(hostname->s, uri->s + SIZEOF_RSYNC, n);
  hostname->s[n] = '\0';
  return 1;
}

/**
 * OID comparison.
 */
static int oid_cmp(const ASN1_OBJECT *obj, const unsigned char *oid, const size_t oidlen)
{
  assert(obj != NULL && oid != NULL);
  if (obj->length != oidlen)
    return obj->length - oidlen;
  else
    return memcmp(obj->data, oid, oidlen);
}

/**
 * Get value of code in a validation_status_t.
 */
static int validation_status_get_code(const validation_status_t *v, 
				      const mib_counter_t code)
{
  assert(v && code < MIB_COUNTER_T_MAX);
  return (v->events[code / 8] & (1 << (code % 8))) != 0;
}

/**
 * Set value of code in a validation_status_t.
 */
static void validation_status_set_code(validation_status_t *v, 
				       const mib_counter_t code,
				       int value)
{
  assert(v && code < MIB_COUNTER_T_MAX);
  if (value)
    v->events[code / 8] |=  (1 << (code % 8));
  else
    v->events[code / 8] &= ~(1 << (code % 8));
}

/**
 * Add a validation status entry to internal log.
 */
static void log_validation_status(const rcynic_ctx_t *rc,
				  const uri_t *uri,
				  const mib_counter_t code,
				  const object_generation_t generation)
{
  validation_status_t v_, *v = NULL;
  int was_set;

  assert(rc && uri && code < MIB_COUNTER_T_MAX && generation < OBJECT_GENERATION_MAX);

  if (!rc->validation_status)
    return;

  memset(&v_, 0, sizeof(v_));
  v_.uri = *uri;
  v_.generation = generation;

  v = sk_validation_status_t_value(rc->validation_status, sk_validation_status_t_find(rc->validation_status, &v_));
  if (v == NULL) {
    if ((v = validation_status_t_new()) == NULL) {
      logmsg(rc, log_sys_err, "Couldn't allocate validation status entry for %s", uri->s);
      return;
    }
    *v = v_;
    if (!sk_validation_status_t_push(rc->validation_status, v)) {
      logmsg(rc, log_sys_err, "Couldn't store validation status entry for %s", uri->s);
      free(v);
      return;
    }
  }

  was_set = validation_status_get_code(v, code);

  v->timestamp = time(0);
  validation_status_set_code(v, code, 1);

  if (!was_set)
    logmsg(rc, log_verbose, "Recording \"%s\" for %s%s%s",
	   (mib_counter_desc[code]
	    ? mib_counter_desc[code]
	    : X509_verify_cert_error_string(mib_counter_openssl[code])),
	   (generation != object_generation_null ? object_generation_label[generation] : ""),
	   (generation != object_generation_null ? " " : ""),
	   uri->s);
}

/**
 * Validation status object comparision.
 */
static int validation_status_cmp(const validation_status_t * const *a, const validation_status_t * const *b)
{
  int cmp = strcmp((*a)->uri.s, (*b)->uri.s);
  if (cmp)
    return cmp;
  cmp = (int) ((*a)->generation) - (int) ((*b)->generation);
  if (cmp)
    return cmp;
  return 0;
}

/**
 * Copy or link a file, as the case may be.
 */
static int cp_ln(const rcynic_ctx_t *rc, const path_t *source, const path_t *target)
{
  struct stat statbuf;
  struct utimbuf utimebuf;
  FILE *in = NULL, *out = NULL;
  int c, ok = 0;

  if (rc->use_links) {
    (void) unlink(target->s);
    ok = link(source->s, target->s) == 0;
    if (!ok)
      logmsg(rc, log_sys_err, "Couldn't link %s to %s: %s",
	     source->s, target->s, strerror(errno));
    return ok;
  }

  if ((in = fopen(source->s, "rb")) == NULL ||
      (out = fopen(target->s, "wb")) == NULL)
    goto done;

  while ((c = getc(in)) != EOF)
    if (putc(c, out) == EOF)
      goto done;

  ok = 1;

 done:
  ok &= !(in  != NULL && fclose(in)  == EOF);
  ok &= !(out != NULL && fclose(out) == EOF);

  if (!ok) {
    logmsg(rc, log_sys_err, "Couldn't copy %s to %s: %s",
	   source->s, target->s, strerror(errno));
    return ok;
  }

  /*
   * Perserve the file modification time to allow for detection of
   * changed objects in the authenticated directory.  Failure to reset
   * the times is not optimal, but is also not critical, thus no
   * failure return.
   */
  if (stat(source->s, &statbuf) < 0 ||
      (utimebuf.actime = statbuf.st_atime,
       utimebuf.modtime = statbuf.st_mtime,
       utime(target->s, &utimebuf) < 0))
    logmsg(rc, log_sys_err, "Couldn't copy inode timestamp from %s to %s: %s",
	   source->s, target->s, strerror(errno));

  return ok;
}

/**
 * Install an object.
 */
static int install_object(const rcynic_ctx_t *rc,
			  const uri_t *uri,
			  const path_t *source,
			  const mib_counter_t code,
			  const object_generation_t generation)
{
  path_t target;

  if (!uri_to_filename(rc, uri, &target, &rc->new_authenticated)) {
    logmsg(rc, log_data_err, "Couldn't generate installation name for %s", uri->s);
    return 0;
  }

  if (!mkdir_maybe(rc, &target)) {
    logmsg(rc, log_sys_err, "Couldn't create directory for %s", target.s);
    return 0;
  }

  if (!cp_ln(rc, source, &target))
    return 0;
  log_validation_status(rc, uri, code, generation);
  return 1;
}

/**
 * Check str for a suffix.
 */
static int endswith(const char *str, const char *suffix)
{
  size_t len_str, len_suffix;
  assert(str != NULL && suffix != NULL);
  len_str = strlen(str);
  len_suffix = strlen(suffix);
  return len_str >= len_suffix && !strcmp(str + len_str - len_suffix, suffix);
}

/**
 * Check str for a prefix.
 */
static int startswith(const char *str, const char *prefix)
{
  size_t len_str, len_prefix;
  assert(str != NULL && prefix != NULL);
  len_str = strlen(str);
  len_prefix = strlen(prefix);
  return len_str >= len_prefix && !strncmp(str, prefix, len_prefix);
}


/**
 * Set a directory name, adding or stripping trailing slash as needed.
 */
static int set_directory(const rcynic_ctx_t *rc, path_t *out, const char *in, const int want_slash)
{
  int has_slash, need_slash;
  size_t n;

  assert(rc && in && out);

  n = strlen(in);

  if (n == 0) {
    logmsg(rc, log_usage_err, "Empty path");
    return 0;
  }

  has_slash = in[n - 1] == '/';

  need_slash = want_slash && !has_slash;

  if (n + need_slash + 1 > sizeof(out->s)) {
    logmsg(rc, log_usage_err, "Path \"%s\" too long", in);
    return 0;
  }

  strcpy(out->s, in);
  if (need_slash)
    strcat(out->s, "/");
  else if (has_slash && !want_slash)
    out->s[n - 1] = '\0';

  return 1;
}

/**
 * Construct names for the directories not directly settable by the
 * user.
 */
static int construct_directory_names(rcynic_ctx_t *rc)
{
  ssize_t n;
  path_t p;
  time_t t = time(0);

  p = rc->authenticated;

  n = strlen(p.s);

  if (n + sizeof(authenticated_symlink_suffix) >= sizeof(p.s)) {
    logmsg(rc, log_usage_err, "Symlink name would be too long");
    return 0;
  }

  if (strftime(p.s + n, sizeof(p.s) - n - 1, ".%Y-%m-%dT%H:%M:%SZ", gmtime(&t)) == 0) {
    logmsg(rc, log_usage_err, "Generated path with timestamp would be too long");
    return 0;
  }

  if (!set_directory(rc, &rc->new_authenticated, p.s, 1))
    return 0;

  if (!set_directory(rc, &rc->old_authenticated, rc->authenticated.s, 1))
    return 0;

  return 1;
}

/**
 * Remove a directory tree, like rm -rf.
 */
static int rm_rf(const path_t *name)
{
  path_t path;
  struct dirent *d;
  size_t len;
  DIR *dir;
  int ret = 0, need_slash;

  assert(name);
  len = strlen(name->s);
  assert(len > 0 && len < sizeof(path.s));
  need_slash = name->s[len - 1] != '/';

  if (rmdir(name->s) == 0)
    return 1;

  switch (errno) {
  case ENOENT:
    return 1;
  case ENOTEMPTY:
    break;
  default:
    return 0;
  }

  if ((dir = opendir(name->s)) == NULL)
    return 0;

  while ((d = readdir(dir)) != NULL) {
    if (d->d_name[0] == '.' && (d->d_name[1] == '\0' || (d->d_name[1] == '.' && d->d_name[2] == '\0')))
      continue;
    if (len + strlen(d->d_name) + need_slash >= sizeof(path.s))
      goto done;
    strcpy(path.s, name->s);
    if (need_slash)
      strcat(path.s, "/");
    strcat(path.s, d->d_name);
    switch (d->d_type) {
    case DT_DIR:
      if (!rm_rf(&path))
	goto done;
      continue;
    default:
      if (unlink(path.s) < 0)
	goto done;
      continue;
    }
  }

  ret = rmdir(name->s) == 0;

 done:
  closedir(dir);
  return ret;
}

/**
 * Do final symlink shuffle and cleanup of output directories.
 */
static int finalize_directories(const rcynic_ctx_t *rc)
{
  path_t path, sym, real_old, real_new;
  const char *dir;
  size_t n;
  glob_t g;
  int i;

  if (!realpath(rc->old_authenticated.s, real_old.s))
    real_old.s[0] = '\0';

  if (!realpath(rc->new_authenticated.s, real_new.s))
    real_old.s[0] = '\0';

  path = rc->new_authenticated;

  n = strlen(path.s);
  assert(n > 1 && path.s[n - 1] == '/');
  path.s[n - 1] = '\0';

  if ((dir = strrchr(path.s, '/')) == NULL)
    dir = path.s;
  else
    dir++;

  sym = rc->authenticated;

  assert(strlen(sym.s) + sizeof(authenticated_symlink_suffix) < sizeof(sym.s));
  strcat(sym.s, authenticated_symlink_suffix);

  (void) unlink(sym.s);

  if (symlink(dir, sym.s) < 0) {
    logmsg(rc, log_sys_err, "Couldn't link %s to %s: %s",
	   sym.s, dir, strerror(errno));
    return 0;
  }

  if (rename(sym.s, rc->authenticated.s) < 0) {
    logmsg(rc, log_sys_err, "Couldn't rename %s to %s: %s",
	   sym.s, rc->authenticated.s, strerror(errno));
    return 0;
  }

  path = rc->authenticated;
  assert(strlen(path.s) + sizeof(".*") < sizeof(path.s));
  strcat(path.s, ".*");

  memset(&g, 0, sizeof(g));

  if (real_new.s[0] && glob(path.s, 0, 0, &g) == 0)
    for (i = 0; i < g.gl_pathc; i++)
      if (realpath(g.gl_pathv[i], path.s) &&
	  strcmp(path.s, real_old.s) && 
	  strcmp(path.s, real_new.s))
	rm_rf(&path);

  return 1;
}

/**
 * Be kind to people who are upgrading: tell them what's wrong when we
 * start up, rather than doing all the work then throwing away
 * results.  Some day this code will go away.
 */
static int upgraded_from_pre_symlink_rcynic(const rcynic_ctx_t *rc)
{
  path_t p;

  if (readlink(rc->authenticated.s, p.s, sizeof(p.s)) == 0 && errno == EINVAL) {
    logmsg(rc, log_usage_err,
	   "You appear to be upgrading from an old version of rcynic.  "
	   "Please remove %s then run rcynic again.", rc->authenticated.s);
    return 0;
  }

  return 1;
}



/**
 * Check to see whether a hostname is in the dead host cache.
 */
static int dead_host_check(const rcynic_ctx_t *rc, const uri_t *uri)
{
  hostname_t hostname;

  assert(rc && uri && rc->dead_host_cache);

  return (uri_to_hostname(uri, &hostname) &&
	  sk_OPENSSL_STRING_find(rc->dead_host_cache, hostname.s) >= 0);
}


/**
 * Add an entry to the dead host cache.
 */
static void dead_host_add(const rcynic_ctx_t *rc, const uri_t *uri)
{
  hostname_t hostname;

  assert(rc && uri && rc->dead_host_cache);

  if (dead_host_check(rc, uri))
    return;

  if (!uri_to_hostname(uri, &hostname))
    return;

  (void) sk_OPENSSL_STRING_push_strdup(rc->dead_host_cache, hostname.s);
}



/**
 * Test whether a pair of URIs "conflict", that is, whether attempting
 * to rsync both of them at the same time in parallel might cause
 * unpredictable behavior.  Might need a better name for this test.
 *
 * Returns non-zero iff the two URIs "conflict".
 */
static int conflicting_uris(const uri_t *a, const uri_t *b)
{
  size_t len_a, len_b;

  assert(a && is_rsync(a->s) && b && is_rsync(b->s));

  len_a = strlen(a->s);
  len_b = strlen(b->s);

  assert(len_a < sizeof(a->s) && len_b < sizeof(b->s));

  return !strncmp(a->s, b->s, len_a < len_b ? len_a : len_b);
}



/**
 * Read non-directory filenames from a directory, so we can check to
 * see what's missing from a manifest.
 */
static STACK_OF(OPENSSL_STRING) *directory_filenames(const rcynic_ctx_t *rc,
						     const walk_state_t state,
						     const uri_t *uri)
{
  STACK_OF(OPENSSL_STRING) *result = NULL;
  path_t path;
  const path_t *prefix = NULL;
  DIR *dir = NULL;
  struct dirent *d;
  int ok = 0;

  assert(rc && uri);

  switch (state) {
  case walk_state_current:
    prefix = &rc->unauthenticated;
    break;
  case walk_state_backup:
    prefix = &rc->old_authenticated;
    break;
  default:
    goto done;
  }

  if (!uri_to_filename(rc, uri, &path, prefix) ||
      (dir = opendir(path.s)) == NULL || 
      (result = sk_OPENSSL_STRING_new(uri_cmp)) == NULL)
    goto done;

  while ((d = readdir(dir)) != NULL)
    if (d->d_type != DT_DIR && !sk_OPENSSL_STRING_push_strdup(result, d->d_name))
      goto done;

  ok = 1;

 done:
  if (dir != NULL)
    closedir(dir);

  if (ok)
    return result;

  sk_OPENSSL_STRING_pop_free(result, OPENSSL_STRING_free);
  return NULL;
}



/**
 * Increment walk context reference count.
 */
static void walk_ctx_attach(walk_ctx_t *w)
{
  if (w != NULL) {
    w->refcount++;
    assert(w->refcount != 0);
  }
}

/**
 * Decrement walk context reference count; freeing the context if the
 * reference count is now zero.
 */
static void walk_ctx_detach(walk_ctx_t *w)
{
  if (w != NULL && --(w->refcount) == 0) {
    assert(w->refcount == 0);
    X509_free(w->cert);
    Manifest_free(w->manifest);
    sk_OPENSSL_STRING_pop_free(w->filenames, OPENSSL_STRING_free);
    free(w);
  }
}

/**
 * Return top context of a walk context stack.
 */
static walk_ctx_t *walk_ctx_stack_head(STACK_OF(walk_ctx_t) *wsk)
{
  return sk_walk_ctx_t_value(wsk, sk_walk_ctx_t_num(wsk) - 1);
}

/**
 * Walk context iterator.  Think of this as the thing you call in the
 * third clause of a conceptual "for" loop: this reinitializes as
 * necessary for the next pass through the loop.
 *
 * This is still under construction, but general idea is that we have
 * several state variables in a walk context which collectively define
 * the current pass, product URI, etc, and we want to be able to
 * iterate through this sequence via the event system.  So we need a
 * function which steps to the next state.
 */
static void walk_ctx_loop_next(const rcynic_ctx_t *rc, STACK_OF(walk_ctx_t) *wsk)
{
  walk_ctx_t *w = walk_ctx_stack_head(wsk);

  assert(rc && wsk && w);

  if (w->manifest && w->manifest_iteration + 1 < sk_FileAndHash_num(w->manifest->fileList)) {
    w->manifest_iteration++;
    return;
  }

  if (w->filenames && w->filename_iteration + 1 < sk_OPENSSL_STRING_num(w->filenames)) {
    w->filename_iteration++;
    return;
  }

  if (w->state < walk_state_done) {
    w->state++;
    w->manifest_iteration = 0;
    w->filename_iteration = 0;
    sk_OPENSSL_STRING_pop_free(w->filenames, OPENSSL_STRING_free);
    w->filenames = directory_filenames(rc, w->state, &w->certinfo.sia);
  }
}

/**
 * Whether we're done iterating over a walk context.  Think of this as
 * the thing you call (negated) in the second clause of a conceptual
 * "for" loop.
 */
static int walk_ctx_loop_done(STACK_OF(walk_ctx_t) *wsk)
{
  walk_ctx_t *w = walk_ctx_stack_head(wsk);
  return wsk == NULL || w == NULL || w->state >= walk_state_done;
}

static Manifest *check_manifest(const rcynic_ctx_t *rc,
				STACK_OF(walk_ctx_t) *wsk);

/**
 * Loop initializer for walk context.  Think of this as the thing you
 * call in the first clause of a conceptual "for" loop.
 */
static void walk_ctx_loop_init(const rcynic_ctx_t *rc, STACK_OF(walk_ctx_t) *wsk)
{
  walk_ctx_t *w = walk_ctx_stack_head(wsk);

  assert(rc && wsk && w && w->state == walk_state_ready);

  assert(w->manifest == NULL);
  if ((w->manifest = check_manifest(rc, wsk)) == NULL)
    logmsg(rc, log_telemetry, "Couldn't get manifest %s, blundering onward", w->certinfo.manifest.s);

  assert(w->filenames == NULL);
  w->filenames = directory_filenames(rc, w->state, &w->certinfo.sia);

  w->stale_manifest = w->manifest != NULL && X509_cmp_current_time(w->manifest->nextUpdate) < 0;

  w->manifest_iteration = 0;
  w->filename_iteration = 0;
  w->state++;

  assert(w->state == walk_state_current);

  while (!walk_ctx_loop_done(wsk) &&
	 (w->manifest == NULL  || w->manifest_iteration >= sk_FileAndHash_num(w->manifest->fileList)) &&
	 (w->filenames == NULL || w->filename_iteration >= sk_OPENSSL_STRING_num(w->filenames)))
    walk_ctx_loop_next(rc, wsk);
}

/**
 * Extract URI and hash values from walk context.
 */
static int walk_ctx_loop_this(const rcynic_ctx_t *rc,
			      STACK_OF(walk_ctx_t) *wsk,
			      uri_t *uri,
			      const unsigned char **hash,
			      size_t *hashlen)
{
  const walk_ctx_t *w = walk_ctx_stack_head(wsk);
  const char *name = NULL;
  FileAndHash *fah = NULL;

  assert(rc && wsk && w && uri && hash && hashlen);

  if (w->manifest != NULL && w->manifest_iteration < sk_FileAndHash_num(w->manifest->fileList)) {
    fah = sk_FileAndHash_value(w->manifest->fileList, w->manifest_iteration);
    name = (const char *) fah->file->data;
  } else if (w->filenames != NULL && w->filename_iteration < sk_OPENSSL_STRING_num(w->filenames)) {
    name = sk_OPENSSL_STRING_value(w->filenames, w->filename_iteration);
  }

  if (name == NULL) {
    logmsg(rc, log_sys_err, "Can't find a URI in walk context, this shouldn't happen: state %d, manifest_iteration %d, filename_iteration %d",
	   (int) w->state, w->manifest_iteration, w->filename_iteration);
    return 0;
  }

  if (strlen(w->certinfo.sia.s) + strlen(name) >= sizeof(uri->s)) {
    logmsg(rc, log_data_err, "URI %s%s too long, skipping", w->certinfo.sia.s, uri->s);
    return 0;
  }

  strcpy(uri->s, w->certinfo.sia.s);
  strcat(uri->s, name);

  if (fah != NULL) {
    sk_OPENSSL_STRING_remove(w->filenames, name);
    *hash = fah->hash->data;
    *hashlen = fah->hash->length;
  } else {
    *hash = NULL;
    *hashlen = 0;
  }

  return 1;
}

/**
 * Create a new walk context stack.
 */
static STACK_OF(walk_ctx_t) *walk_ctx_stack_new(void)
{
  return sk_walk_ctx_t_new_null();
}

/**
 * Push a walk context onto a walk context stack, return the new context.
 */
static walk_ctx_t *walk_ctx_stack_push(STACK_OF(walk_ctx_t) *wsk,
				       X509 *x,
				       const certinfo_t *certinfo)
{
  walk_ctx_t *w;

  if (x == NULL || certinfo == NULL)
    return NULL;

  if ((w = malloc(sizeof(*w))) == NULL)
    return NULL;

  memset(w, 0, sizeof(*w));
  w->cert = x;
  w->certinfo = *certinfo;

  if (!sk_walk_ctx_t_push(wsk, w)) {
    free(w);
    return NULL;
  }

  walk_ctx_attach(w);
  return w;
}

/**
 * Pop and discard a walk context from a walk context stack.
 */
static void walk_ctx_stack_pop(STACK_OF(walk_ctx_t) *wsk)
{
  walk_ctx_detach(sk_walk_ctx_t_pop(wsk));
}

/**
 * Clone a stack of walk contexts.
 */
static STACK_OF(walk_ctx_t) *walk_ctx_stack_clone(STACK_OF(walk_ctx_t) *old_wsk)
{
  STACK_OF(walk_ctx_t) *new_wsk;
  int i;
  if (old_wsk == NULL || (new_wsk = sk_walk_ctx_t_dup(old_wsk)) == NULL)
    return NULL;
  for (i = 0; i < sk_walk_ctx_t_num(new_wsk); i++)
    walk_ctx_attach(sk_walk_ctx_t_value(new_wsk, i));
  return new_wsk;
}

/**
 * Extract certificate stack from walk context stack.  Returns a newly
 * created STACK_OF(X509) pointing to the existing cert objects (ie,
 * this is a shallow copy, so only free the STACK_OF(X509), not the
 * certificates themselves).
 */
static STACK_OF(X509) *walk_ctx_stack_certs(STACK_OF(walk_ctx_t) *wsk)
{
  STACK_OF(X509) *xsk = sk_X509_new_null();
  walk_ctx_t *w;
  int i;

  for (i = 0; i < sk_walk_ctx_t_num(wsk); i++)
    if ((w = sk_walk_ctx_t_value(wsk, i)) == NULL ||
	(w->cert != NULL && !sk_X509_push(xsk, w->cert)))
      goto fail;

  return xsk;

 fail:
  sk_X509_free(xsk);
  return NULL;
}

/**
 * Free a walk context stack, decrementing reference counts of each
 * frame on it.
 */
static void walk_ctx_stack_free(STACK_OF(walk_ctx_t) *wsk)
{
  sk_walk_ctx_t_pop_free(wsk, walk_ctx_detach);
}



static int rsync_count_running(const rcynic_ctx_t *);

/**
 * Add a task to the task queue.
 */
static int task_add(const rcynic_ctx_t *rc,
		    void (*handler)(rcynic_ctx_t *, STACK_OF(walk_ctx_t) *),
		    STACK_OF(walk_ctx_t) *wsk)
{
  task_t *t = malloc(sizeof(*t));

  assert(rc && rc->task_queue && handler);

  assert(rsync_count_running(rc) <= rc->max_parallel_fetches);

  if (!t)
    return 0;

  t->handler = handler;
  t->wsk = wsk;

  if (sk_task_t_push(rc->task_queue, t))
    return 1;

  free(t);
  return 0;
}

/**
 * Run tasks until queue is empty.
 */
static void task_run_q(rcynic_ctx_t *rc)
{
  task_t *t;
  assert(rc && rc->task_queue);
  while ((t = sk_task_t_shift(rc->task_queue)) != NULL) {
    t->handler(rc, t->wsk);
    free(t);
  }
}



/**
 * Record that we've already synced a particular rsync URI.
 */

static void rsync_cache_add(const rcynic_ctx_t *rc, const uri_t *uri)
{
  uri_t uribuf;
  char *s;

  assert(rc && uri && rc->rsync_cache);
  uribuf = *uri;
  while ((s = strrchr(uribuf.s, '/')) != NULL && s[1] == '\0')
    *s = '\0';
  assert(strlen(uribuf.s) > SIZEOF_RSYNC);
  if (!sk_OPENSSL_STRING_push_strdup(rc->rsync_cache, uribuf.s  + SIZEOF_RSYNC))
    logmsg(rc, log_sys_err, "Couldn't cache URI %s, blundering onward", uri->s);
}

/**
 * Maintain a cache of URIs we've already fetched.
 */
static int rsync_cached_string(const rcynic_ctx_t *rc,
			       const char *string)
{
  char *s, buffer[URI_MAX];

  assert(rc && rc->rsync_cache && strlen(string) < sizeof(buffer));
  strcpy(buffer, string);
  if ((s = strrchr(buffer, '/')) != NULL && s[1] == '\0')
    *s = '\0';
  while (sk_OPENSSL_STRING_find(rc->rsync_cache, buffer) < 0) {
    if ((s = strrchr(buffer, '/')) == NULL)
      return 0;
    *s = '\0';
  }
  return 1;
}

/**
 * Check whether a particular URI has been cached.
 */
static int rsync_cached_uri(const rcynic_ctx_t *rc,
			    const uri_t *uri)
{
  return is_rsync(uri->s) && rsync_cached_string(rc, uri->s + SIZEOF_RSYNC);
}

/**
 * Return count of how many rsync contexts are in running.
 */
static int rsync_count_running(const rcynic_ctx_t *rc)
{
  const rsync_ctx_t *ctx;
  int i, n = 0;

  assert(rc && rc->rsync_queue);

  for (i = 0; (ctx = sk_rsync_ctx_t_value(rc->rsync_queue, i)) != NULL; ++i) {
    switch (ctx->state) {
    case rsync_state_running:
    case rsync_state_terminating:
      n++;
    default:
      continue;
    }
  }

  return n;
}

/**
 * Test whether an rsync context conflicts with anything that's
 * currently runable.
 */
static int rsync_conflicts(const rcynic_ctx_t *rc,
			   const rsync_ctx_t *ctx)
{
  const rsync_ctx_t *c;
  int i;

  assert(rc && ctx && rc->rsync_queue);

  for (i = 0; (c = sk_rsync_ctx_t_value(rc->rsync_queue, i)) != NULL; ++i)
    if (c != ctx &&
	(c->state == rsync_state_initial ||
	 c->state == rsync_state_running) &&
	conflicting_uris(&c->uri, &ctx->uri))
      return 1;

  return 0;
}

/**
 * Test whether a rsync context is runable at this time.
 */
static int rsync_runable(const rcynic_ctx_t *rc,
			 const rsync_ctx_t *ctx)
{
  assert(rc && ctx);

  switch (ctx->state) {

  case rsync_state_initial:
  case rsync_state_running:
    return 1;

  case rsync_state_retry_wait:
    return ctx->deadline <= time(0);

  case rsync_state_terminating:
    return 0;

  case rsync_state_conflict_wait:
    return !rsync_conflicts(rc, ctx);
  }

  return 0;
}

/**
 * Return count of runable rsync contexts.
 */
static int rsync_count_runable(const rcynic_ctx_t *rc)
{
  const rsync_ctx_t *ctx;
  int i, n = 0;

  assert(rc && rc->rsync_queue);

  for (i = 0; (ctx = sk_rsync_ctx_t_value(rc->rsync_queue, i)) != NULL; ++i)
    if (rsync_runable(rc, ctx))
      n++;

  return n;
}

/**
 * Run an rsync process.
 */
static void rsync_run(const rcynic_ctx_t *rc,
		      rsync_ctx_t *ctx)
{
  static const char * const rsync_cmd[] = {
    "rsync", "--update", "--times", "--copy-links", "--itemize-changes"
  };
  static const char * const rsync_tree_args[] = {
    "--recursive", "--delete"
  };

  const char *argv[10];
  path_t path;
  int i, argc = 0, flags, pipe_fds[2];

  pipe_fds[0] = pipe_fds[1] = -1;

  assert(rc && ctx && ctx->pid == 0 && ctx->state != rsync_state_running && rsync_runable(rc, ctx));

  assert(rsync_count_running(rc) < rc->max_parallel_fetches);

  logmsg(rc, log_telemetry, "Fetching %s", ctx->uri.s);

  memset(argv, 0, sizeof(argv));

  for (i = 0; i < sizeof(rsync_cmd)/sizeof(*rsync_cmd); i++) {
    assert(argc < sizeof(argv)/sizeof(*argv));
    argv[argc++] = rsync_cmd[i];
  }
  if (endswith(ctx->uri.s, "/")) {
    for (i = 0; i < sizeof(rsync_tree_args)/sizeof(*rsync_tree_args); i++) {
      assert(argc < sizeof(argv)/sizeof(*argv));
      argv[argc++] = rsync_tree_args[i];
    }
  }

  if (rc->rsync_program)
    argv[0] = rc->rsync_program;

  if (!uri_to_filename(rc, &ctx->uri, &path, &rc->unauthenticated)) {
    logmsg(rc, log_data_err, "Couldn't extract filename from URI: %s", ctx->uri.s);
    goto lose;
  }

  assert(argc < sizeof(argv)/sizeof(*argv));
  argv[argc++] = ctx->uri.s;

  assert(argc < sizeof(argv)/sizeof(*argv));
  argv[argc++] = path.s;

  if (!mkdir_maybe(rc, &path)) {
    logmsg(rc, log_sys_err, "Couldn't make target directory: %s", path.s);
    goto lose;
  }

  for (i = 0; i < argc; i++)
    logmsg(rc, log_verbose, "rsync argv[%d]: %s", i, argv[i]);

  if (pipe(pipe_fds) < 0) {
    logmsg(rc, log_sys_err, "pipe() failed: %s", strerror(errno));
    goto lose;
  }
  ctx->fd = pipe_fds[0];

  if ((flags = fcntl(ctx->fd, F_GETFL, 0)) == -1) {
    logmsg(rc, log_sys_err, "fcntl(F_GETFL) failed: %s",
	   strerror(errno));
    goto lose;
  }
  flags |= O_NONBLOCK;
  if (fcntl(ctx->fd, F_SETFL, flags) == -1) {
    logmsg(rc, log_sys_err, "fcntl(F_SETFL) failed: %s",
	   strerror(errno));
    goto lose;
  }

  switch ((ctx->pid = vfork())) {

  case -1:
     logmsg(rc, log_sys_err, "vfork() failed: %s", strerror(errno));
     goto lose;

  case 0:
    /*
     * Child
     */
#define whine(msg) ((void) write(2, msg, sizeof(msg) - 1))
    if (close(pipe_fds[0]) < 0)
      whine("close(pipe_fds[0]) failed\n");
    else if (dup2(pipe_fds[1], 1) < 0)
      whine("dup2(pipe_fds[1], 1) failed\n");
    else if (dup2(pipe_fds[1], 2) < 0)
      whine("dup2(pipe_fds[1], 2) failed\n");
    else if (close(pipe_fds[1]) < 0)
      whine("close(pipe_fds[1]) failed\n");
    else if (execvp(argv[0], (char * const *) argv) < 0)
      whine("execvp(argv[0], (char * const *) argv) failed\n");
    whine("last system error: ");
    write(2, strerror(errno), strlen(strerror(errno)));
    whine("\n");
    _exit(1);
#undef whine

  default:
    /*
     * Parent
     */
    (void) close(pipe_fds[1]);
    pipe_fds[1] = -1;
    ctx->state = rsync_state_running;
    ctx->problem = rsync_problem_none;
    if (rc->rsync_timeout)
      ctx->deadline = time(0) + rc->rsync_timeout;
    logmsg(rc, log_debug, "Subprocess %u started, queued %d, runable %d, running %d, max %d, URI %s",
	   (unsigned) ctx->pid, sk_rsync_ctx_t_num(rc->rsync_queue), rsync_count_runable(rc), rsync_count_running(rc), rc->max_parallel_fetches, ctx->uri.s);
    if (ctx->handler)
      ctx->handler(rc, ctx, rsync_status_pending, &ctx->uri, ctx->wsk);
    return;

  }

 lose:
  if (pipe_fds[0] != -1)
    (void) close(pipe_fds[0]);
  if (pipe_fds[1] != -1)
    (void) close(pipe_fds[1]);
  if (rc->rsync_queue && ctx)
    (void) sk_rsync_ctx_t_delete_ptr(rc->rsync_queue, ctx);
  if (ctx && ctx->handler)
    ctx->handler(rc, ctx, rsync_status_failed, &ctx->uri, ctx->wsk);
  if (ctx)
    free(ctx);
}

/**
 * Process one line of rsync's output.  This is a separate function
 * primarily to centralize scraping for magic error strings.
 */
static void do_one_rsync_log_line(const rcynic_ctx_t *rc,
				  rsync_ctx_t *ctx)
{
  unsigned u;
  char *s;

  /*
   * Send line to our log unless it's empty.
   */
  if (ctx->buffer[strspn(ctx->buffer, " \t\n\r")] != '\0')
    logmsg(rc, log_telemetry, "rsync[%u]: %s", ctx->pid, ctx->buffer);

  /*
   * Check for magic error strings
   */
  if ((s = strstr(ctx->buffer, "@ERROR: max connections")) != NULL) {
    ctx->problem = rsync_problem_refused;
    if (sscanf(s, "@ERROR: max connections (%u) reached -- try again later", &u) == 1)
      logmsg(rc, log_debug, "Subprocess %u reported limit of %u for %s", ctx->pid, u, ctx->uri.s);
  }
}

/**
 * Construct select() arguments.
 */
static int rsync_construct_select(const rcynic_ctx_t *rc,
				  const time_t now,
				  fd_set *rfds,
				  struct timeval *tv)
{
  rsync_ctx_t *ctx;
  time_t when = 0;
  int i, n = 0;

  assert(rc && rc->rsync_queue && rfds && tv);

  FD_ZERO(rfds);

  for (i = 0; (ctx = sk_rsync_ctx_t_value(rc->rsync_queue, i)) != NULL; ++i) {
    switch (ctx->state) {

    case rsync_state_running:
      if (ctx->fd >= 0) {
	FD_SET(ctx->fd, rfds);
	if (ctx->fd > n)
	  n = ctx->fd;
      }
      if (!rc->rsync_timeout)
	continue;
      /* Fall through */

    case rsync_state_retry_wait:
      if (when == 0 || ctx->deadline < when)
	when = ctx->deadline;
      /* Fall through */

    default:
      continue;
    }
  }

  tv->tv_sec = when ? when - now : 0;
  tv->tv_usec = 0;
  return n;
}

/**
 * Manager for queue of rsync tasks in progress.
 *
 * General plan here is to process one completed child, or output
 * accumulated from children, or block if there is absolutely nothing
 * to do, on the theory that caller had nothing to do either or would
 * not have called us.  Once we've done something allegedly useful, we
 * return, because this is not the event loop; if and when the event
 * loop has nothing more important to do, we'll be called again.
 *
 * So this is the only place where the program blocks waiting for
 * children, but we only do it when we know there's nothing else
 * useful that we could be doing while we wait.
 */
static void rsync_mgr(const rcynic_ctx_t *rc)
{
  time_t now = time(0);
  int i, n, pid_status = -1;
  rsync_ctx_t *ctx = NULL;
  struct timeval tv;
  fd_set rfds;
  pid_t pid;
  char *s;

  assert(rc && rc->rsync_queue);

  /*
   * Check for exited subprocesses.
   */

  while ((pid = waitpid(-1, &pid_status, WNOHANG)) > 0) {

    /*
     * Child exited, handle it.
     */

    logmsg(rc, log_debug, "Subprocess %d exited with status %d", pid, WEXITSTATUS(pid_status));

    for (i = 0; (ctx = sk_rsync_ctx_t_value(rc->rsync_queue, i)) != NULL; ++i)
      if (ctx->pid == pid)
	break;
    if (ctx == NULL) {
      assert(i == sk_rsync_ctx_t_num(rc->rsync_queue));
      logmsg(rc, log_sys_err, "Couldn't find rsync context for pid %d", pid);
      continue;
    }

    close(ctx->fd);
    ctx->fd = -1;

    if (ctx->buflen > 0) {
      assert(ctx->buflen < sizeof(ctx->buffer));
      ctx->buffer[ctx->buflen] = '\0';
      do_one_rsync_log_line(rc, ctx);
      ctx->buflen = 0;
    }

    switch (WEXITSTATUS(pid_status)) {

    case 0:
      log_validation_status(rc, &ctx->uri, 
			    (ctx->problem == rsync_problem_timed_out
			     ? rsync_timed_out
			     : rsync_succeeded),
			    object_generation_null);
      break;

    case 5:			/* "Error starting client-server protocol" */
      /*
       * Handle remote rsyncd refusing to talk to us because we've
       * exceeded its connection limit.  Back off for a short
       * interval, then retry.
       */
      if (ctx->problem == rsync_problem_refused && ctx->tries < rc->max_retries) {
	unsigned char r;
	if (!RAND_bytes(&r, sizeof(r)))
	  r = 60;
	ctx->deadline = time(0) + rc->retry_wait_min + r;
	ctx->state = rsync_state_retry_wait;
	ctx->problem = rsync_problem_none;
	ctx->pid = 0;
	ctx->tries++;
	logmsg(rc, log_telemetry, "Scheduling retry for %s", ctx->uri.s);
	continue;
      }
      
      /* Otherwise, fall through */

    case 2:			/* "Protocol incompatibility" */
    case 4:		        /* "Requested  action  not supported" */
    case 10:			/* "Error in socket I/O" */
    case 11:			/* "Error in file I/O" */
    case 12:		   	/* "Error in rsync protocol data stream" */
    case 21:		      	/* "Some error returned by waitpid()" */
    case 30:			/* "Timeout in data send/receive" */
    case 35:		 	/* "Timeout waiting for daemon connection" */
      logmsg(rc, log_telemetry, "Adding %s to dead host cache", ctx->uri.s);
      dead_host_add(rc, &ctx->uri);

      /* Fall through */

    default:
      logmsg(rc, log_data_err, "rsync %u exited with status %d fetching %s",
	     (unsigned) pid, WEXITSTATUS(pid_status), ctx->uri.s);
      log_validation_status(rc, &ctx->uri,
			    (rc->rsync_timeout && now >= ctx->deadline
			     ? rsync_timed_out
			     : rsync_failed),
			    object_generation_null);
      break;
    }

    rsync_cache_add(rc, &ctx->uri);
    if (ctx->handler)
      ctx->handler(rc, ctx, (ctx->problem == rsync_problem_timed_out
			     ? rsync_status_timed_out
			     : WEXITSTATUS(pid_status) != 0
			     ? rsync_status_failed
			     : rsync_status_done),
		   &ctx->uri, ctx->wsk);
    (void) sk_rsync_ctx_t_delete_ptr(rc->rsync_queue, ctx);
    free(ctx);
    ctx = NULL;
  }

  if (pid == -1 && errno != EINTR && errno != ECHILD)
    logmsg(rc, log_sys_err, "waitpid() returned error: %s", strerror(errno));

  assert(rsync_count_running(rc) <= rc->max_parallel_fetches);

  /*
   * Look for rsync contexts that have become runable.
   */
  for (i = 0; (ctx = sk_rsync_ctx_t_value(rc->rsync_queue, i)) != NULL; ++i)
    if (ctx->state != rsync_state_running &&
	rsync_runable(rc, ctx) &&
	rsync_count_running(rc) < rc->max_parallel_fetches)
      rsync_run(rc, ctx);

  assert(rsync_count_running(rc) <= rc->max_parallel_fetches);

  /*
   * Check for log text from subprocesses.
   */

  n = rsync_construct_select(rc, now, &rfds, &tv);

  if (n > 0 || tv.tv_sec)
    n = select(n + 1, &rfds, NULL, NULL, tv.tv_sec ? &tv : NULL);

  if (n > 0) {

    for (i = 0; (ctx = sk_rsync_ctx_t_value(rc->rsync_queue, i)) != NULL; ++i) {
      if (ctx->fd <= 0 || !FD_ISSET(ctx->fd, &rfds))
	continue;

      assert(ctx->buflen < sizeof(ctx->buffer) - 1);

      while ((n = read(ctx->fd, ctx->buffer + ctx->buflen, sizeof(ctx->buffer) - 1 - ctx->buflen)) > 0) {
	ctx->buflen += n;
	assert(ctx->buflen < sizeof(ctx->buffer));
	ctx->buffer[ctx->buflen] = '\0';

	while ((s = strchr(ctx->buffer, '\n')) != NULL) {
	  *s++ = '\0';
	  do_one_rsync_log_line(rc, ctx);
	  assert(s > ctx->buffer && s < ctx->buffer + sizeof(ctx->buffer));
	  ctx->buflen -= s - ctx->buffer;
	  assert(ctx->buflen < sizeof(ctx->buffer));
	  if (ctx->buflen > 0)
	    memmove(ctx->buffer, s, ctx->buflen);
	  ctx->buffer[ctx->buflen] = '\0';
	}

	if (ctx->buflen == sizeof(ctx->buffer) - 1) {
	  ctx->buffer[sizeof(ctx->buffer) - 1] = '\0';
	  do_one_rsync_log_line(rc, ctx);
	  ctx->buflen = 0;
	}
      }

      if (n == 0) {
	(void) close(ctx->fd);
	ctx->fd = -1;
      }
    }
  }

  assert(rsync_count_running(rc) <= rc->max_parallel_fetches);

  /*
   * Deal with children that have been running too long.
   */
  if (rc->rsync_timeout) {
    for (i = 0; (ctx = sk_rsync_ctx_t_value(rc->rsync_queue, i)) != NULL; ++i) {
      int sig;
      if (ctx->pid <= 0 || now < ctx->deadline)
	continue;
      sig = ctx->tries++ < KILL_MAX ? SIGTERM : SIGKILL;
      if (ctx->state != rsync_state_terminating) {
	ctx->problem = rsync_problem_timed_out;
	ctx->state = rsync_state_terminating;
	ctx->tries = 0;
	logmsg(rc, log_telemetry, "Subprocess %u is taking too long fetching %s, whacking it", (unsigned) ctx->pid, ctx->uri.s);
	dead_host_add(rc, &ctx->uri);
      } else if (sig == SIGTERM) {
	logmsg(rc, log_telemetry, "Whacking subprocess %u again", (unsigned) ctx->pid);
      } else {
	logmsg(rc, log_telemetry, "Whacking subprocess %u with big hammer", (unsigned) ctx->pid);
      }
      (void) kill(ctx->pid, sig);
      ctx->deadline = now + 1;
    }
  }
}

/**
 * Set up rsync context and attempt to start it.
 */
static void rsync_init(const rcynic_ctx_t *rc,
		       const uri_t *uri,
		       STACK_OF(walk_ctx_t) *wsk,
		       void (*handler)(const rcynic_ctx_t *, const rsync_ctx_t *, const rsync_status_t, const uri_t *, STACK_OF(walk_ctx_t) *))
{
  rsync_ctx_t *ctx = NULL;

  assert(rc && uri && strlen(uri->s) > SIZEOF_RSYNC);

  if (!rc->run_rsync) {
    logmsg(rc, log_verbose, "rsync disabled, skipping %s", uri->s);
    rsync_cache_add(rc, uri);
    if (handler)
      handler(rc, NULL, rsync_status_skipped, uri, wsk);
    return;
  }

  if (rsync_cached_uri(rc, uri)) {
    logmsg(rc, log_verbose, "rsync cache hit for %s", uri->s);
    if (handler)
      handler(rc, NULL, rsync_status_done, uri, wsk);
    return;
  }

  if (dead_host_check(rc, uri)) {
    logmsg(rc, log_verbose, "Dead host cache hit for %s", uri->s);
    rsync_cache_add(rc, uri);
    if (handler)
      handler(rc, NULL, rsync_status_skipped, uri, wsk);
    return;
  }

  if ((ctx = malloc(sizeof(*ctx))) == NULL) {
    logmsg(rc, log_sys_err, "malloc(rsync_ctxt_t) failed");
    if (handler)
      handler(rc, NULL, rsync_status_failed, uri, wsk);
    return;
  }

  memset(ctx, 0, sizeof(*ctx));
  ctx->uri = *uri;
  ctx->handler = handler;
  ctx->wsk = wsk;
  ctx->fd = -1;

  if (!sk_rsync_ctx_t_push(rc->rsync_queue, ctx)) {
    logmsg(rc, log_sys_err, "Couldn't push rsync state object onto queue, punting %s", ctx->uri.s);
    if (handler)
      handler(rc, ctx, rsync_status_failed, uri, wsk);
    free(ctx);
    return;
  }

  if (rsync_conflicts(rc, ctx)) {
    logmsg(rc, log_debug, "New rsync context %s is feeling conflicted", ctx->uri.s);
    ctx->state = rsync_state_conflict_wait;
  }


#if 0
  if (rsync_runable(rc, ctx) && rsync_count_running(rc) < rc->max_parallel_fetches);
    rsync_run(rc, ctx);
#endif
}

/**
 * rsync a single file (trust anchor, CRL, manifest, ROA, whatever).
 */
static void rsync_file(const rcynic_ctx_t *rc,
		       const uri_t *uri)
{
  assert(!endswith(uri->s, "/"));
  rsync_init(rc, uri, NULL, NULL);
}

/**
 * rsync an entire subtree, generally rooted at a SIA collection.
 */
static void rsync_tree(const rcynic_ctx_t *rc,
		       const uri_t *uri,
		       STACK_OF(walk_ctx_t) *wsk,
		       void (*handler)(const rcynic_ctx_t *, const rsync_ctx_t *, const rsync_status_t, const uri_t *, STACK_OF(walk_ctx_t) *))
{
  assert(endswith(uri->s, "/"));
  rsync_init(rc, uri, wsk, handler);
}



/**
 * Clean up old stuff from previous rsync runs.  --delete doesn't help
 * if the URI changes and we never visit the old URI again.
 */
static int prune_unauthenticated(const rcynic_ctx_t *rc,
				 const path_t *name,
				 const size_t baselen)
{
  path_t path;
  struct dirent *d;
  size_t len;
  DIR *dir;
  int need_slash;

  assert(rc && name && baselen > 0);
  len = strlen(name->s);
  assert(len >= baselen && len < sizeof(path.s));
  need_slash = name->s[len - 1] != '/';

  if (rsync_cached_string(rc, name->s + baselen)) {
    logmsg(rc, log_debug, "prune: cache hit for %s, not cleaning", name->s);
    return 1;
  }

  if (rmdir(name->s) == 0) {
    logmsg(rc, log_debug, "prune: removed %s", name->s);
    return 1;
  }

  switch (errno) {
  case ENOENT:
    logmsg(rc, log_debug, "prune: nonexistant %s", name->s);
    return 1;
  case ENOTEMPTY:
    break;
  default:
    logmsg(rc, log_debug, "prune: other error %s: %s", name->s, strerror(errno));
    return 0;
  }

  if ((dir = opendir(name->s)) == NULL)
    return 0;

  while ((d = readdir(dir)) != NULL) {
    if (d->d_name[0] == '.' && (d->d_name[1] == '\0' || (d->d_name[1] == '.' && d->d_name[2] == '\0')))
      continue;
    if (len + strlen(d->d_name) + need_slash >= sizeof(path)) {
      logmsg(rc, log_debug, "prune: %s%s%s too long", name->s, (need_slash ? "/" : ""), d->d_name);
      goto done;
    }
    strcpy(path.s, name->s);
    if (need_slash)
      strcat(path.s, "/");
    strcat(path.s, d->d_name);
    switch (d->d_type) {
    case DT_DIR:
      if (!prune_unauthenticated(rc, &path, baselen))
	goto done;
      continue;
    default:
      if (rsync_cached_string(rc, path.s + baselen)) {
	logmsg(rc, log_debug, "prune: cache hit %s", path.s);
	continue;
      }
      if (unlink(path.s) < 0) {
	logmsg(rc, log_debug, "prune: removing %s failed: %s", path.s, strerror(errno));
	goto done;
      }
      logmsg(rc, log_debug, "prune: removed %s", path.s);
      continue;
    }
  }

  if (rmdir(name->s) < 0 && errno != ENOTEMPTY)
    logmsg(rc, log_debug, "prune: couldn't remove %s: %s", name->s, strerror(errno));

 done:
  closedir(dir);
  return !d;
}



/**
 * Read a DER object using a BIO pipeline that hashes the file content
 * as we read it.  Returns the internal form of the parsed DER object,
 * sets the hash buffer (if specified) as a side effect.  The default
 * hash algorithm is SHA-256.
 */
static void *read_file_with_hash(const path_t *filename,
				 const ASN1_ITEM *it,
				 const EVP_MD *md,
				 hashbuf_t *hash)
{
  void *result = NULL;
  BIO *b;

  if ((b = BIO_new_file(filename->s, "rb")) == NULL)
    goto error;

  if (hash != NULL) {
    BIO *b2 = BIO_new(BIO_f_md());
    if (b2 == NULL)
      goto error;
    if (md == NULL)
      md = EVP_sha256();
    if (!BIO_set_md(b2, md)) {
      BIO_free(b2);
      goto error;
    }
    BIO_push(b2, b);
    b = b2;
  }

  if ((result = ASN1_item_d2i_bio(it, b, NULL)) == NULL)
    goto error;

  if (hash != NULL) {
    memset(hash, 0, sizeof(*hash));
    BIO_gets(b, (char *) hash, sizeof(hash->h));
  }    

 error:
  BIO_free_all(b);
  return result;
}

/**
 * Read and hash a certificate.
 */
static X509 *read_cert(const path_t *filename, hashbuf_t *hash)
{
  return read_file_with_hash(filename, ASN1_ITEM_rptr(X509), NULL, hash);
}

/**
 * Read and hash a CRL.
 */
static X509_CRL *read_crl(const path_t *filename, hashbuf_t *hash)
{
  return read_file_with_hash(filename, ASN1_ITEM_rptr(X509_CRL), NULL, hash);
}

/**
 * Read and hash a CMS message.
 */
static CMS_ContentInfo *read_cms(const path_t *filename, hashbuf_t *hash)
{
  return read_file_with_hash(filename, ASN1_ITEM_rptr(CMS_ContentInfo), NULL, hash);
}



/**
 * Extract CRLDP data from a certificate.
 */
static void extract_crldp_uri(const rcynic_ctx_t *rc,
			      const uri_t *uri,
			      const object_generation_t generation,
			      const STACK_OF(DIST_POINT) *crldp,
			      uri_t *result)
{
  DIST_POINT *d;
  int i;

  assert(crldp);

  if (sk_DIST_POINT_num(crldp) != 1) {
    log_validation_status(rc, uri, malformed_crldp, generation);
    return;
  }

  d = sk_DIST_POINT_value(crldp, 0);

  if (d->reasons || d->CRLissuer || !d->distpoint || d->distpoint->type != 0) {
    log_validation_status(rc, uri, malformed_crldp, generation);
    return;
  }

  for (i = 0; i < sk_GENERAL_NAME_num(d->distpoint->name.fullname); i++) {
    GENERAL_NAME *n = sk_GENERAL_NAME_value(d->distpoint->name.fullname, i);
    assert(n != NULL);
    if (n->type != GEN_URI) {
      log_validation_status(rc, uri, malformed_crldp, generation);
      return;
    }
    if (!is_rsync((char *) n->d.uniformResourceIdentifier->data)) {
      logmsg(rc, log_verbose, "Skipping non-rsync URI %s for %s",
	     (char *) n->d.uniformResourceIdentifier->data, uri->s);
      continue;
    }
    if (sizeof(result->s) <= n->d.uniformResourceIdentifier->length) {
      log_validation_status(rc, uri, uri_too_long, generation);
      continue;
    }
    strcpy(result->s, (char *) n->d.uniformResourceIdentifier->data);
    return;
  }
}

/**
 * Extract SIA or AIA data from a certificate.
 */
static void extract_access_uri(const rcynic_ctx_t *rc,
			       const uri_t *uri,
			       const object_generation_t generation,
			       const AUTHORITY_INFO_ACCESS *xia,
			       const unsigned char *oid,
			       const int oidlen,
			       uri_t *result)
{
  int i;

  if (!xia)
    return;

  for (i = 0; i < sk_ACCESS_DESCRIPTION_num(xia); i++) {
    ACCESS_DESCRIPTION *a = sk_ACCESS_DESCRIPTION_value(xia, i);
    assert(a != NULL);
    if (a->location->type != GEN_URI)
      return;
    if (oid_cmp(a->method, oid, oidlen))
      continue;
    if (!is_rsync((char *) a->location->d.uniformResourceIdentifier->data)) {
      logmsg(rc, log_verbose, "Skipping non-rsync URI %s for %s",
	     a->location->d.uniformResourceIdentifier->data, uri->s);
      continue;
    }
    if (sizeof(result->s) <= a->location->d.uniformResourceIdentifier->length) {
      log_validation_status(rc, uri, uri_too_long, generation);
      continue;
    }
    strcpy(result->s, (char *) a->location->d.uniformResourceIdentifier->data);
    return;
  }
}

/**
 * Parse interesting stuff from a certificate.
 */
static void parse_cert(const rcynic_ctx_t *rc, X509 *x, certinfo_t *c, const uri_t *uri, const object_generation_t generation)
{
  STACK_OF(DIST_POINT) *crldp;
  AUTHORITY_INFO_ACCESS *xia;

  assert(x != NULL && c != NULL && uri != NULL);
  memset(c, 0, sizeof(*c));

  c->ca = X509_check_ca(x) == 1;
  c->uri = *uri;
  c->generation = generation;

  if ((xia = X509_get_ext_d2i(x, NID_info_access, NULL, NULL)) != NULL) {
    extract_access_uri(rc, uri, generation, xia, id_ad_caIssuers, sizeof(id_ad_caIssuers), &c->aia);
    sk_ACCESS_DESCRIPTION_pop_free(xia, ACCESS_DESCRIPTION_free);
  }

  if ((xia = X509_get_ext_d2i(x, NID_sinfo_access, NULL, NULL)) != NULL) {
    extract_access_uri(rc, uri, generation, xia, id_ad_caRepository, sizeof(id_ad_caRepository), &c->sia);
    extract_access_uri(rc, uri, generation, xia, id_ad_rpkiManifest, sizeof(id_ad_rpkiManifest), &c->manifest);
    sk_ACCESS_DESCRIPTION_pop_free(xia, ACCESS_DESCRIPTION_free);
  }

  if ((crldp = X509_get_ext_d2i(x, NID_crl_distribution_points, NULL, NULL)) != NULL) {
    extract_crldp_uri(rc, uri, generation, crldp, &c->crldp);
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
  }
}



/**
 * Attempt to read and check one CRL from disk.
 */

static X509_CRL *check_crl_1(const rcynic_ctx_t *rc,
			     const uri_t *uri,
			     path_t *path,
			     const path_t *prefix,
			     X509 *issuer,
			     const unsigned char *hash,
			     const size_t hashlen,
			     const object_generation_t generation)
{
  hashbuf_t hashbuf;
  X509_CRL *crl = NULL;
  EVP_PKEY *pkey;
  int ret;

  assert(uri && path && issuer);

  if (!uri_to_filename(rc, uri, path, prefix))
    goto punt;

  if (hashlen > sizeof(hashbuf.h)) {
    log_validation_status(rc, uri, hash_too_long, generation);
    goto punt;
  }

  if (hash)
    crl = read_crl(path, &hashbuf);
  else
    crl = read_crl(path, NULL);

  if (!crl)
    goto punt;

  if (hash && memcmp(hashbuf.h, hash, hashlen)) {
    log_validation_status(rc, uri, crl_digest_mismatch, generation);
    goto punt;
  }

  if (X509_cmp_current_time(X509_CRL_get_lastUpdate(crl)) > 0) {
    log_validation_status(rc, uri, crl_not_yet_valid, generation);
    goto punt;
  }

  if (X509_cmp_current_time(X509_CRL_get_nextUpdate(crl)) < 0) {
    log_validation_status(rc, uri, stale_crl, generation);
    if (!rc->allow_stale_crl)
      goto punt;
  }

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

/**
 * Check whether we already have a particular CRL, attempt to fetch it
 * and check issuer's signature if we don't.
 */
static X509_CRL *check_crl(const rcynic_ctx_t *rc,
			   const uri_t *uri,
			   X509 *issuer,
			   const unsigned char *hash,
			   const size_t hashlen)
{
  path_t path;
  X509_CRL *crl;

  if (uri_to_filename(rc, uri, &path, &rc->new_authenticated) &&
      (crl = read_crl(&path, NULL)) != NULL)
    return crl;

  logmsg(rc, log_telemetry, "Checking CRL %s", uri->s);

  if ((crl = check_crl_1(rc, uri, &path, &rc->unauthenticated,
			 issuer, hash, hashlen, object_generation_current))) {
    install_object(rc, uri, &path, object_accepted, object_generation_current);
    return crl;
  } else if (!access(path.s, F_OK)) {
    log_validation_status(rc, uri, object_rejected, object_generation_current);
  }

  if ((crl = check_crl_1(rc, uri, &path, &rc->old_authenticated,
			 issuer, hash, hashlen, object_generation_backup))) {
    install_object(rc, uri, &path, object_accepted, object_generation_backup);
    return crl;
  } else if (!access(path.s, F_OK)) {
    log_validation_status(rc, uri, object_rejected, object_generation_backup);
  }

  return NULL;
}



/**
 * Check whether extensions in a certificate are allowed by profile.
 * Also returns failure in a few null-pointer cases that can't
 * possibly conform to profile.
 */
static int check_allowed_extensions(const X509 *x, const int allow_eku)
{
  int i;

  if (x == NULL || x->cert_info == NULL || x->cert_info->extensions == NULL)
    return 0;

  for (i = 0; i < sk_X509_EXTENSION_num(x->cert_info->extensions); i++) {
    switch (OBJ_obj2nid(sk_X509_EXTENSION_value(x->cert_info->extensions,
						i)->object)) {
    case NID_basic_constraints:
    case NID_subject_key_identifier:
    case NID_authority_key_identifier:
    case NID_key_usage:
    case NID_crl_distribution_points:
    case NID_info_access:
    case NID_sinfo_access:
    case NID_certificate_policies:
    case NID_sbgp_ipAddrBlock:
    case NID_sbgp_autonomousSysNum:
      continue;
    case NID_ext_key_usage:
      if (allow_eku)
	continue;
      else
	return 0;
    default:
      return 0;
    }
  }

  return 1;
}

/**
 * Check whether a Distinguished Name conforms to the rescert profile.
 * The profile is very restrictive: it only allows one mandatory
 * CommonName field and one optional SerialNumber field, both of which
 * must be of type PrintableString.
 */
static int check_allowed_dn(X509_NAME *dn)
{
  X509_NAME_ENTRY *ne;
  ASN1_STRING *s;
  int loc;

  if (dn == NULL)
    return 0;

  switch (X509_NAME_entry_count(dn)) {

  case 2:
    if ((loc = X509_NAME_get_index_by_NID(dn, NID_serialNumber, -1)) < 0 ||
	(ne = X509_NAME_get_entry(dn, loc)) == NULL ||
	(s = X509_NAME_ENTRY_get_data(ne)) == NULL ||
	ASN1_STRING_type(s) != V_ASN1_PRINTABLESTRING)
      return 0;

    /* Fall through */

  case 1:
    if ((loc = X509_NAME_get_index_by_NID(dn, NID_commonName, -1)) < 0 ||
	(ne = X509_NAME_get_entry(dn, loc)) == NULL ||
	(s = X509_NAME_ENTRY_get_data(ne)) == NULL ||
	ASN1_STRING_type(s) != V_ASN1_PRINTABLESTRING)
      return 0;

    return 1;

  default:
    return 0;
  }
}



/**
 * Validation callback function for use with x509_verify_cert().
 */
static int check_x509_cb(int ok, X509_STORE_CTX *ctx)
{
  rcynic_x509_store_ctx_t *rctx = (rcynic_x509_store_ctx_t *) ctx;
  mib_counter_t code;

  assert(rctx != NULL);

  switch (ctx->error) {
  case X509_V_OK:
    return ok;

  case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
    /*
     * Informational events, not really errors.  ctx->check_issued()
     * is called in many places where failure to find an issuer is not
     * a failure for the calling function.  Just leave these alone.
     */
    return ok;

  case X509_V_ERR_CRL_HAS_EXPIRED:
    /*
     * This isn't really an error, exactly.  CRLs don't really
     * "expire".  What OpenSSL really means by this error is just
     * "it's now later than the issuer said it intended to publish a
     * new CRL".  Whether we treat this as an error or not is
     * configurable, see the allow_stale_crl parameter.
     *
     * Deciding whether to allow stale CRLs is check_crl_1()'s job,
     * not ours.  By the time this callback occurs, we've already
     * accepted the CRL; this callback is just notifying us that the
     * object being checked is tainted by a stale CRL.  So we mark the
     * object as tainted and carry on.
     */
    log_validation_status(rctx->rc, &rctx->subject->uri, tainted_by_stale_crl, rctx->subject->generation);
    ok = 1;
    return ok;

  case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
    /*
     * This is another error that's only an error in the strange world
     * of OpenSSL, but a more serious one.  By default, OpenSSL
     * expects all trust anchors to be self-signed.  This is not a
     * PKIX requirement, it's just an OpenSSL thing, but one violates
     * it at one's peril, because the only way to convince OpenSSL to
     * allow a non-self-signed trust anchor is to intercept this
     * "error" in the verify callback handler.
     *
     * So this program supports non-self-signed trust anchors, but be
     * warned that enabling this feature may cause this program's
     * output not to work with other OpenSSL-based applications.
     */
    if (rctx->rc->allow_non_self_signed_trust_anchor)
      ok = 1;
    log_validation_status(rctx->rc, &rctx->subject->uri, trust_anchor_not_self_signed, rctx->subject->generation);
    return ok;

  /*
   * Select correct MIB counter for every known OpenSSL verify errors
   * except the ones we handle explicitly above, then fall through to
   * common handling for all of these.
   */
#define QV(x)							\
  case x:							\
    code = mib_openssl_##x;					\
    break;
    MIB_COUNTERS_FROM_OPENSSL;
#undef	QV

  default:
    code = unknown_verify_error;
    break;
  }

  log_validation_status(rctx->rc, &rctx->subject->uri, code, rctx->subject->generation);
  return ok;
}

/**
 * Check crypto aspects of a certificate, policy OID, RFC 3779 path
 * validation, and conformance to the RPKI certificate profile.
 */
static int check_x509(const rcynic_ctx_t *rc,
		      STACK_OF(X509) *certs,
		      X509 *x,
		      const certinfo_t *subject,
		      const certinfo_t *issuer_certinfo)
{
  rcynic_x509_store_ctx_t rctx;
  STACK_OF(X509_CRL) *crls = NULL;
  EVP_PKEY *pkey = NULL;
  X509_CRL *crl = NULL;
  unsigned long flags = (X509_V_FLAG_POLICY_CHECK | X509_V_FLAG_EXPLICIT_POLICY | X509_V_FLAG_X509_STRICT);
  X509 *issuer;
  int ret = 0;

  assert(rc && certs && x && subject);

  if (!X509_STORE_CTX_init(&rctx.ctx, rc->x509_store, x, NULL))
    return 0;
  rctx.rc = rc;
  rctx.subject = subject;

  issuer = sk_X509_value(certs, sk_X509_num(certs) - 1);
  assert(issuer != NULL);

  if (subject->sia.s[0] && subject->sia.s[strlen(subject->sia.s) - 1] != '/') {
    log_validation_status(rc, &subject->uri, malformed_sia, subject->generation);
    goto done;
  }

  if (!subject->ta && !subject->aia.s[0]) {
    log_validation_status(rc, &subject->uri, aia_missing, subject->generation);
    goto done;
  }

  if (!issuer_certinfo->ta && strcmp(issuer_certinfo->uri.s, subject->aia.s)) {
    log_validation_status(rc, &subject->uri, aia_mismatch, subject->generation);
    goto done;
  }

  if (subject->ca && !subject->sia.s[0]) {
    log_validation_status(rc, &subject->uri, sia_missing, subject->generation);
    goto done;
  }

  if (subject->ca && !subject->manifest.s[0]) {
    log_validation_status(rc, &subject->uri, manifest_missing, subject->generation);
    goto done;
  }

  if (subject->ca && !startswith(subject->manifest.s, subject->sia.s)) {
    log_validation_status(rc, &subject->uri, manifest_mismatch, subject->generation);
    goto done;
  }

  if (!check_allowed_extensions(x, !subject->ca)) {
    log_validation_status(rc, &subject->uri, disallowed_extension, subject->generation);
    goto done;
  }

  if (!check_allowed_dn(X509_get_subject_name(x)))
    log_validation_status(rc, &subject->uri, nonconformant_subject_name, subject->generation);

  if (!check_allowed_dn(X509_get_issuer_name(x)))
    log_validation_status(rc, &subject->uri, nonconformant_issuer_name, subject->generation);

  if (subject->ta) {

    if (subject->crldp.s[0]) {
      log_validation_status(rc, &subject->uri, trust_anchor_with_crldp, subject->generation);
      goto done;
    }

  } else {

    if (!subject->crldp.s[0]) {
      log_validation_status(rc, &subject->uri, crldp_missing, subject->generation);
      goto done;
    }

    if (!subject->ca && !startswith(subject->crldp.s, issuer_certinfo->sia.s)) {
      log_validation_status(rc, &subject->uri, crldp_mismatch, subject->generation);
      goto done;
    }
 
    flags |= X509_V_FLAG_CRL_CHECK;

    if ((pkey = X509_get_pubkey(issuer)) == NULL || X509_verify(x, pkey) <= 0) {
      log_validation_status(rc, &subject->uri, certificate_bad_signature, subject->generation);
      goto done;
    }

    if ((crl = check_crl(rc, &subject->crldp, issuer, NULL, 0)) == NULL) {
      log_validation_status(rc, &subject->uri, certificate_bad_crl, subject->generation);
      goto done;
    }

    if ((crls = sk_X509_CRL_new_null()) == NULL || !sk_X509_CRL_push(crls, crl)) {
      logmsg(rc, log_sys_err,
	     "Internal allocation error setting up CRL for validation");
      goto done;
    }
    crl = NULL;

    X509_STORE_CTX_set0_crls(&rctx.ctx, crls);

  }

  X509_STORE_CTX_trusted_stack(&rctx.ctx, certs);
  X509_STORE_CTX_set_verify_cb(&rctx.ctx, check_x509_cb);

  X509_VERIFY_PARAM_set_flags(rctx.ctx.param, flags);

  X509_VERIFY_PARAM_add0_policy(rctx.ctx.param, OBJ_txt2obj(rpki_policy_oid, 1));

  if (X509_verify_cert(&rctx.ctx) <= 0) {
    log_validation_status(rc, &subject->uri, certificate_failed_validation, subject->generation);
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

/**
 * Load certificate, check against manifest, then run it through all
 * the check_x509() tests.
 */
static X509 *check_cert_1(const rcynic_ctx_t *rc,
			  const uri_t *uri,
			  path_t *path,
			  const path_t *prefix,
			  STACK_OF(X509) *certs,
			  const certinfo_t *issuer,
			  certinfo_t *subject,
			  const unsigned char *hash,
			  const size_t hashlen,
			  object_generation_t generation)
{
  hashbuf_t hashbuf;
  X509 *x = NULL;

  assert(uri && path && certs && issuer && subject);

  if (!uri_to_filename(rc, uri, path, prefix))
    return NULL;

  if (access(path->s, R_OK))
    return NULL;

  if (hashlen > sizeof(hashbuf.h)) {
    log_validation_status(rc, uri, hash_too_long, generation);
    goto punt;
  }

  if (hash)
    x = read_cert(path, &hashbuf);
  else
    x = read_cert(path, NULL);

  if (!x) {
    logmsg(rc, log_sys_err, "Can't read certificate %s", path->s);
    goto punt;
  }

  if (hash && memcmp(hashbuf.h, hash, hashlen)) {
    log_validation_status(rc, uri, certificate_digest_mismatch, generation);
    goto punt;
  }

  parse_cert(rc, x, subject, uri, generation);

  if (check_x509(rc, certs, x, subject, issuer))
    return x;

 punt:
  X509_free(x);
  return NULL;
}

/**
 * Try to find a good copy of a certificate either in fresh data or in
 * backup data from a previous run of this program.
 */
static X509 *check_cert(rcynic_ctx_t *rc,
			uri_t *uri,
			STACK_OF(walk_ctx_t) *wsk,
			certinfo_t *subject,
			const unsigned char *hash,
			const size_t hashlen)
{
  walk_ctx_t *w = walk_ctx_stack_head(wsk);
  object_generation_t generation;
  const certinfo_t *issuer = NULL;
  STACK_OF(X509) *certs = NULL;
  const path_t *prefix = NULL;
  path_t path;
  X509 *x;

  assert(rc && uri && wsk && w && subject);

  issuer = &w->certinfo;

  switch (w->state) {
  case walk_state_current:
    prefix = &rc->unauthenticated;
    generation = object_generation_current;
    break;
  case walk_state_backup:
    prefix = &rc->old_authenticated;
    generation = object_generation_backup;
    break;
  default:
    return NULL;
  }

  /*
   * If target file already exists and we're not here to recheck with
   * better data, just get out now.
   */

  if (uri_to_filename(rc, uri, &path, &rc->new_authenticated) && 
      !access(path.s, R_OK)) {
    if (w->state == walk_state_backup || sk_OPENSSL_STRING_find(rc->backup_cache, uri->s) < 0)
      return NULL;
    assert(generation == object_generation_current);
    log_validation_status(rc, uri, current_cert_recheck, generation);
    logmsg(rc, log_telemetry, "Rechecking %s", uri->s);
  } else {
    logmsg(rc, log_telemetry, "Checking %s", uri->s);
  }

  if ((certs = walk_ctx_stack_certs(wsk)) == NULL)
    return NULL;

  if ((x = check_cert_1(rc, uri, &path, prefix, certs, issuer, subject, hash, hashlen, generation)) != NULL) {
    install_object(rc, uri, &path, object_accepted, generation);
    if (w->state == walk_state_current)
      sk_OPENSSL_STRING_remove(rc->backup_cache, uri->s);
    else if (!sk_OPENSSL_STRING_push_strdup(rc->backup_cache, uri->s))
      logmsg(rc, log_sys_err, "Couldn't cache URI %s, blundering onward", uri->s);
      
  } else if (!access(path.s, F_OK)) {
    log_validation_status(rc, uri, object_rejected, generation);
  }

  sk_X509_free(certs);
  certs = NULL;

  return x;
}



/**
 * Read and check one manifest from disk.
 */
static Manifest *check_manifest_1(const rcynic_ctx_t *rc,
				  const uri_t *uri,
				  path_t *path,
				  const path_t *prefix,
				  STACK_OF(X509) *certs,
				  const object_generation_t generation)
{
  CMS_ContentInfo *cms = NULL;
  const ASN1_OBJECT *eContentType = NULL;
  STACK_OF(X509) *signers = NULL;
  STACK_OF(X509_CRL) *crls = NULL;
  X509_CRL *crl = NULL;
  Manifest *manifest = NULL, *result = NULL;
  BIO *bio = NULL;
  rcynic_x509_store_ctx_t rctx;
  certinfo_t certinfo;
  int i, initialized_store_ctx = 0;
  FileAndHash *fah = NULL;
  char *crl_tail;

  assert(rc && uri && path && prefix && certs && sk_X509_num(certs));

  if (!uri_to_filename(rc, uri, path, prefix) ||
      (cms = read_cms(path, NULL)) == NULL)
    goto done;

  if ((eContentType = CMS_get0_eContentType(cms)) == NULL ||
      oid_cmp(eContentType, id_ct_rpkiManifest, sizeof(id_ct_rpkiManifest))) {
    log_validation_status(rc, uri, manifest_bad_econtenttype, generation);
    goto done;
  }

  if ((bio = BIO_new(BIO_s_mem())) == NULL) {
    logmsg(rc, log_sys_err, "Couldn't allocate BIO for manifest %s", uri->s);
    goto done;
  }

  if (CMS_verify(cms, NULL, NULL, NULL, bio, CMS_NO_SIGNER_CERT_VERIFY) <= 0) {
    log_validation_status(rc, uri, manifest_invalid_cms, generation);
    goto done;
  }

  if ((signers = CMS_get0_signers(cms)) == NULL || sk_X509_num(signers) != 1) {
    log_validation_status(rc, uri, manifest_missing_signer, generation);
    goto done;
  }

  parse_cert(rc, sk_X509_value(signers, 0), &certinfo, uri, generation);

  if (!certinfo.crldp.s[0]) {
    log_validation_status(rc, uri, manifest_missing_crldp, generation);
    goto done;
  }

  if ((crl_tail = strrchr(certinfo.crldp.s, '/')) == NULL) {
    log_validation_status(rc, uri, manifest_malformed_crldp, generation);
    goto done;
  }
  crl_tail++;

  if ((manifest = ASN1_item_d2i_bio(ASN1_ITEM_rptr(Manifest), bio, NULL)) == NULL) {
    log_validation_status(rc, uri, manifest_decode_error, generation);
    goto done;
  }

  if (manifest->version) {
    log_validation_status(rc, uri, manifest_wrong_version, generation);
    goto done;
  }

  if (X509_cmp_current_time(manifest->thisUpdate) > 0) {
    log_validation_status(rc, uri, manifest_not_yet_valid, generation);
    goto done;
  }

  if (X509_cmp_current_time(manifest->nextUpdate) < 0) {
    log_validation_status(rc, uri, stale_manifest, generation);
    if (!rc->allow_stale_manifest)
      goto done;
  }

  if (manifest->fileHashAlg == NULL ||
      oid_cmp(manifest->fileHashAlg, id_sha256, sizeof(id_sha256)))
    goto done;

  for (i = 0; (fah = sk_FileAndHash_value(manifest->fileList, i)) != NULL; i++)
    if (!strcmp((char *) fah->file->data, crl_tail))
      break;

  if (fah) {
    crl = check_crl(rc, &certinfo.crldp,
		    sk_X509_value(certs, sk_X509_num(certs) - 1),
		    fah->hash->data, fah->hash->length);
  } else {
    log_validation_status(rc, uri, crl_not_in_manifest, generation);
    if (rc->require_crl_in_manifest)
      goto done;
    crl = check_crl(rc, &certinfo.crldp,
		    sk_X509_value(certs, sk_X509_num(certs) - 1),
		    NULL, 0);
  }

  if (!crl)
    goto done;

  if ((crls = sk_X509_CRL_new_null()) == NULL || !sk_X509_CRL_push(crls, crl))
    goto done;
  crl = NULL;

  if (!(initialized_store_ctx = X509_STORE_CTX_init(&rctx.ctx, rc->x509_store, sk_X509_value(signers, 0), NULL)))
    goto done;
  
  rctx.rc = rc;
  rctx.subject = &certinfo;

  X509_STORE_CTX_trusted_stack(&rctx.ctx, certs);
  X509_STORE_CTX_set0_crls(&rctx.ctx, crls);
  X509_STORE_CTX_set_verify_cb(&rctx.ctx, check_x509_cb);

  X509_VERIFY_PARAM_set_flags(rctx.ctx.param,
			      X509_V_FLAG_CRL_CHECK |
			      X509_V_FLAG_POLICY_CHECK |
			      X509_V_FLAG_EXPLICIT_POLICY |
			      X509_V_FLAG_X509_STRICT);

  X509_VERIFY_PARAM_add0_policy(rctx.ctx.param, OBJ_txt2obj(rpki_policy_oid, 1));

  if (X509_verify_cert(&rctx.ctx) <= 0) {
    /*
     * Redundant error message?
     */
    log_validation_status(rc, uri, manifest_invalid_ee, generation);
    goto done;
  }

  result = manifest;
  manifest = NULL;

 done:
  if (initialized_store_ctx)
    X509_STORE_CTX_cleanup(&rctx.ctx);
  BIO_free(bio);
  Manifest_free(manifest);
  CMS_ContentInfo_free(cms);
  sk_X509_free(signers);
  sk_X509_CRL_pop_free(crls, X509_CRL_free);

  return result;
}

/**
 * Check whether we already have a particular manifest, attempt to fetch it
 * and check issuer's signature if we don't.
 */
static Manifest *check_manifest(const rcynic_ctx_t *rc,
				STACK_OF(walk_ctx_t) *wsk)
{
  walk_ctx_t *w = walk_ctx_stack_head(wsk);
  CMS_ContentInfo *cms = NULL;
  Manifest *manifest = NULL;
  STACK_OF(X509) *certs = NULL;
  BIO *bio = NULL;
  path_t path;
  uri_t *uri;

  assert(rc && wsk && w);

  uri = &w->certinfo.manifest;

  if (uri_to_filename(rc, uri, &path, &rc->new_authenticated) &&
      (cms = read_cms(&path, NULL)) != NULL &&
      (bio = BIO_new(BIO_s_mem()))!= NULL &&
      CMS_verify(cms, NULL, NULL, NULL, bio,
		 CMS_NO_SIGNER_CERT_VERIFY |
		 CMS_NO_ATTR_VERIFY |
		 CMS_NO_CONTENT_VERIFY) > 0)
    manifest = ASN1_item_d2i_bio(ASN1_ITEM_rptr(Manifest), bio, NULL);

  CMS_ContentInfo_free(cms);
  BIO_free(bio);

  if (manifest != NULL)
    return manifest;

  logmsg(rc, log_telemetry, "Checking manifest %s", uri->s);

  if ((certs = walk_ctx_stack_certs(wsk)) == NULL)
    return NULL;

  if (manifest == NULL) {
    if ((manifest = check_manifest_1(rc, uri, &path,
				     &rc->unauthenticated, certs, object_generation_current)) != NULL)
      install_object(rc, uri, &path, object_accepted, object_generation_current);
    else if (!access(path.s, F_OK))
      log_validation_status(rc, uri, object_rejected, object_generation_current);
  }

  if (manifest == NULL) {
    if ((manifest = check_manifest_1(rc, uri, &path,
				     &rc->old_authenticated, certs, object_generation_backup)) != NULL)
      install_object(rc, uri, &path, object_accepted, object_generation_backup);
    else if (!access(path.s, F_OK))
      log_validation_status(rc, uri, object_rejected, object_generation_backup);
  }

  sk_X509_free(certs);
  certs = NULL;

  return manifest;
}



/**
 * Extract a ROA prefix from the ASN.1 bitstring encoding.
 */
static int extract_roa_prefix(unsigned char *addr,
			      unsigned *prefixlen,
			      const ASN1_BIT_STRING *bs,
			      const unsigned afi)
{
  unsigned length;

  switch (afi) {
  case IANA_AFI_IPV4: length =  4; break;
  case IANA_AFI_IPV6: length = 16; break;
  default: return 0;
  }

  if (bs->length < 0 || bs->length > length)
    return 0;

  if (bs->length > 0) {
    memcpy(addr, bs->data, bs->length);
    if ((bs->flags & 7) != 0) {
      unsigned char mask = 0xFF >> (8 - (bs->flags & 7));
      addr[bs->length - 1] &= ~mask;
    }
  }

  memset(addr + bs->length, 0, length - bs->length);

  *prefixlen = (bs->length * 8) - (bs->flags & 7);

  return 1;
}

/**
 * Read and check one ROA from disk.
 */
static int check_roa_1(const rcynic_ctx_t *rc,
		       const uri_t *uri,
		       path_t *path,
		       const path_t *prefix,
		       STACK_OF(X509) *certs,
		       const unsigned char *hash,
		       const size_t hashlen,
		       const object_generation_t generation)
{
  unsigned char addrbuf[ADDR_RAW_BUF_LEN];
  const ASN1_OBJECT *eContentType = NULL;
  STACK_OF(IPAddressFamily) *roa_resources = NULL, *ee_resources = NULL;
  STACK_OF(X509_CRL) *crls = NULL;
  STACK_OF(X509) *signers = NULL;
  CMS_ContentInfo *cms = NULL;
  X509_CRL *crl = NULL;
  hashbuf_t hashbuf;
  ROA *roa = NULL;
  BIO *bio = NULL;
  rcynic_x509_store_ctx_t rctx;
  certinfo_t certinfo;
  int i, j, initialized_store_ctx = 0, result = 0;
  unsigned afi, *safi = NULL, safi_, prefixlen;
  ROAIPAddressFamily *rf;
  ROAIPAddress *ra;

  assert(rc && uri && path && prefix && certs && sk_X509_num(certs));

  if (!uri_to_filename(rc, uri, path, prefix))
    goto error;

  if (hashlen > sizeof(hashbuf.h)) {
    log_validation_status(rc, uri, hash_too_long, generation);
    goto error;
  }

  if (hash)
    cms = read_cms(path, &hashbuf);
  else
    cms = read_cms(path, NULL);

  if (!cms)
    goto error;

  if (hash && memcmp(hashbuf.h, hash, hashlen)) {
    log_validation_status(rc, uri, roa_digest_mismatch, generation);
    goto error;
  }

  if (!(eContentType = CMS_get0_eContentType(cms)) ||
      oid_cmp(eContentType, id_ct_routeOriginAttestation,
	      sizeof(id_ct_routeOriginAttestation))) {
    log_validation_status(rc, uri, roa_bad_econtenttype, generation);
    goto error;
  }

  if ((bio = BIO_new(BIO_s_mem())) == NULL) {
    logmsg(rc, log_sys_err, "Couldn't allocate BIO for ROA %s", uri->s);
    goto error;
  }

  if (CMS_verify(cms, NULL, NULL, NULL, bio, CMS_NO_SIGNER_CERT_VERIFY) <= 0) {
    log_validation_status(rc, uri, roa_invalid_cms, generation);
    goto error;
  }

  if (!(signers = CMS_get0_signers(cms)) || sk_X509_num(signers) != 1) {
    log_validation_status(rc, uri, roa_missing_signer, generation);
    goto error;
  }

  parse_cert(rc, sk_X509_value(signers, 0), &certinfo, uri, generation);

  if (!(roa = ASN1_item_d2i_bio(ASN1_ITEM_rptr(ROA), bio, NULL))) {
    log_validation_status(rc, uri, roa_decode_error, generation);
    goto error;
  }

  if (roa->version) {
    log_validation_status(rc, uri, roa_wrong_version, generation);
    goto error;
  }

  /*
   * ROA issuer doesn't need rights to the ASN, so we don't need to
   * check the asID field.
   */

  ee_resources = X509_get_ext_d2i(sk_X509_value(signers, 0), NID_sbgp_ipAddrBlock, NULL, NULL);

  /*
   * Extract prefixes from ROA and convert them into a resource set.
   */

  if (!(roa_resources = sk_IPAddressFamily_new_null()))
    goto error;

  for (i = 0; i < sk_ROAIPAddressFamily_num(roa->ipAddrBlocks); i++) {
    rf = sk_ROAIPAddressFamily_value(roa->ipAddrBlocks, i);
    if (!rf || !rf->addressFamily || rf->addressFamily->length < 2 || rf->addressFamily->length > 3) {
      log_validation_status(rc, uri, malformed_roa_addressfamily, generation);
      goto error;
    }
    afi = (rf->addressFamily->data[0] << 8) | (rf->addressFamily->data[1]);
    if (rf->addressFamily->length == 3)
      *(safi = &safi_) = rf->addressFamily->data[2];
    for (j = 0; j < sk_ROAIPAddress_num(rf->addresses); j++) {
      ra = sk_ROAIPAddress_value(rf->addresses, j);
      if (!ra ||
	  !extract_roa_prefix(addrbuf, &prefixlen, ra->IPAddress, afi) ||
	  !v3_addr_add_prefix(roa_resources, afi, safi, addrbuf, prefixlen)) {
	log_validation_status(rc, uri, roa_resources_malformed, generation);
	goto error;
      }
    }
  }

  /*
   * ROAs can include nested prefixes, so direct translation to
   * resource sets could include overlapping ranges, which is illegal.
   * So we have to remove nested stuff before whacking into canonical
   * form.  Fortunately, this is relatively easy, since we know these
   * are just prefixes, not ranges: in a list of prefixes sorted by
   * the RFC 3779 rules, the first element of a set of nested prefixes
   * will always be the least specific.
   */

  for (i = 0; i < sk_IPAddressFamily_num(roa_resources); i++) {
    IPAddressFamily *f = sk_IPAddressFamily_value(roa_resources, i);

    if ((afi = v3_addr_get_afi(f)) == 0) {
      log_validation_status(rc, uri, roa_bad_afi, generation);
      goto error;
    }

    if (f->ipAddressChoice->type == IPAddressChoice_addressesOrRanges) {
      IPAddressOrRanges *aors = f->ipAddressChoice->u.addressesOrRanges;

      sk_IPAddressOrRange_sort(aors);

      for (j = 0; j < sk_IPAddressOrRange_num(aors) - 1; j++) {
	IPAddressOrRange *a = sk_IPAddressOrRange_value(aors, j);
	IPAddressOrRange *b = sk_IPAddressOrRange_value(aors, j + 1);
	unsigned char a_min[ADDR_RAW_BUF_LEN], a_max[ADDR_RAW_BUF_LEN];
	unsigned char b_min[ADDR_RAW_BUF_LEN], b_max[ADDR_RAW_BUF_LEN];
	int length;

	if ((length = v3_addr_get_range(a, afi, a_min, a_max, ADDR_RAW_BUF_LEN)) == 0 ||
	    (length = v3_addr_get_range(b, afi, b_min, b_max, ADDR_RAW_BUF_LEN)) == 0) {
	  log_validation_status(rc, uri, roa_resources_malformed, generation);
	  goto error;
	}

	if (memcmp(a_max, b_max, length) >= 0) {
	  (void) sk_IPAddressOrRange_delete(aors, j + 1);
	  IPAddressOrRange_free(b);
	  --j;
	}
      }
    }
  }

  if (!v3_addr_canonize(roa_resources)) {
    log_validation_status(rc, uri, roa_resources_malformed, generation);
    goto error;
  }

  if (!v3_addr_subset(roa_resources, ee_resources)) {
    log_validation_status(rc, uri, roa_not_nested, generation);
    goto error;
  }

  if (!(crl = check_crl(rc, &certinfo.crldp, sk_X509_value(certs, sk_X509_num(certs) - 1), NULL, 0))) {
    log_validation_status(rc, uri, roa_bad_crl, generation);
    goto error;
  }

  if (!(crls = sk_X509_CRL_new_null()) || !sk_X509_CRL_push(crls, crl))
    goto error;
  crl = NULL;

  if (!(initialized_store_ctx = X509_STORE_CTX_init(&rctx.ctx, rc->x509_store, sk_X509_value(signers, 0), NULL)))
    goto error;
  
  rctx.rc = rc;
  rctx.subject = &certinfo;

  X509_STORE_CTX_trusted_stack(&rctx.ctx, certs);
  X509_STORE_CTX_set0_crls(&rctx.ctx, crls);
  X509_STORE_CTX_set_verify_cb(&rctx.ctx, check_x509_cb);

  X509_VERIFY_PARAM_set_flags(rctx.ctx.param,
			      X509_V_FLAG_CRL_CHECK |
			      X509_V_FLAG_POLICY_CHECK |
			      X509_V_FLAG_EXPLICIT_POLICY |
			      X509_V_FLAG_X509_STRICT);

  X509_VERIFY_PARAM_add0_policy(rctx.ctx.param, OBJ_txt2obj(rpki_policy_oid, 1));

  if (X509_verify_cert(&rctx.ctx) <= 0) {
    /*
     * Redundant error message?
     */
    log_validation_status(rc, uri, roa_invalid_ee, generation);
    goto error;
  }

  result = 1;

 error:
  if (initialized_store_ctx)
    X509_STORE_CTX_cleanup(&rctx.ctx);
  BIO_free(bio);
  ROA_free(roa);
  CMS_ContentInfo_free(cms);
  sk_X509_free(signers);
  sk_X509_CRL_pop_free(crls, X509_CRL_free);
  sk_IPAddressFamily_pop_free(roa_resources, IPAddressFamily_free);
  sk_IPAddressFamily_pop_free(ee_resources, IPAddressFamily_free);

  return result;
}

/**
 * Check whether we already have a particular ROA, attempt to fetch it
 * and check issuer's signature if we don't.
 */
static void check_roa(const rcynic_ctx_t *rc,
		      const uri_t *uri,
		      STACK_OF(walk_ctx_t) *wsk,
		      const unsigned char *hash,
		      const size_t hashlen)
{
  STACK_OF(X509) *certs = NULL;
  path_t path;

  assert(rc && uri && wsk);

  if (uri_to_filename(rc, uri, &path, &rc->new_authenticated) &&
      !access(path.s, F_OK))
    return;

  logmsg(rc, log_telemetry, "Checking ROA %s", uri->s);

  if ((certs = walk_ctx_stack_certs(wsk)) == NULL)
    return;

  if (check_roa_1(rc, uri, &path, &rc->unauthenticated,
		  certs, hash, hashlen, object_generation_current)) {
    install_object(rc, uri, &path, object_accepted, object_generation_current);
    goto done;
  } else if (!access(path.s, F_OK)) {
    log_validation_status(rc, uri, object_rejected, object_generation_current);
  }

  if (check_roa_1(rc, uri, &path, &rc->old_authenticated,
		  certs, hash, hashlen, object_generation_backup)) {
    install_object(rc, uri, &path, object_accepted, object_generation_backup);
    goto done;
  } else if (!access(path.s, F_OK)) {
    log_validation_status(rc, uri, object_rejected, object_generation_backup);
  }

 done:
  sk_X509_free(certs);
}



/**
 * Read and check one Ghostbuster record from disk.
 */
static int check_ghostbuster_1(const rcynic_ctx_t *rc,
			       const uri_t *uri,
			       path_t *path,
			       const path_t *prefix,
			       STACK_OF(X509) *certs,
			       const unsigned char *hash,
			       const size_t hashlen,
			       const object_generation_t generation)
{
  const ASN1_OBJECT *eContentType = NULL;
  STACK_OF(X509_CRL) *crls = NULL;
  STACK_OF(X509) *signers = NULL;
  CMS_ContentInfo *cms = NULL;
  X509_CRL *crl = NULL;
  hashbuf_t hashbuf;
  BIO *bio = NULL;
  rcynic_x509_store_ctx_t rctx;
  certinfo_t certinfo;
  int initialized_store_ctx = 0, result = 0;

  assert(rc && uri && path && prefix && certs && sk_X509_num(certs));

  if (!uri_to_filename(rc, uri, path, prefix))
    goto error;

  if (hashlen > sizeof(hashbuf.h)) {
    log_validation_status(rc, uri, hash_too_long, generation);
    goto error;
  }

  if (hash)
    cms = read_cms(path, &hashbuf);
  else
    cms = read_cms(path, NULL);

  if (!cms)
    goto error;

  if (hash && memcmp(hashbuf.h, hash, hashlen)) {
    log_validation_status(rc, uri, ghostbuster_digest_mismatch, generation);
    goto error;
  }

  if (!(eContentType = CMS_get0_eContentType(cms)) ||
      oid_cmp(eContentType, id_ct_rpkiGhostbusters,
	      sizeof(id_ct_rpkiGhostbusters))) {
    log_validation_status(rc, uri, ghostbuster_bad_econtenttype, generation);
    goto error;
  }

#if 0
  /*
   * May want this later if we're going to inspect the VCard.  For now,
   * just leave this NULL and the right thing should happen.
   */
  if ((bio = BIO_new(BIO_s_mem())) == NULL) {
    logmsg(rc, log_sys_err, "Couldn't allocate BIO for Ghostbuster record %s", uri->s);
    goto error;
  }
#endif

  if (CMS_verify(cms, NULL, NULL, NULL, bio, CMS_NO_SIGNER_CERT_VERIFY) <= 0) {
    log_validation_status(rc, uri, ghostbuster_invalid_cms, generation);
    goto error;
  }

  if (!(signers = CMS_get0_signers(cms)) || sk_X509_num(signers) != 1) {
    log_validation_status(rc, uri, ghostbuster_missing_signer, generation);
    goto error;
  }

  parse_cert(rc, sk_X509_value(signers, 0), &certinfo, uri, generation);

#if 0
  /*
   * Here is where we would read the VCard from the bio returned by
   * CMS_verify() so that we could check the VCard.
   */
#endif

  if (!(crl = check_crl(rc, &certinfo.crldp, sk_X509_value(certs, sk_X509_num(certs) - 1), NULL, 0))) {
    log_validation_status(rc, uri, ghostbuster_bad_crl, generation);
    goto error;
  }

  if (!(crls = sk_X509_CRL_new_null()) || !sk_X509_CRL_push(crls, crl))
    goto error;
  crl = NULL;

  if (!(initialized_store_ctx = X509_STORE_CTX_init(&rctx.ctx, rc->x509_store, sk_X509_value(signers, 0), NULL)))
    goto error;
  
  rctx.rc = rc;
  rctx.subject = &certinfo;

  X509_STORE_CTX_trusted_stack(&rctx.ctx, certs);
  X509_STORE_CTX_set0_crls(&rctx.ctx, crls);
  X509_STORE_CTX_set_verify_cb(&rctx.ctx, check_x509_cb);

  X509_VERIFY_PARAM_set_flags(rctx.ctx.param,
			      X509_V_FLAG_CRL_CHECK |
			      X509_V_FLAG_POLICY_CHECK |
			      X509_V_FLAG_EXPLICIT_POLICY |
			      X509_V_FLAG_X509_STRICT);

  X509_VERIFY_PARAM_add0_policy(rctx.ctx.param, OBJ_txt2obj(rpki_policy_oid, 1));

  if (X509_verify_cert(&rctx.ctx) <= 0) {
    log_validation_status(rc, uri, ghostbuster_invalid_ee, generation);
    goto error;
  }

  result = 1;

 error:
  if (initialized_store_ctx)
    X509_STORE_CTX_cleanup(&rctx.ctx);
  BIO_free(bio);
  CMS_ContentInfo_free(cms);
  sk_X509_free(signers);
  sk_X509_CRL_pop_free(crls, X509_CRL_free);

  return result;
}

/**
 * Check whether we already have a particular Ghostbuster record,
 * attempt to fetch it and check issuer's signature if we don't.
 */
static void check_ghostbuster(const rcynic_ctx_t *rc,
			      const uri_t *uri,
			      STACK_OF(walk_ctx_t) *wsk,
			      const unsigned char *hash,
			      const size_t hashlen)
{
  STACK_OF(X509) *certs = NULL;
  path_t path;

  assert(rc && uri && wsk);

  if (uri_to_filename(rc, uri, &path, &rc->new_authenticated) &&
      !access(path.s, F_OK))
    return;

  logmsg(rc, log_telemetry, "Checking Ghostbuster record %s", uri->s);

  if ((certs = walk_ctx_stack_certs(wsk)) == NULL)
    return;

  if (check_ghostbuster_1(rc, uri, &path, &rc->unauthenticated,
			  certs, hash, hashlen, object_generation_current)) {
    install_object(rc, uri, &path, object_accepted, object_generation_current);
    goto done;
  } else if (!access(path.s, F_OK)) {
    log_validation_status(rc, uri, object_rejected, object_generation_current);
  }

  if (check_ghostbuster_1(rc, uri, &path, &rc->old_authenticated,
			  certs, hash, hashlen, object_generation_backup)) {
    install_object(rc, uri, &path, object_accepted, object_generation_backup);
    goto done;
  } else if (!access(path.s, F_OK)) {
    log_validation_status(rc, uri, object_rejected, object_generation_backup);
  }

 done:
  sk_X509_free(certs);
}



static void walk_cert(rcynic_ctx_t *, STACK_OF(walk_ctx_t) *);

/**
 * rsync callback for fetching SIA tree.
 */
static void rsync_sia_callback(const rcynic_ctx_t *rc,
			       const rsync_ctx_t *ctx,
			       const rsync_status_t status,
			       const uri_t *uri,
			       STACK_OF(walk_ctx_t) *wsk)
{
  walk_ctx_t *w = walk_ctx_stack_head(wsk);

  assert(rc && wsk);

  switch (status) {

  case rsync_status_pending:
    if (rsync_count_runable(rc) >= rc->max_parallel_fetches)
      return;

    assert(rsync_count_running(rc) < rc->max_parallel_fetches);

    if ((wsk = walk_ctx_stack_clone(wsk)) == NULL) {
      logmsg(rc, log_sys_err, "walk_ctx_stack_clone() failed, probably memory exhaustion, blundering onwards without forking stack");
      return;
    }

    walk_ctx_stack_pop(wsk);
    task_add(rc, walk_cert, wsk);
    return;

  case rsync_status_failed:
    log_validation_status(rc, uri, rsync_failed, object_generation_null);
    break;

  case rsync_status_timed_out:
    log_validation_status(rc, uri, rsync_timed_out, object_generation_null);
    break;

  case rsync_status_skipped:
    log_validation_status(rc, uri, rsync_skipped, object_generation_null);
    break;

  case rsync_status_done:
    break;
  }

  w->state++;
  task_add(rc, walk_cert, wsk);
}

/**
 * Recursive walk of certificate hierarchy (core of the program).
 *
 * Walk all products of the current certificate, starting with the
 * ones named in the manifest and continuing with any that we find in
 * the publication directory but which are not named in the manifest.
 *
 * Dispatch to correct checking code for the object named by URI,
 * based on the filename extension in the uri.  CRLs are a special
 * case because we've already checked them by the time we get here, so
 * we just ignore them.  Other objects are either certificates or
 * CMS-signed objects of one kind or another.
 */
static void walk_cert(rcynic_ctx_t *rc, STACK_OF(walk_ctx_t) *wsk)
{
  const unsigned char *hash = NULL;
  object_generation_t generation;
  size_t hashlen;
  walk_ctx_t *w;
  uri_t uri;

  assert(rc && wsk);

  while ((w = walk_ctx_stack_head(wsk)) != NULL) {

    switch (w->state) {
    case walk_state_current:
      generation = object_generation_current;
      break;
    case walk_state_backup:
      generation = object_generation_backup;
      break;
    default:
      generation = object_generation_null;
      break;
    }

    switch (w->state) {

    case walk_state_initial:

      if (!w->certinfo.sia.s[0] || !w->certinfo.ca) {
	w->state = walk_state_done;
	continue;
      }
      
      if (!w->certinfo.manifest.s[0]) {
	log_validation_status(rc, &w->certinfo.uri, manifest_missing, w->certinfo.generation);
	w->state = walk_state_done;
	continue;
      }

      w->state++;
      continue;

    case walk_state_rsync:

      rsync_tree(rc, &w->certinfo.sia, wsk, rsync_sia_callback);
      return;

    case walk_state_ready:

      walk_ctx_loop_init(rc, wsk);      /* sets w->state */
      continue;

    case walk_state_current:
    case walk_state_backup:

      if (!walk_ctx_loop_this(rc, wsk, &uri, &hash, &hashlen)) {
	walk_ctx_loop_next(rc, wsk);
	continue;
      }

      if (endswith(uri.s, ".crl") || endswith(uri.s, ".mft") || endswith(uri.s, ".mnf")) {
	walk_ctx_loop_next(rc, wsk);
	continue;			/* CRLs and manifests checked elsewhere */
      }

      if (hash == NULL)
	log_validation_status(rc, &uri, tainted_by_not_being_in_manifest, generation);
      else if (w->stale_manifest)
	log_validation_status(rc, &uri, tainted_by_stale_manifest, generation);

      if (hash == NULL && !rc->allow_object_not_in_manifest) {
	walk_ctx_loop_next(rc, wsk);
	continue;
      }

      if (endswith(uri.s, ".roa")) {
	check_roa(rc, &uri, wsk, hash, hashlen);
	walk_ctx_loop_next(rc, wsk);
	continue;
      }

      if (endswith(uri.s, ".gbr")) {
	check_ghostbuster(rc, &uri, wsk, hash, hashlen);
	walk_ctx_loop_next(rc, wsk);
	continue;
      }

      if (endswith(uri.s, ".cer")) {
	certinfo_t subject;
	X509 *x = check_cert(rc, &uri, wsk, &subject, hash, hashlen);
	if (!walk_ctx_stack_push(wsk, x, &subject))
	  walk_ctx_loop_next(rc, wsk);
	continue;
      }
      
      log_validation_status(rc, &uri, unknown_object_type_skipped, object_generation_null);
      walk_ctx_loop_next(rc, wsk);
      continue;

    case walk_state_done:

      walk_ctx_stack_pop(wsk);	/* Resume our issuer's state */
      continue;

    }
  }

  assert(walk_ctx_stack_head(wsk) == NULL);
  walk_ctx_stack_free(wsk);
}

/**
 * Check a trust anchor.  Yes, we trust it, by definition, but it
 * still needs to conform to the certificate profile, the
 * self-signature must be correct, etcetera.
 */
static void check_ta(rcynic_ctx_t *rc, STACK_OF(walk_ctx_t) *wsk)
{
  STACK_OF(X509) *certs = walk_ctx_stack_certs(wsk);
  walk_ctx_t *w = walk_ctx_stack_head(wsk);
  int ok = 0;

  if (certs  != NULL && w != NULL)
    ok = check_x509(rc, certs, w->cert, &w->certinfo, &w->certinfo);

  sk_X509_free(certs);

  if (!ok)
    return;

  task_add(rc, walk_cert, wsk);

  while (sk_task_t_num(rc->task_queue) > 0 || sk_rsync_ctx_t_num(rc->rsync_queue) > 0) {
    task_run_q(rc);
    rsync_mgr(rc);
  }
}



/**
 * Read a trust anchor from disk and compare with known public key.
 * NB: EVP_PKEY_cmp() returns 1 for match, not 0 like every other
 * xyz_cmp() function in the entire OpenSSL library.  Go figure.
 */
static X509 *read_ta(const rcynic_ctx_t *rc, const uri_t *uri, const path_t *path, const EVP_PKEY *pkey, object_generation_t generation)

{
  EVP_PKEY *xpkey = NULL;
  X509 *x = NULL;
  int match = 0;

  if ((x = read_cert(path, NULL)) == NULL || (xpkey = X509_get_pubkey(x)) == NULL) {
    log_validation_status(rc, uri, unreadable_trust_anchor, generation);
  } else {
    match = EVP_PKEY_cmp(pkey, xpkey) == 1;
    if (!match)
      log_validation_status(rc, uri, trust_anchor_key_mismatch, generation);
  }

  EVP_PKEY_free(xpkey);
  if (match)
    return x;
  X509_free(x);
  return NULL;
}



/**
 * Main program.  Parse command line, read config file, iterate over
 * trust anchors found via config file and do a tree walk for each
 * trust anchor.
 */
int main(int argc, char *argv[])
{
  int opt_jitter = 0, use_syslog = 0, use_stderr = 0, syslog_facility = 0;
  int opt_syslog = 0, opt_stderr = 0, opt_level = 0, prune = 1;
  char *cfg_file = "rcynic.conf";
  char *lockfile = NULL, *xmlfile = NULL;
  int c, i, j, ret = 1, jitter = 600, lockfd = -1;
  STACK_OF(CONF_VALUE) *cfg_section = NULL;
  STACK_OF(walk_ctx_t) *wsk = NULL;
  CONF *cfg_handle = NULL;
  walk_ctx_t *w = NULL;
  time_t start = 0, finish;
  unsigned long hash;
  rcynic_ctx_t rc;
  unsigned delay;
  long eline = 0;
  BIO *bio = NULL;

  memset(&rc, 0, sizeof(rc));

  if ((rc.jane = strrchr(argv[0], '/')) == NULL)
    rc.jane = argv[0];
  else
    rc.jane++;

  rc.log_level = log_data_err;
  rc.allow_stale_crl = 1;
  rc.allow_stale_manifest = 1;
  rc.max_parallel_fetches = 1;
  rc.max_retries = 3;
  rc.retry_wait_min = 30;
  rc.run_rsync = 1;
  rc.rsync_timeout = 300;

#define QQ(x,y)   rc.priority[x] = y;
  LOG_LEVELS;
#undef QQ

  if (!set_directory(&rc, &rc.authenticated,   "rcynic-data/authenticated", 0) ||
      !set_directory(&rc, &rc.unauthenticated, "rcynic-data/unauthenticated/", 1))
    goto done;

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  while ((c = getopt(argc, argv, "c:l:sej:V")) > 0) {
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
    case 'e':
      use_stderr = opt_stderr = 1;
      break;
    case 'j':
      if (!configure_integer(&rc, &jitter, optarg))
	goto done;
      opt_jitter = 1;
      break;
    case 'V':
      puts(svn_id);
      ret = 0;
      goto done;
    default:
      logmsg(&rc, log_usage_err,
	     "usage: %s [-c configfile] [-s] [-e] [-l loglevel] [-j jitter] [-V]",
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

    if (!name_cmp(val->name, "authenticated") &&
    	!set_directory(&rc, &rc.authenticated, val->value, 0))
      goto done;

    else if (!name_cmp(val->name, "unauthenticated") &&
	     !set_directory(&rc, &rc.unauthenticated, val->value, 1))
      goto done;

    else if (!name_cmp(val->name, "rsync-timeout") &&
	     !configure_integer(&rc, &rc.rsync_timeout, val->value))
	goto done;

    else if (!name_cmp(val->name, "max-parallel-fetches") &&
	     !configure_integer(&rc, &rc.max_parallel_fetches, val->value))
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

    else if (!opt_stderr &&
	     !name_cmp(val->name, "use-stderr") &&
	     !configure_boolean(&rc, &use_stderr, val->value))
      goto done;

    else if (!name_cmp(val->name, "syslog-facility") &&
	     !configure_syslog(&rc, &syslog_facility,
			       facilitynames, val->value))
      goto done;

    else if (!name_cmp(val->name, "xml-summary"))
      xmlfile = strdup(val->value);

    else if (!name_cmp(val->name, "allow-stale-crl") &&
	     !configure_boolean(&rc, &rc.allow_stale_crl, val->value))
      goto done;

    else if (!name_cmp(val->name, "allow-stale-manifest") &&
	     !configure_boolean(&rc, &rc.allow_stale_manifest, val->value))
      goto done;

    else if (!name_cmp(val->name, "allow-non-self-signed-trust-anchor") &&
	     !configure_boolean(&rc, &rc.allow_non_self_signed_trust_anchor, val->value))
      goto done;

    else if (!name_cmp(val->name, "require-crl-in-manifest") &&
	     !configure_boolean(&rc, &rc.require_crl_in_manifest, val->value))
      goto done;

    else if (!name_cmp(val->name, "allow-object-not-in-manifest") &&
	     !configure_boolean(&rc, &rc.allow_object_not_in_manifest, val->value))
      goto done;

    else if (!name_cmp(val->name, "use-links") &&
	     !configure_boolean(&rc, &rc.use_links, val->value))
      goto done;

    else if (!name_cmp(val->name, "prune") &&
	     !configure_boolean(&rc, &prune, val->value))
      goto done;

    else if (!name_cmp(val->name, "run-rsync") &&
	     !configure_boolean(&rc, &rc.run_rsync, val->value))
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

  if ((rc.rsync_cache = sk_OPENSSL_STRING_new(uri_cmp)) == NULL) {
    logmsg(&rc, log_sys_err, "Couldn't allocate rsync_cache stack");
    goto done;
  }

  if ((rc.backup_cache = sk_OPENSSL_STRING_new(uri_cmp)) == NULL) {
    logmsg(&rc, log_sys_err, "Couldn't allocate backup_cache stack");
    goto done;
  }

  if ((rc.dead_host_cache = sk_OPENSSL_STRING_new(uri_cmp)) == NULL) {
    logmsg(&rc, log_sys_err, "Couldn't allocate dead_host_cache stack");
    goto done;
  }

  if (xmlfile != NULL) {
    if ((rc.validation_status = sk_validation_status_t_new(validation_status_cmp)) == NULL) {
      logmsg(&rc, log_sys_err, "Couldn't allocate validation_status stack");
      goto done;
    }
  }

  if ((rc.x509_store = X509_STORE_new()) == NULL) {
    logmsg(&rc, log_sys_err, "Couldn't allocate X509_STORE");
    goto done;
  }

  if ((rc.rsync_queue = sk_rsync_ctx_t_new_null()) == NULL) {
    logmsg(&rc, log_sys_err, "Couldn't allocate rsync_queue");
    goto done;
  }

  if ((rc.task_queue = sk_task_t_new_null()) == NULL) {
    logmsg(&rc, log_sys_err, "Couldn't allocate task_queue");
    goto done;
  }

  rc.use_syslog = use_syslog;

  if (use_syslog)
    openlog(rc.jane,
	    LOG_PID | (use_stderr ? LOG_PERROR : 0),
	    (syslog_facility ? syslog_facility : LOG_LOCAL0));

  if (!upgraded_from_pre_symlink_rcynic(&rc))
    goto done;

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
    lockfd = -1;
    goto done;
  }

  start = time(0);
  logmsg(&rc, log_telemetry, "Starting");

  if (!construct_directory_names(&rc))
    goto done;

  if (!access(rc.new_authenticated.s, F_OK)) {
    logmsg(&rc, log_sys_err, "Timestamped output directory %s already exists!  Clock went backwards?", rc.new_authenticated.s);
    goto done;
  }

  if (!mkdir_maybe(&rc, &rc.new_authenticated)) {
    logmsg(&rc, log_sys_err, "Couldn't prepare directory %s: %s",
	   rc.new_authenticated.s, strerror(errno));
    goto done;
  }

  for (i = 0; i < sk_CONF_VALUE_num(cfg_section); i++) {
    CONF_VALUE *val = sk_CONF_VALUE_value(cfg_section, i);
    object_generation_t generation = object_generation_null;
    path_t path1, path2;
    certinfo_t ta_certinfo;
    uri_t uri;
    X509 *x = NULL;

    assert(val && val->name && val->value);

    if (!name_cmp(val->name, "trust-anchor-uri-with-key") ||
	!name_cmp(val->name, "indirect-trust-anchor")) {
      /*
       * Obsolete syntax.  If you're reading this comment because you
       * had an old rcynic.conf and got this error message:
       *
       * "indirect-trust-anchor" is exactly the same as
       * "trust-anchor-locator", the name was changed to settle a
       * terminology fight in the IETF SIDR WG.
       *
       * "trust-anchor-uri-with-key" is semantically identical to
       * "trust-anchor-locator" (and was the original form of this
       * mechanism), but the syntax and local file format is
       * different.
       *
       * If you're seeing this error, you should just obtain current
       * TAL files.   Also see the "make-tal.sh" script.
       */
      logmsg(&rc, log_usage_err,
	     "Directive \"%s\" is obsolete -- please use \"trust-anchor-locator\" instead",
	     val->name);
      goto done;
    }

    if (!name_cmp(val->name, "trust-anchor")) {
      /*
       * Local file trust anchor method.
       */
      logmsg(&rc, log_telemetry, "Processing trust anchor from local file %s", val->value);
      if (strlen(val->value) >= sizeof(path1.s)) {
	logmsg(&rc, log_usage_err, "Trust anchor path name too long %s", val->value);
	goto done;
      }
      strcpy(path1.s, val->value);

      /* Construct file:// URI for logging */
      assert(sizeof("file://") < sizeof(uri.s));
      strcpy(uri.s, "file://");
      if (path1.s[0] != '/') {
	if (getcwd(uri.s + strlen(uri.s), sizeof(uri.s) - strlen(uri.s)) == NULL ||
	    (!endswith(uri.s, "/") && strlen(uri.s) >= sizeof(uri.s) - 1))
	  uri.s[0] = '\0';
	else
	  strcat(uri.s, "/");
      }
      if (uri.s[0] != '\0' && strlen(uri.s) + strlen(path1.s) < sizeof(uri.s))
	strcat(uri.s, path1.s);
      else
	uri.s[0] = '\0';

      if ((x = read_cert(&path1, NULL)) == NULL) {
	log_validation_status(&rc, &uri, unreadable_trust_anchor, generation);
	continue;
      }
      hash = X509_subject_name_hash(x);
      for (j = 0; j < INT_MAX; j++) {
	if (snprintf(path2.s, sizeof(path2.s), "%s%lx.%d.cer",
		     rc.new_authenticated.s, hash, j) == sizeof(path2.s)) {
	  logmsg(&rc, log_sys_err,
		 "Couldn't construct path name for trust anchor %s", path1.s);
	  goto done;
	}
	if (access(path2.s, F_OK))
	  break;
      }
      if (j == INT_MAX) {
	logmsg(&rc, log_sys_err, "Couldn't find a free name for trust anchor %s", path1.s);
	goto done;
      }
    }

    if (!name_cmp(val->name, "trust-anchor-locator")) {
      /*
       * Trust anchor locator (URI + public key) method.
       */
      EVP_PKEY *pkey = NULL;
      char *fn;
      path_t path3;

      fn = val->value;
      bio = BIO_new_file(fn, "r");
      if (!bio || BIO_gets(bio, uri.s, sizeof(uri.s)) <= 0) {
	log_validation_status(&rc, &uri, unreadable_trust_anchor_locator, object_generation_null);
	BIO_free(bio);
	bio = NULL;
	continue;
      }
      uri.s[strcspn(uri.s, " \t\r\n")] = '\0';
      bio = BIO_push(BIO_new(BIO_f_linebreak()), bio);
      bio = BIO_push(BIO_new(BIO_f_base64()), bio);
      if (!uri_to_filename(&rc, &uri, &path1, &rc.unauthenticated) ||
	  !uri_to_filename(&rc, &uri, &path2, &rc.new_authenticated) ||
	  !uri_to_filename(&rc, &uri, &path3, &rc.old_authenticated)) {
	log_validation_status(&rc, &uri, unreadable_trust_anchor_locator, object_generation_null);
	BIO_free_all(bio);
	bio = NULL;
	continue;
      }
      logmsg(&rc, log_telemetry, "Processing trust anchor from URI %s", uri.s);
      rsync_file(&rc, &uri);
      while (sk_rsync_ctx_t_num(rc.rsync_queue) > 0)
	rsync_mgr(&rc);
      if (bio)
	pkey = d2i_PUBKEY_bio(bio, NULL);
      BIO_free_all(bio);
      bio = NULL;
      if (!pkey) {
	log_validation_status(&rc, &uri, unreadable_trust_anchor_locator, object_generation_null);
	continue;
      }
      generation = object_generation_current;
      if ((x = read_ta(&rc, &uri, &path1, pkey, generation)) == NULL) {
	generation = object_generation_backup;
	path1 = path3;
	x = read_ta(&rc, &uri, &path1, pkey, generation);
      }
      EVP_PKEY_free(pkey);
      if (!x)
	continue;
    }

    if (!x)
      continue;

    logmsg(&rc, log_telemetry, "Copying trust anchor %s to %s", path1.s, path2.s);

    if (!mkdir_maybe(&rc, &path2) || !cp_ln(&rc, &path1, &path2))
      goto done;

    if ((wsk = walk_ctx_stack_new()) == NULL) {
      logmsg(&rc, log_sys_err, "Couldn't allocate walk context stack");
      goto done;
    }

    parse_cert(&rc, x, &ta_certinfo, &uri, generation);
    ta_certinfo.ta = 1;

    if ((w = walk_ctx_stack_push(wsk, x, &ta_certinfo)) == NULL) {
      logmsg(&rc, log_sys_err, "Couldn't push walk context stack");
      goto done;
    }

    check_ta(&rc, wsk);
    wsk = NULL;			/* Ownership of wsk passed to check_ta() */
  }

  if (!finalize_directories(&rc))
    goto done;

  if (prune && !prune_unauthenticated(&rc, &rc.unauthenticated,
				      strlen(rc.unauthenticated.s))) {
    logmsg(&rc, log_sys_err, "Trouble pruning old unauthenticated data");
    goto done;
  }

  ret = 0;

 done:
  log_openssl_errors(&rc);

  if (xmlfile != NULL) {

    char tad[sizeof("2006-10-13T11:22:33Z") + 1];
    time_t tad_time = time(0);
    struct tm *tad_tm = gmtime(&tad_time);
    int ok = 1, use_stdout = !strcmp(xmlfile, "-");
    hostname_t hostname;
    mib_counter_t code;
    FILE *f = NULL;

    strftime(tad, sizeof(tad), "%Y-%m-%dT%H:%M:%SZ", tad_tm);

    ok &= gethostname(hostname.s, sizeof(hostname.s)) == 0;

    if (use_stdout)
      f = stdout;
    else if (ok)
      ok &= (f = fopen(xmlfile, "w")) != NULL;

    if (ok)
      logmsg(&rc, log_telemetry, "Writing XML summary to %s",
	     (use_stdout ? "standard output" : xmlfile));

    if (ok)
      ok &= fprintf(f, "<?xml version=\"1.0\" ?>\n"
		    "<rcynic-summary date=\"%s\" rcynic-version=\"%s\""
		    " summary-version=\"%d\" reporting-hostname=\"%s\">\n"
		    "  <labels>\n",
		    tad, svn_id, XML_SUMMARY_VERSION, hostname.s) != EOF;

    for (j = 0; ok && j < MIB_COUNTER_T_MAX; ++j)
      if (ok)
	ok &= fprintf(f, "    <%s kind=\"%s\">%s</%s>\n",
		      mib_counter_label[j], mib_counter_kind[j],
		      (mib_counter_desc[j]
		       ? mib_counter_desc[j]
		       : X509_verify_cert_error_string(mib_counter_openssl[j])),
		      mib_counter_label[j]) != EOF;

    if (ok)
      ok &= fprintf(f, "  </labels>\n") != EOF;

    for (i = 0; ok && i < sk_validation_status_t_num(rc.validation_status); i++) {
      validation_status_t *v = sk_validation_status_t_value(rc.validation_status, i);
      assert(v);

      tad_tm = gmtime(&v->timestamp);
      strftime(tad, sizeof(tad), "%Y-%m-%dT%H:%M:%SZ", tad_tm);

      for (code = (mib_counter_t) 0; ok && code < MIB_COUNTER_T_MAX; code++) {
	if (validation_status_get_code(v, code)) {
	  if (ok)
	    ok &= fprintf(f, "  <validation_status timestamp=\"%s\" status=\"%s\"",
			  tad, mib_counter_label[code]) != EOF;
	  if (ok && (v->generation == object_generation_current ||
		     v->generation == object_generation_backup))
	    ok &= fprintf(f, " generation=\"%s\"",
			  object_generation_label[v->generation]) != EOF;
	  if (ok)
	    ok &= fprintf(f, ">%s</validation_status>\n", v->uri.s) != EOF;
	}
      }
    }

    if (ok)
      ok &= fprintf(f, "</rcynic-summary>\n") != EOF;

    if (f && !use_stdout)
      ok &= fclose(f) != EOF;

    if (!ok)
      logmsg(&rc, log_sys_err, "Couldn't write XML summary to %s: %s",
	     xmlfile, strerror(errno));

  }

  /*
   * Do NOT free cfg_section, NCONF_free() takes care of that
   */
  sk_OPENSSL_STRING_pop_free(rc.rsync_cache, OPENSSL_STRING_free);
  sk_OPENSSL_STRING_pop_free(rc.backup_cache, OPENSSL_STRING_free);
  sk_OPENSSL_STRING_pop_free(rc.dead_host_cache, OPENSSL_STRING_free);
  sk_validation_status_t_pop_free(rc.validation_status, validation_status_t_free);
  X509_STORE_free(rc.x509_store);
  NCONF_free(cfg_handle);
  CONF_modules_free();
  BIO_free(bio);
  EVP_cleanup();
  ERR_free_strings();
  if (rc.rsync_program)
    free(rc.rsync_program);
  if (lockfile && lockfd >= 0)
    unlink(lockfile);
  if (lockfile)
    free(lockfile);
  if (xmlfile)
    free(xmlfile);

  if (start) {
    finish = time(0);
    logmsg(&rc, log_telemetry,
	   "Finished, elapsed time %u:%02u:%02u",
	   (unsigned) ((finish - start) / 3600),
	   (unsigned) ((finish - start) / 60 % 60),
	   (unsigned) ((finish - start) % 60));
  }

  return ret;
}
