/*
 * Copyright (C) 2009--2012  Internet Systems Consortium ("ISC")
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

#include <rpki/roa.h>
#include <rpki/manifest.h>

#include "bio_f_linebreak.h"

#include "defstack.h"

/*
 * Whether to run the old slow STACK-based validation_status lookup in
 * parallel to the new faster AVL-based mechanism.  The code
 * controlled by this option will probably go away soon, it's just here
 * in case we run into trouble while testing the new code.
 */
#ifndef AVL_PARANOIA
#define	AVL_PARANOIA	0
#endif

#if !defined(FILENAME_MAX) && defined(PATH_MAX) && PATH_MAX > 1024
#define	FILENAME_MAX	PATH_MAX
#elif !defined(FILENAME_MAX)
#define	FILENAME_MAX	1024
#endif

#define	SCHEME_RSYNC	("rsync://")
#define	SIZEOF_RSYNC	(sizeof(SCHEME_RSYNC) - 1)

/**
 * Maximum length of a hostname.
 */
#ifndef	HOSTNAME_MAX
#define	HOSTNAME_MAX	256
#endif

/**
 * Maximum length of an URI.
 */
#define	URI_MAX		(SIZEOF_RSYNC + HOSTNAME_MAX + 1 + FILENAME_MAX)

/**
 * Maximum number of times we try to kill an inferior process before
 * giving up.
 */
#define	KILL_MAX	10

/**
 * Version number of XML summary output.
 */
#define	XML_SUMMARY_VERSION	1

/**
 * How much buffer space do we need for a raw address?
 */
#define ADDR_RAW_BUF_LEN	16

/**
 * How many bytes is a SHA256 digest?
 */
#define	HASH_SHA256_LEN		32

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
  QB(aia_extension_missing,		"AIA extension missing")	    \
  QB(aia_extension_forbidden,		"AIA extension forbidden")	    \
  QB(aia_uri_missing,			"AIA URI missing")		    \
  QB(aki_extension_issuer_mismatch,	"AKI extension issuer mismatch")    \
  QB(aki_extension_missing,		"AKI extension missing")	    \
  QB(aki_extension_wrong_format,	"AKI extension is wrong format")    \
  QB(bad_asidentifiers,			"Bad ASIdentifiers extension")	    \
  QB(bad_cms_econtenttype,		"Bad CMS eContentType")		    \
  QB(bad_cms_si_contenttype,		"Bad CMS SI ContentType")	    \
  QB(bad_cms_signer_infos,		"Bad CMS signerInfos")		    \
  QB(bad_crl,				"Bad CRL")			    \
  QB(bad_ipaddrblocks,			"Bad IPAddrBlocks extension")	    \
  QB(bad_key_usage,			"Bad keyUsage")			    \
  QB(bad_manifest_digest_length,	"Bad manifest digest length")	    \
  QB(bad_public_key,			"Bad public key")		    \
  QB(bad_roa_asID,			"Bad ROA asID")			    \
  QB(bad_serial_number,			"Bad serialNumber")		    \
  QB(certificate_bad_signature,		"Bad certificate signature")	    \
  QB(certificate_failed_validation,	"Certificate failed validation")    \
  QB(cms_econtent_decode_error,		"CMS eContent decode error")	    \
  QB(cms_includes_crls, 		"CMS includes CRLs")		    \
  QB(cms_signer_missing,		"CMS signer missing")		    \
  QB(cms_ski_mismatch,			"CMS SKI mismatch")		    \
  QB(cms_validation_failure,		"CMS validation failure")	    \
  QB(crl_not_in_manifest,               "CRL not listed in manifest")	    \
  QB(crl_not_yet_valid,			"CRL not yet valid")		    \
  QB(crl_number_extension_missing,	"CRL number extension missing")	    \
  QB(crl_number_out_of_range,		"CRL number out of range")	    \
  QB(crldp_doesnt_match_issuer_sia,	"CRLDP doesn't match issuer's SIA") \
  QB(crldp_uri_missing,			"CRLDP URI missing")		    \
  QB(disallowed_x509v3_extension,	"Disallowed X.509v3 extension")     \
  QB(duplicate_name_in_manifest,	"Duplicate name in manifest")	    \
  QB(inappropriate_eku_extension,	"Inappropriate EKU extension")	    \
  QB(malformed_aia_extension,		"Malformed AIA extension")	    \
  QB(malformed_sia_extension,		"Malformed SIA extension")	    \
  QB(malformed_basic_constraints,	"Malformed basicConstraints")	    \
  QB(malformed_certificate_policy,	"Malformed certificate policy")	    \
  QB(malformed_trust_anchor,		"Malformed trust anchor")	    \
  QB(malformed_cadirectory_uri,		"Malformed caDirectory URI")	    \
  QB(malformed_crldp_extension,		"Malformed CRDLP extension")	    \
  QB(malformed_crldp_uri,		"Malformed CRDLP URI")		    \
  QB(malformed_roa_addressfamily,       "Malformed ROA addressFamily")	    \
  QB(malformed_tal_uri,			"Malformed TAL URI")		    \
  QB(manifest_carepository_mismatch,	"Manifest caRepository mismatch")   \
  QB(manifest_lists_missing_object,	"Manifest lists missing object")    \
  QB(manifest_not_yet_valid,		"Manifest not yet valid")	    \
  QB(missing_resources,			"Missing resources")		    \
  QB(negative_manifest_number,		"Negative manifestNumber")	    \
  QB(nonconformant_asn1_time_value,	"Nonconformant ASN.1 time value")   \
  QB(nonconformant_public_key_algorithm,"Nonconformant public key algorithm")\
  QB(nonconformant_signature_algorithm,	"Nonconformant signature algorithm")\
  QB(nonconformant_digest_algorithm,	"Nonconformant digest algorithm")   \
  QB(nonconformant_certificate_uid,	"Nonconformant certificate UID")    \
  QB(object_rejected,			"Object rejected")		    \
  QB(rfc3779_inheritance_required,	"RFC 3779 inheritance required")    \
  QB(roa_contains_bad_afi_value,	"ROA contains bad AFI value")	    \
  QB(roa_resource_not_in_ee,		"ROA resource not in EE")	    \
  QB(roa_resources_malformed,		"ROA resources malformed")	    \
  QB(rsync_transfer_failed,		"rsync transfer failed")	    \
  QB(rsync_transfer_timed_out,		"rsync transfer timed out")	    \
  QB(sia_cadirectory_uri_missing,	"SIA caDirectory URI missing")	    \
  QB(sia_extension_missing,		"SIA extension missing")	    \
  QB(sia_manifest_uri_missing,		"SIA manifest URI missing")	    \
  QB(ski_extension_missing,		"SKI extension missing")	    \
  QB(ski_public_key_mismatch,		"SKI public key mismatch")	    \
  QB(trust_anchor_key_mismatch,		"Trust anchor key mismatch")	    \
  QB(trust_anchor_with_crldp,		"Trust anchor can't have CRLDP")    \
  QB(unknown_openssl_verify_error,	"Unknown OpenSSL verify error")	    \
  QB(unreadable_trust_anchor,		"Unreadable trust anchor")	    \
  QB(unreadable_trust_anchor_locator,	"Unreadable trust anchor locator")  \
  QB(wrong_object_version,		"Wrong object version")		    \
  QW(aia_doesnt_match_issuer,		"AIA doesn't match issuer")	    \
  QW(bad_cms_si_signed_attributes, 	"Bad CMS SI signed attributes")	    \
  QW(crldp_names_newer_crl,		"CRLDP names newer CRL")	    \
  QW(digest_mismatch,			"Digest mismatch")		    \
  QW(ee_certificate_with_1024_bit_key, 	"EE certificate with 1024 bit key") \
  QW(issuer_uses_multiple_crldp_values,	"Issuer uses multiple CRLDP values")\
  QW(multiple_rsync_uris_in_extension,  "Multiple rsync URIs in extension") \
  QW(nonconformant_issuer_name,		"Nonconformant X.509 issuer name")  \
  QW(nonconformant_subject_name,	"Nonconformant X.509 subject name") \
  QW(rsync_partial_transfer,		"rsync partial transfer")	    \
  QW(rsync_transfer_skipped,		"rsync transfer skipped")	    \
  QW(stale_crl_or_manifest,		"Stale CRL or manifest")	    \
  QW(tainted_by_stale_crl,		"Tainted by stale CRL")		    \
  QW(tainted_by_stale_manifest,		"Tainted by stale manifest")	    \
  QW(tainted_by_not_being_in_manifest,	"Tainted by not being in manifest") \
  QW(trust_anchor_not_self_signed,	"Trust anchor not self-signed")	    \
  QW(unknown_object_type_skipped,	"Unknown object type skipped")	    \
  QW(uri_too_long,			"URI too long")			    \
  QW(wrong_cms_si_signature_algorithm,	"Wrong CMS SI signature algorithm") \
  QW(wrong_cms_si_digest_algorithm,	"Wrong CMS SI digest algorithm")    \
  QG(current_cert_recheck,		"Certificate rechecked")	    \
  QG(non_rsync_uri_in_extension,	"Non-rsync URI in extension")	    \
  QG(object_accepted,			"Object accepted")		    \
  QG(rsync_transfer_succeeded,		"rsync transfer succeeded")	    \
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
 * Type-safe wrapper for hash buffers.
 */
typedef struct { unsigned char h[EVP_MAX_MD_SIZE]; } hashbuf_t;

/**
 * Type-safe wrapper for timestamp strings.
 */
typedef struct { char s[sizeof("2001-01-01T00:00:00Z") + 1]; } timestamp_t;

/**
 * Per-URI validation status object.
 * uri must be first element.
 */
typedef struct validation_status {
  uri_t uri;
  object_generation_t generation;
  time_t timestamp;
#if AVL_PARANOIA
  unsigned creation_order;
#endif
  unsigned char events[(MIB_COUNTER_T_MAX + 7) / 8];
  short balance;
  struct validation_status *left_child;
  struct validation_status *right_child;
} validation_status_t;

DECLARE_STACK_OF(validation_status_t)

/**
 * Structure to hold data parsed out of a certificate.
 */
typedef struct certinfo {
  int ca, ta;
  object_generation_t generation;
  uri_t uri, sia, aia, crldp, manifest, signedobject;
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
  object_generation_t manifest_generation;
  STACK_OF(OPENSSL_STRING) *filenames;
  int manifest_iteration, filename_iteration, stale_manifest;
  walk_state_t state;
  uri_t crldp;
  STACK_OF(X509) *certs;
  STACK_OF(X509_CRL) *crls;
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
 * States for asynchronous rsync.
 * "initial" must be first.
 */

#define RSYNC_STATES	\
  QQ(initial)		\
  QQ(running)		\
  QQ(conflict_wait)	\
  QQ(retry_wait)	\
  QQ(closed)		\
  QQ(terminating)

#define QQ(x)	rsync_state_##x,
typedef enum { RSYNC_STATES RSYNC_STATE_T_MAX } rsync_state_t;
#undef	QQ

#define QQ(x)	#x ,
static const char * const rsync_state_label[] = { RSYNC_STATES NULL };
#undef	QQ

/**
 * Context for asyncronous rsync.
 */
typedef struct rsync_ctx {
  uri_t uri;
  void (*handler)(rcynic_ctx_t *, const struct rsync_ctx *, const rsync_status_t, const uri_t *, STACK_OF(walk_ctx_t) *);
  STACK_OF(walk_ctx_t) *wsk;
  rsync_state_t state;
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
 * Record of rsync attempts.
 */
typedef struct rsync_history {
  uri_t uri;
  time_t started, finished;
  rsync_status_t status;
  int final_slash;
} rsync_history_t;

DECLARE_STACK_OF(rsync_history_t)

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
  rcynic_ctx_t *rc;
  const certinfo_t *subject;
} rcynic_x509_store_ctx_t;

/**
 * Program context that would otherwise be a mess of global variables.
 */
struct rcynic_ctx {
  path_t authenticated, old_authenticated, new_authenticated, unauthenticated;
  char *jane, *rsync_program;
  STACK_OF(validation_status_t) *validation_status;
  STACK_OF(rsync_history_t) *rsync_history;
  STACK_OF(rsync_ctx_t) *rsync_queue;
  STACK_OF(task_t) *task_queue;
  int use_syslog, allow_stale_crl, allow_stale_manifest, use_links;
  int require_crl_in_manifest, rsync_timeout, priority[LOG_LEVEL_T_MAX];
  int allow_non_self_signed_trust_anchor, allow_object_not_in_manifest;
  int max_parallel_fetches, max_retries, retry_wait_min, run_rsync;
  int allow_digest_mismatch, allow_crl_digest_mismatch;
  int allow_nonconformant_name, allow_ee_without_signedObject;
  int allow_1024_bit_ee_key, allow_wrong_cms_si_attributes;
  unsigned max_select_time;
#if AVL_PARANOIA
  unsigned validation_status_creation_order;
#endif
  validation_status_t *validation_status_in_waiting;
  validation_status_t *validation_status_root;
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

/** 1.3.6.1.5.5.7.48.11 */
static const unsigned char id_ad_signedObject[] =
  {0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x30, 0xb};

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
 * Constants for comparisions.  We can't build these at compile time,
 * so they can't be const, but treat them as if they were once
 * allocated.
 *
 * We probably need both a better scheme for naming NID_ replacements
 * and a more comprehensive rewrite of how we handle OIDs OpenSSL
 * doesn't know about, so that we neither conflict with defined
 * symbols nor duplicate effort nor explode if and when OpenSSL adds
 * new OIDs (with or without the names we would have used).
 */

static const ASN1_INTEGER *asn1_zero, *asn1_four_octets, *asn1_twenty_octets;
static int NID_binary_signing_time;



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



/**
 * Allocate a new rsync_history_t object.
 */
static rsync_history_t *rsync_history_t_new(void)
{
  rsync_history_t *h = malloc(sizeof(*h));
  if (h)
    memset(h, 0, sizeof(*h));
  return h;
}

/**
 * Type-safe wrapper around free() to keep safestack macros happy.
 */
static void rsync_history_t_free(rsync_history_t *h)
{
  if (h)
    free(h);
}

/**
 * Compare two rsync_history_t objects.
 */
static int rsync_history_cmp(const rsync_history_t * const *a, const rsync_history_t * const *b)
{
  return strcmp((*a)->uri.s, (*b)->uri.s);
}



/**
 * Convert a time_t to a printable string in UTC format.
 */
static const char *time_to_string(timestamp_t *ts, const time_t *t)
{
  time_t now;
  size_t n;

  assert(ts != NULL);

  if (t == NULL) {
    now = time(0);
    t = &now;
  }

  n = strftime(ts->s, sizeof(ts->s), "%Y-%m-%dT%H:%M:%SZ", gmtime(t));
  assert(n > 0);

  return ts->s;
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
  assert(rc && fmt);

  if (rc->log_level < level)
    return;

  if (rc->use_syslog) {
    vsyslog(rc->priority[level], fmt, ap);
  } else {
    char ts[sizeof("00:00:00")+1];
    time_t t = time(0);
    strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&t));
    fprintf(stderr, "%s: ", ts);
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
 * Configure unsigned integer variable.
 */
static int configure_unsigned_integer(const rcynic_ctx_t *rc,
				      unsigned *result,
				      const char *val)
{
  unsigned long res;
  char *p;

  assert(rc && result && val);

  res = strtoul(val, &p, 10);
  
  if (*val != '\0' && *p == '\0') {
    *result = (unsigned) res;
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
 * Compare filename fields of two FileAndHash structures.
 */
static int FileAndHash_name_cmp(const FileAndHash * const *a, const FileAndHash * const *b)
{
  return strcmp((char *) (*a)->file->data, (char *) (*b)->file->data);
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
 * validation_status object comparison, for AVL tree rather than
 * OpenSSL stacks.
 */
static int
validation_status_cmp(const validation_status_t *node,
		      const uri_t *uri,
		      const object_generation_t generation)
{
  int cmp = ((int) node->generation) - ((int) generation);
  if (cmp)
    return cmp;
  else
    return strcmp(uri->s, node->uri.s);
}

/**
 * validation_status AVL tree insertion.  Adapted from code written by
 * Paul Vixie and explictly placed in the public domain using examples
 * from the book: "Algorithms & Data Structures," Niklaus Wirth,
 * Prentice-Hall, 1986, ISBN 0-13-022005-1.  Thanks, Paul!
 */
static validation_status_t *
validation_status_sprout(validation_status_t **node,
			 int *needs_balancing,
			 validation_status_t *new_node)
{
#ifdef AVL_DEBUG
#define AVL_MSG(msg) sprintf(stderr, "AVL_DEBUG: '%s'\n", msg)
#else
#define AVL_MSG(msg)
#endif

  validation_status_t *p1, *p2, *result;
  int cmp;

  /*
   * Are we grounded?  If so, add the node "here" and set the
   * rebalance flag, then exit.
   */
  if (*node == NULL) {
    AVL_MSG("Grounded, adding new node");
    new_node->left_child = NULL;
    new_node->right_child = NULL;
    new_node->balance = 0;
    *node = new_node;
    *needs_balancing = 1;
    return *node;
  }

  /*
   * Compare the data.
   */
  cmp = validation_status_cmp(*node, &new_node->uri, new_node->generation);

  /*
   * If LESS, prepare to move to the left.
   */
  if (cmp < 0) {

    AVL_MSG("LESS. sprouting left.");
    result = validation_status_sprout(&(*node)->left_child, needs_balancing, new_node);

    if (*needs_balancing) {
      AVL_MSG("LESS: left branch has grown longer");

      switch ((*node)->balance) {

      case 1:
	/*
	 * Right branch WAS longer; balance is ok now.
	 */
	AVL_MSG("LESS: case 1.. balance restored implicitly");
	(*node)->balance = 0;
	*needs_balancing = 0;
	break;

      case 0:
	/*
	 * Balance WAS okay; now left branch longer.
	 */
	AVL_MSG("LESS: case 0.. balnce bad but still ok");
	(*node)->balance = -1;
	break;

      case -1:
	/*
	 * Left branch was already too long.  Rebalance.
	 */
	AVL_MSG("LESS: case -1: rebalancing");
	p1 = (*node)->left_child;

	if (p1->balance == -1) {
	  AVL_MSG("LESS: single LL");
	  (*node)->left_child = p1->right_child;
	  p1->right_child = *node;
	  (*node)->balance = 0;
	  *node = p1;
	}

	else {
	  AVL_MSG("LESS: double LR");

	  p2 = p1->right_child;
	  p1->right_child = p2->left_child;
	  p2->left_child = p1;

	  (*node)->left_child = p2->right_child;
	  p2->right_child = *node;

	  if (p2->balance == -1)
	    (*node)->balance = 1;
	  else
	    (*node)->balance = 0;

	  if (p2->balance == 1)
	    p1->balance = -1;
	  else
	    p1->balance = 0;
	  *node = p2;
	}

	(*node)->balance = 0;
	*needs_balancing = 0;
      }
    }
    return result;
  }

  /*
   * If MORE, prepare to move to the right.
   */
  if (cmp > 0) {

    AVL_MSG("MORE: sprouting to the right");
    result = validation_status_sprout(&(*node)->right_child, needs_balancing, new_node);

    if (*needs_balancing) {
      AVL_MSG("MORE: right branch has grown longer");

      switch ((*node)->balance) {

      case -1:AVL_MSG("MORE: balance was off, fixed implicitly");
	(*node)->balance = 0;
	*needs_balancing = 0;
	break;

      case 0:	AVL_MSG("MORE: balance was okay, now off but ok");
	(*node)->balance = 1;
	break;

      case 1:	AVL_MSG("MORE: balance was off, need to rebalance");
	p1 = (*node)->right_child;

	if (p1->balance == 1) {
	  AVL_MSG("MORE: single RR");
	  (*node)->right_child = p1->left_child;
	  p1->left_child = *node;
	  (*node)->balance = 0;
	  *node = p1;
	}

	else {
	  AVL_MSG("MORE: double RL");

	  p2 = p1->left_child;
	  p1->left_child = p2->right_child;
	  p2->right_child = p1;

	  (*node)->right_child = p2->left_child;
	  p2->left_child = *node;

	  if (p2->balance == 1)
	    (*node)->balance = -1;
	  else
	    (*node)->balance = 0;

	  if (p2->balance == -1)
	    p1->balance = 1;
	  else
	    p1->balance = 0;

	  *node = p2;
	} /*else*/
	(*node)->balance = 0;
	*needs_balancing = 0;
      }
    }
    return result;
  }

  /*
   * Neither more nor less, found existing node matching key, return it.
   */
  AVL_MSG("I found it!");
  *needs_balancing = 0;
  return *node;

#undef AVL_DEBUG
}

/**
 * Add a validation status entry to internal log.
 */
static void log_validation_status(rcynic_ctx_t *rc,
				  const uri_t *uri,
				  const mib_counter_t code,
				  const object_generation_t generation)
{
  validation_status_t *v = NULL;
  int needs_balancing = 0;

  assert(rc && uri && code < MIB_COUNTER_T_MAX && generation < OBJECT_GENERATION_MAX);

  if (!rc->validation_status)
    return;

  if (code == rsync_transfer_skipped && !rc->run_rsync)
    return;

  if (rc->validation_status_in_waiting == NULL &&
      (rc->validation_status_in_waiting = validation_status_t_new()) == NULL) {
    logmsg(rc, log_sys_err, "Couldn't allocate validation status entry for %s", uri->s);
    return;
  }

  v = rc->validation_status_in_waiting;
  memset(v, 0, sizeof(*v));
  v->uri = *uri;
  v->generation = generation;

  v = validation_status_sprout(&rc->validation_status_root, &needs_balancing, v);
  if (v == rc->validation_status_in_waiting)
    rc->validation_status_in_waiting = NULL;

#if AVL_PARANOIA
  {
    validation_status_t *v2 = sk_validation_status_t_value(rc->validation_status,
							   sk_validation_status_t_find(rc->validation_status, v));
    assert((rc->validation_status_in_waiting == NULL) == (v2 == NULL));
    if (rc->validation_status_in_waiting == NULL) {
      v->creation_order = rc->validation_status_creation_order++;
      assert(rc->validation_status_creation_order != 0);
    }
  }
#endif

  if (rc->validation_status_in_waiting == NULL &&
      !sk_validation_status_t_push(rc->validation_status, v)) {
    logmsg(rc, log_sys_err, "Couldn't store validation status entry for %s", uri->s);
    return;
  }

  v->timestamp = time(0);

  if (validation_status_get_code(v, code))
    return;

  validation_status_set_code(v, code, 1);

  logmsg(rc, log_verbose, "Recording \"%s\" for %s%s%s",
	 (mib_counter_desc[code]
	  ? mib_counter_desc[code]
	  : X509_verify_cert_error_string(mib_counter_openssl[code])),
	 (generation != object_generation_null ? object_generation_label[generation] : ""),
	 (generation != object_generation_null ? " " : ""),
	 uri->s);
}

#if AVL_PARANOIA

/**
 * Validation status object comparision.  While building up the
 * database, we want to do lookups based on URI and generation number.
 */
static int
validation_status_cmp_uri(const validation_status_t * const *a, const validation_status_t * const *b)
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
 * Validation status object comparision.  When writing out the
 * database, one of our primary consumers has respectfully requested
 * that we write in something approximating the order we traversed, so
 * we regenerate that order using the "order" field added for just
 * that purpose when creating these objects.
 */
static int validation_status_cmp_creation_order(const validation_status_t * const *a, const validation_status_t * const *b)
{
  int cmp = (*a)->creation_order - (*b)->creation_order;
  assert(cmp != 0 || a == b);
  return cmp;
}

#endif

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
static int install_object(rcynic_ctx_t *rc,
			  const uri_t *uri,
			  const path_t *source,
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
  log_validation_status(rc, uri, object_accepted, generation);
  return 1;
}

/**
 * AVL tree lookup for validation status objects.
 */
static validation_status_t *
validation_status_find(validation_status_t *node,
		       const uri_t *uri,
		       const object_generation_t generation)
{
  int cmp;

  while (node != NULL)
    if ((cmp = validation_status_cmp(node, uri, generation)) == 0)
      return node;
    else
      node = cmp < 0 ? node->left_child : node->right_child;

  return NULL;
}

/**
 * Figure out whether we already have a good copy of an object.  This
 * is a little more complicated than it sounds, because we might have
 * failed the current generation and accepted the backup due to having
 * followed the old CA certificate chain first during a key rollover.
 * So if this check is of the current object and we have not already
 * accepted the current object for this URI, we need to recheck.
 *
 * We also handle logging when we decide that we do need to check, so
 * that the caller doesn't need to concern itself with why we thought
 * the check was necessary.
 */
static int skip_checking_this_object(rcynic_ctx_t *rc, 
				     const uri_t *uri,
				     const object_generation_t generation)
{
  validation_status_t *v = NULL;
  path_t path;

  assert(rc && uri && rc->validation_status);

  if (!uri_to_filename(rc, uri, &path, &rc->new_authenticated))
    return 1;

  if (access(path.s, R_OK)) {
    logmsg(rc, log_telemetry, "Checking %s", uri->s);
    return 0;
  }
  
  if (generation != object_generation_current)
    return 1;

  v = validation_status_find(rc->validation_status_root, uri, generation);

#if AVL_PARANOIA
  {
    validation_status_t v_, *v2 = NULL;
    memset(&v_, 0, sizeof(v_));
    v_.uri = *uri;
    v_.generation = generation;
    v2 = sk_validation_status_t_value(rc->validation_status,
				      sk_validation_status_t_find(rc->validation_status, &v_));
    assert(v == v2);
  }
#endif

  if (v != NULL && validation_status_get_code(v, object_accepted))
    return 1;

  log_validation_status(rc, uri, current_cert_recheck, generation);
  logmsg(rc, log_telemetry, "Rechecking %s", uri->s);
  return 0;
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
 * Convert a filename to a file:// URI, for logging.
 */
static void filename_to_uri(uri_t *uri,
			    const char *fn)
{
  assert(sizeof("file://") < sizeof(uri->s));
  strcpy(uri->s, "file://");
  if (*fn != '/') {
    if (getcwd(uri->s + strlen(uri->s), sizeof(uri->s) - strlen(uri->s)) == NULL ||
	(!endswith(uri->s, "/") && strlen(uri->s) >= sizeof(uri->s) - 1))
      uri->s[0] = '\0';
    else
      strcat(uri->s, "/");
  }
  if (uri->s[0] != '\0' && strlen(uri->s) + strlen(fn) < sizeof(uri->s))
    strcat(uri->s, fn);
  else
    uri->s[0] = '\0';
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
 * Construct names for the directories not directly settable by the
 * user.
 *
 * This function also checks for an old-style rc->authenticated
 * directory, to simplify upgrade from older versions of rcynic.
 */
static int construct_directory_names(rcynic_ctx_t *rc)
{
  struct stat st;
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

  if (lstat(rc->authenticated.s, &st) == 0 && (st.st_mode & S_IFDIR) != 0 &&
      strlen(rc->authenticated.s) + sizeof(".old") < sizeof(p.s)) {
    p = rc->authenticated;
    strcat(p.s, ".old");
    rm_rf(&p);
    (void) rename(rc->authenticated.s, p.s);
  }

  if (lstat(rc->authenticated.s, &st) == 0 && (st.st_mode & S_IFDIR) != 0) {
    logmsg(rc, log_usage_err,
	   "Existing %s directory is in the way, please remove it",
	   rc->authenticated.s);
    return 0;
  }

  return 1;
}

/**
 * Do final symlink shuffle and cleanup of output directories.
 */
static int finalize_directories(const rcynic_ctx_t *rc)
{
  path_t path, real_old, real_new;
  const char *dir;
  glob_t g;
  int i;

  if (!realpath(rc->old_authenticated.s, real_old.s))
    real_old.s[0] = '\0';

  if (!realpath(rc->new_authenticated.s, real_new.s))
    real_new.s[0] = '\0';

  assert(real_new.s[0] && real_new.s[strlen(real_new.s) - 1] != '/');

  if ((dir = strrchr(real_new.s, '/')) == NULL)
    dir = real_new.s;
  else
    dir++;

  path = rc->authenticated;

  if (strlen(path.s) + sizeof(authenticated_symlink_suffix) >= sizeof(path.s))
    return 0;
  strcat(path.s, authenticated_symlink_suffix);

  (void) unlink(path.s);

  if (symlink(dir, path.s) < 0) {
    logmsg(rc, log_sys_err, "Couldn't link %s to %s: %s",
	   path.s, dir, strerror(errno));
    return 0;
  }

  if (rename(path.s, rc->authenticated.s) < 0) {
    logmsg(rc, log_sys_err, "Couldn't rename %s to %s: %s",
	   path.s, rc->authenticated.s, strerror(errno));
    return 0;
  }

  if (real_old.s[0] && strlen(rc->authenticated.s) + sizeof(".old") < sizeof(path.s)) {
    assert(real_old.s[strlen(real_old.s) - 1] != '/');

    path = rc->authenticated;
    strcat(path.s, ".old");

    (void) unlink(path.s);

    if ((dir = strrchr(real_old.s, '/')) == NULL)
      dir = real_old.s;
    else
      dir++;
    
    (void) symlink(dir, path.s);
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
    sk_X509_free(w->certs);
    sk_X509_CRL_pop_free(w->crls, X509_CRL_free);
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
 * Whether we're done iterating over a walk context.  Think of this as
 * the thing you call (negated) in the second clause of a conceptual
 * "for" loop.
 */
static int walk_ctx_loop_done(STACK_OF(walk_ctx_t) *wsk)
{
  walk_ctx_t *w = walk_ctx_stack_head(wsk);
  return wsk == NULL || w == NULL || w->state >= walk_state_done;
}

/**
 * Walk context iterator.  Think of this as the thing you call in the
 * third clause of a conceptual "for" loop: this reinitializes as
 * necessary for the next pass through the loop.
 *
 * General idea here is that we have several state variables in a walk
 * context which collectively define the current pass, product URI,
 * etc, and we want to be able to iterate through this sequence via
 * the event system.  So this function steps to the next state.
 *
 * Conceptually, w->manifest->fileList and w->filenames form a single
 * array with index w->manifest_iteration + w->filename_iteration.
 * Beware of fencepost errors, I've gotten this wrong once already.
 * Slightly odd coding here is to make it easier to check this.
 */
static void walk_ctx_loop_next(const rcynic_ctx_t *rc, STACK_OF(walk_ctx_t) *wsk)
{
  walk_ctx_t *w = walk_ctx_stack_head(wsk);
  int n_manifest, n_filenames;

  assert(rc && wsk && w);

  assert(w->manifest_iteration >= 0 && w->filename_iteration >= 0);

  n_manifest  = w->manifest  ? sk_FileAndHash_num(w->manifest->fileList) : 0;
  n_filenames = w->filenames ? sk_OPENSSL_STRING_num(w->filenames)       : 0;

  if (w->manifest_iteration + w->filename_iteration < n_manifest + n_filenames) {
    if (w->manifest_iteration < n_manifest)
      w->manifest_iteration++;
    else
      w->filename_iteration++;
  }

  assert(w->manifest_iteration <= n_manifest && w->filename_iteration <= n_filenames);

  if (w->manifest_iteration + w->filename_iteration < n_manifest + n_filenames)
    return;

  while (!walk_ctx_loop_done(wsk)) {
    w->state++;
    w->manifest_iteration = 0;
    w->filename_iteration = 0;
    sk_OPENSSL_STRING_pop_free(w->filenames, OPENSSL_STRING_free);
    w->filenames = directory_filenames(rc, w->state, &w->certinfo.sia);
    if (w->manifest != NULL || w->filenames != NULL)
      return;
  }
}

static int check_manifest(rcynic_ctx_t *rc, STACK_OF(walk_ctx_t) *wsk);

/**
 * Loop initializer for walk context.  Think of this as the thing you
 * call in the first clause of a conceptual "for" loop.
 */
static void walk_ctx_loop_init(rcynic_ctx_t *rc, STACK_OF(walk_ctx_t) *wsk)
{
  walk_ctx_t *w = walk_ctx_stack_head(wsk);

  assert(rc && wsk && w && w->state == walk_state_ready);

  assert(!w->manifest);

  if (!check_manifest(rc, wsk)) {
    /*
     * Simple failure to find a manifest doesn't get here.  This is
     * for manifest failures that cause us to reject all of this
     * certificate's products due to policy knob settings.
     */
    w->state = walk_state_done;
    return;
  }

  if (!w->manifest)
    logmsg(rc, log_telemetry, "Couldn't get manifest %s, blundering onward", w->certinfo.manifest.s);

  w->manifest_iteration = 0;
  w->filename_iteration = 0;
  w->state++;
  assert(w->state == walk_state_current);

  assert(w->filenames == NULL);
  w->filenames = directory_filenames(rc, w->state, &w->certinfo.sia);

  w->stale_manifest = w->manifest != NULL && X509_cmp_current_time(w->manifest->nextUpdate) < 0;

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

  if (x == NULL ||
      (certinfo == NULL) != (sk_walk_ctx_t_num(wsk) == 0) ||
      (w = malloc(sizeof(*w))) == NULL)
    return NULL;

  memset(w, 0, sizeof(*w));
  w->cert = x;
  if (certinfo != NULL)
    w->certinfo = *certinfo;
  else
    memset(&w->certinfo, 0, sizeof(w->certinfo));

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
 * created STACK_OF(X509) pointing to the existing cert objects.
 *
 * NB: This is a shallow copy, so use sk_X509_free() to free it, not 
 * sk_X509_pop_free().
 */
static STACK_OF(X509) *walk_ctx_stack_certs(const rcynic_ctx_t *rc,
					    STACK_OF(walk_ctx_t) *wsk)
{
  STACK_OF(X509) *xsk = sk_X509_new_null();
  walk_ctx_t *w;
  int i;

  assert(rc);

  for (i = 0; i < sk_walk_ctx_t_num(wsk); i++)
    if ((w = sk_walk_ctx_t_value(wsk, i)) == NULL ||
	(w->cert != NULL && !sk_X509_push(xsk, w->cert)))
      goto fail;

  return xsk;

 fail:
  logmsg(rc, log_sys_err, "Couldn't clone walk_ctx_stack, memory exhausted?");
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
 * Check cache of whether we've already fetched a particular URI.
 */
static rsync_history_t *rsync_history_uri(const rcynic_ctx_t *rc,
					  const uri_t *uri)
{
  rsync_history_t h;
  char *s;
  int i;

  assert(rc && uri && rc->rsync_history);

  if (!is_rsync(uri->s))
    return NULL;

  h.uri = *uri;

  while ((s = strrchr(h.uri.s, '/')) != NULL && s[1] == '\0')
    *s = '\0';

  while ((i = sk_rsync_history_t_find(rc->rsync_history, &h)) < 0) {
    if ((s = strrchr(h.uri.s, '/')) == NULL ||
	(s - h.uri.s) < SIZEOF_RSYNC)
      return NULL;
    *s = '\0';
  }

  return sk_rsync_history_t_value(rc->rsync_history, i);
}

/**
 * Check whether the local filename representation of a particular URI
 * has been cached.
 */
static int rsync_history_uri_filename(const rcynic_ctx_t *rc,
				      const char *filename)
{
  uri_t uri;

  if (strlen(filename) + SIZEOF_RSYNC >= sizeof(uri.s))
    return 0;

  strcpy(uri.s, SCHEME_RSYNC);
  strcat(uri.s, filename);

  return rsync_history_uri(rc, &uri) != NULL;
}

/**
 * Record that we've already attempted to synchronize a particular
 * rsync URI.
 */
static void rsync_history_add(const rcynic_ctx_t *rc,
			      const rsync_ctx_t *ctx,
			      const rsync_status_t status)
{
  int final_slash = 0;
  rsync_history_t *h;
  uri_t uri;
  size_t n;
  char *s;

  assert(rc && ctx && rc->rsync_history && is_rsync(ctx->uri.s));

  uri = ctx->uri;

  while ((s = strrchr(uri.s, '/')) != NULL && s[1] == '\0') {
    final_slash = 1;
    *s = '\0';
  }

  if (status != rsync_status_done) {

    n = SIZEOF_RSYNC + strcspn(uri.s + SIZEOF_RSYNC, "/");
    assert(n < sizeof(uri.s));
    uri.s[n] = '\0';
    final_slash = 1;

    if ((h = rsync_history_uri(rc, &uri)) != NULL) {
      assert(h->status != rsync_status_done);
      return;
    }
  }

  if ((h = rsync_history_t_new()) != NULL) {
    h->uri = uri;
    h->status = status;
    h->started = ctx->started;
    h->finished = time(0);
    h->final_slash = final_slash;
  }

  if (h == NULL || !sk_rsync_history_t_push(rc->rsync_history, h)) {
    rsync_history_t_free(h);
    logmsg(rc, log_sys_err,
	   "Couldn't add %s to rsync_history, blundering onwards", uri.s);
  }
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
    case rsync_state_closed:
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

  case rsync_state_closed:
  case rsync_state_terminating:
    return 0;

  case rsync_state_conflict_wait:
    return !rsync_conflicts(rc, ctx);

  default:
    break;
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
static void rsync_run(rcynic_ctx_t *rc,
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

  if (rsync_history_uri(rc, &ctx->uri)) {
    logmsg(rc, log_verbose, "Late rsync cache hit for %s", ctx->uri.s);
    if (ctx->handler)
      ctx->handler(rc, ctx, rsync_status_done, &ctx->uri, ctx->wsk);
    (void) sk_rsync_ctx_t_delete_ptr(rc->rsync_queue, ctx);
    free(ctx);
    return;
  }

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
    logmsg(rc, log_debug, "rsync argv[%d]: %s", i, argv[i]);

  if (pipe(pipe_fds) < 0) {
    logmsg(rc, log_sys_err, "pipe() failed: %s", strerror(errno));
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
    ctx->fd = pipe_fds[0];
    if ((flags = fcntl(ctx->fd, F_GETFL, 0)) == -1 ||
	fcntl(ctx->fd, F_SETFL, flags | O_NONBLOCK) == -1) {
      logmsg(rc, log_sys_err, "fcntl(ctx->fd, F_[GS]ETFL, O_NONBLOCK) failed: %s",
	     strerror(errno));
      goto lose;
    }
    (void) close(pipe_fds[1]);
    ctx->state = rsync_state_running;
    ctx->problem = rsync_problem_none;
    if (!ctx->started)
      ctx->started = time(0);
    if (rc->rsync_timeout)
      ctx->deadline = time(0) + rc->rsync_timeout;
    logmsg(rc, log_verbose, "Subprocess %u started, queued %d, runable %d, running %d, max %d, URI %s",
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
  if (ctx->pid > 0) {
    (void) kill(ctx->pid, SIGKILL);
    ctx->pid = 0;
  }
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
      logmsg(rc, log_verbose, "Subprocess %u reported limit of %u for %s", ctx->pid, u, ctx->uri.s);
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

  assert(rc && rc->rsync_queue && rfds && tv && rc->max_select_time >= 0);

  FD_ZERO(rfds);

  for (i = 0; (ctx = sk_rsync_ctx_t_value(rc->rsync_queue, i)) != NULL; ++i) {

#if 0
    logmsg(rc, log_debug, "+++ ctx[%d] pid %d fd %d state %s started %lu deadline %lu",
	   i, ctx->pid, ctx->fd, rsync_state_label[ctx->state],
	   (unsigned long) ctx->started, (unsigned long) ctx->deadline);
#endif

    switch (ctx->state) {

    case rsync_state_running:
      assert(ctx->fd >= 0);
      FD_SET(ctx->fd, rfds);
      if (ctx->fd > n)
	n = ctx->fd;
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

  if (when && when < now + rc->max_select_time)
    tv->tv_sec = when - now;
  else
    tv->tv_sec = rc->max_select_time;
  tv->tv_usec = 0;
  return n;
}

/**
 * Convert rsync_status_t to mib_counter_t.
 *
 * Maybe some day this will go away and we won't be carrying
 * essentially the same information in two different databases, but
 * for now I'll settle for cleaning up the duplicate code logic.
 */
static mib_counter_t rsync_status_to_mib_counter(rsync_status_t status)
{
  switch (status) {
  case rsync_status_done:	return rsync_transfer_succeeded;
  case rsync_status_timed_out:	return rsync_transfer_timed_out;
  case rsync_status_failed:	return rsync_transfer_failed;
  case rsync_status_skipped:	return rsync_transfer_skipped;
  default:
    /*
     * Keep GCC from whining about untested cases.
     */
    assert(status == rsync_status_done ||
	   status == rsync_status_timed_out ||
	   status == rsync_status_failed ||
	   status == rsync_status_skipped);
    return rsync_transfer_failed;
  }
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
static void rsync_mgr(rcynic_ctx_t *rc)
{
  rsync_status_t rsync_status;
  int i, n, pid_status = -1;
  rsync_ctx_t *ctx = NULL;
  time_t now = time(0);
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

    logmsg(rc, log_verbose, "Subprocess %u exited with status %d",
	   (unsigned) pid, WEXITSTATUS(pid_status));

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
      rsync_status = rsync_status_done;
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
      goto failure;

    case 23:			/* "Partial transfer due to error" */
      /*
       * This appears to be a catch-all for "something bad happened
       * trying to do what you asked me to do".  In the cases I've
       * seen to date, this is things like "the directory you
       * requested isn't there" or "NFS exploded when I tried to touch
       * the directory".  These aren't network layer failures, so we
       * (probably) shouldn't give up on the repository host.
       */
      rsync_status = rsync_status_done;
      log_validation_status(rc, &ctx->uri, rsync_partial_transfer, object_generation_null);
      break;

    default:
    failure:
      rsync_status = rsync_status_failed;
      logmsg(rc, log_data_err, "rsync %u exited with status %d fetching %s",
	     (unsigned) pid, WEXITSTATUS(pid_status), ctx->uri.s);
      break;
    }

    if (rc->rsync_timeout && now >= ctx->deadline)
      rsync_status = rsync_status_timed_out;
    log_validation_status(rc, &ctx->uri,
			  rsync_status_to_mib_counter(rsync_status),
			  object_generation_null);
    rsync_history_add(rc, ctx, rsync_status);
    if (ctx->handler)
      ctx->handler(rc, ctx, rsync_status, &ctx->uri, ctx->wsk);
    (void) sk_rsync_ctx_t_delete_ptr(rc->rsync_queue, ctx);
    free(ctx);
    ctx = NULL;
  }

  if (pid == -1 && errno != EINTR && errno != ECHILD)
    logmsg(rc, log_sys_err, "waitpid() returned error: %s", strerror(errno));

  assert(rsync_count_running(rc) <= rc->max_parallel_fetches);

  /*
   * Look for rsync contexts that have become runable.  Odd loop
   * structure is because rsync_run() might decide to remove the
   * specified rsync task from the queue instead of running it.
   */
  for (i = 0; (ctx = sk_rsync_ctx_t_value(rc->rsync_queue, i)) != NULL; i++) {
    n = sk_rsync_ctx_t_num(rc->rsync_queue);
    if (ctx->state != rsync_state_running &&
	rsync_runable(rc, ctx) &&
	rsync_count_running(rc) < rc->max_parallel_fetches)
      rsync_run(rc, ctx);
    if (n > sk_rsync_ctx_t_num(rc->rsync_queue))
      i--;
  }

  assert(rsync_count_running(rc) <= rc->max_parallel_fetches);

  /*
   * Check for log text from subprocesses.
   */

  n = rsync_construct_select(rc, now, &rfds, &tv);

  if (n > 0) {
#if 0
    logmsg(rc, log_debug, "++ select(%d, %u)", n, tv.tv_sec);
#endif
    n = select(n + 1, &rfds, NULL, NULL, &tv);
  }

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
	ctx->state = rsync_state_closed;
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
	rsync_history_add(rc, ctx, rsync_status_timed_out);
      } else if (sig == SIGTERM) {
	logmsg(rc, log_verbose, "Whacking subprocess %u again", (unsigned) ctx->pid);
      } else {
	logmsg(rc, log_verbose, "Whacking subprocess %u with big hammer", (unsigned) ctx->pid);
      }
      (void) kill(ctx->pid, sig);
      ctx->deadline = now + 1;
    }
  }
}

/**
 * Set up rsync context and attempt to start it.
 */
static void rsync_init(rcynic_ctx_t *rc,
		       const uri_t *uri,
		       STACK_OF(walk_ctx_t) *wsk,
		       void (*handler)(rcynic_ctx_t *, const rsync_ctx_t *, const rsync_status_t, const uri_t *, STACK_OF(walk_ctx_t) *))
{
  rsync_ctx_t *ctx = NULL;

  assert(rc && uri && strlen(uri->s) > SIZEOF_RSYNC);

  if (!rc->run_rsync) {
    logmsg(rc, log_verbose, "rsync disabled, skipping %s", uri->s);
    if (handler)
      handler(rc, NULL, rsync_status_skipped, uri, wsk);
    return;
  }

  if (rsync_history_uri(rc, uri)) {
    logmsg(rc, log_verbose, "rsync cache hit for %s", uri->s);
    if (handler)
      handler(rc, NULL, rsync_status_done, uri, wsk);
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
}

/**
 * rsync a single file (trust anchor, CRL, manifest, ROA, whatever).
 */
static void rsync_file(rcynic_ctx_t *rc,
		       const uri_t *uri)
{
  assert(!endswith(uri->s, "/"));
  rsync_init(rc, uri, NULL, NULL);
}

/**
 * rsync an entire subtree, generally rooted at a SIA collection.
 */
static void rsync_tree(rcynic_ctx_t *rc,
		       const uri_t *uri,
		       STACK_OF(walk_ctx_t) *wsk,
		       void (*handler)(rcynic_ctx_t *, const rsync_ctx_t *, const rsync_status_t, const uri_t *, STACK_OF(walk_ctx_t) *))
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

  if (rsync_history_uri_filename(rc, name->s + baselen)) {
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
      if (rsync_history_uri_filename(rc, path.s + baselen)) {
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
 * Extract CRLDP data from a certificate.  Stops looking after finding
 * the first rsync URI.
 */
static int extract_crldp_uri(rcynic_ctx_t *rc,
			     const uri_t *uri,
			     const object_generation_t generation,
			     const STACK_OF(DIST_POINT) *crldp,
			     uri_t *result)
{
  DIST_POINT *d;
  int i;

  assert(rc && uri && crldp && result);

  if (sk_DIST_POINT_num(crldp) != 1)
    goto bad;

  d = sk_DIST_POINT_value(crldp, 0);

  if (d->reasons || d->CRLissuer || !d->distpoint || d->distpoint->type != 0)
    goto bad;

  for (i = 0; i < sk_GENERAL_NAME_num(d->distpoint->name.fullname); i++) {
    GENERAL_NAME *n = sk_GENERAL_NAME_value(d->distpoint->name.fullname, i);
    if (n == NULL || n->type != GEN_URI)
      goto bad;
    if (!is_rsync((char *) n->d.uniformResourceIdentifier->data))
      log_validation_status(rc, uri, non_rsync_uri_in_extension, generation);
    else if (sizeof(result->s) <= n->d.uniformResourceIdentifier->length)
      log_validation_status(rc, uri, uri_too_long, generation);
    else if (result->s[0])
      log_validation_status(rc, uri, multiple_rsync_uris_in_extension, generation);
    else
      strcpy(result->s, (char *) n->d.uniformResourceIdentifier->data);
  }

  return result->s[0];

 bad:
  log_validation_status(rc, uri, malformed_crldp_extension, generation);
  return 0;
}

/**
 * Extract SIA or AIA data from a certificate.
 */
static int extract_access_uri(rcynic_ctx_t *rc,
			      const uri_t *uri,
			      const object_generation_t generation,
			      const AUTHORITY_INFO_ACCESS *xia,
			      const unsigned char *oid,
			      const int oidlen,
			      uri_t *result,
			      int *count)
{
  int i;

  assert(rc && uri && xia && oid && result && count);

  for (i = 0; i < sk_ACCESS_DESCRIPTION_num(xia); i++) {
    ACCESS_DESCRIPTION *a = sk_ACCESS_DESCRIPTION_value(xia, i);
    if (a == NULL || a->location->type != GEN_URI)
      return 0;
    if (oid_cmp(a->method, oid, oidlen))
      continue;
    ++*count;
    if (!is_rsync((char *) a->location->d.uniformResourceIdentifier->data))
      log_validation_status(rc, uri, non_rsync_uri_in_extension, generation);
    else if (sizeof(result->s) <= a->location->d.uniformResourceIdentifier->length)
      log_validation_status(rc, uri, uri_too_long, generation);
    else if (result->s[0])
      log_validation_status(rc, uri, multiple_rsync_uris_in_extension, generation);
    else
      strcpy(result->s, (char *) a->location->d.uniformResourceIdentifier->data);      
  }
  return 1;
}



/**
 * Check to see whether an AKI extension is present, is of the right
 * form, and matches the issuer.
 */
static int check_aki(rcynic_ctx_t *rc,
		     const uri_t *uri,
		     const X509 *issuer,
		     const AUTHORITY_KEYID *aki,
		     const object_generation_t generation)
{
  assert(rc && uri && issuer && issuer->skid);

  if (aki == NULL) {
    log_validation_status(rc, uri, aki_extension_missing, generation);
    return 0;
  }

  if (!aki->keyid || aki->serial || aki->issuer) {
    log_validation_status(rc, uri, aki_extension_wrong_format, generation);
    return 0;
  }

  if (ASN1_OCTET_STRING_cmp(aki->keyid, issuer->skid)) {
    log_validation_status(rc, uri, aki_extension_issuer_mismatch, generation);
    return 0;
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
 * Check whether an ASN.1 TIME value conforms to RFC 5280 4.1.2.5.
 */
static int check_allowed_time_encoding(ASN1_TIME *t)
{
  switch (t->type) {

  case V_ASN1_UTCTIME:
    return t->length == sizeof("yymmddHHMMSSZ") - 1;
    
  case  V_ASN1_GENERALIZEDTIME:
    return (t->length == sizeof("yyyymmddHHMMSSZ") - 1 &&
	    strcmp("205", (char *) t->data) <= 0);

  }
  return 0;
}



/**
 * Attempt to read and check one CRL from disk.
 */

static X509_CRL *check_crl_1(rcynic_ctx_t *rc,
			     const uri_t *uri,
			     path_t *path,
			     const path_t *prefix,
			     X509 *issuer,
			     const object_generation_t generation)
{
  STACK_OF(X509_REVOKED) *revoked;
  X509_CRL *crl = NULL;
  EVP_PKEY *pkey;
  int i, ret;

  assert(uri && path && issuer);

  if (!uri_to_filename(rc, uri, path, prefix) ||
      (crl = read_crl(path, NULL)) == NULL)
    goto punt;

  if (X509_CRL_get_version(crl) != 1) {
    log_validation_status(rc, uri, wrong_object_version, generation);
    goto punt;
  }

  if (!crl->crl || !crl->crl->sig_alg || !crl->crl->sig_alg->algorithm ||
      OBJ_obj2nid(crl->crl->sig_alg->algorithm) != NID_sha256WithRSAEncryption) {
    log_validation_status(rc, uri, nonconformant_signature_algorithm, generation);
    goto punt;
  }

  if (!check_allowed_time_encoding(X509_CRL_get_lastUpdate(crl)) ||
      !check_allowed_time_encoding(X509_CRL_get_nextUpdate(crl))) {
    log_validation_status(rc, uri, nonconformant_asn1_time_value, generation);
    goto punt;
  }

  if (X509_cmp_current_time(X509_CRL_get_lastUpdate(crl)) > 0) {
    log_validation_status(rc, uri, crl_not_yet_valid, generation);
    goto punt;
  }

  if (X509_cmp_current_time(X509_CRL_get_nextUpdate(crl)) < 0) {
    log_validation_status(rc, uri, stale_crl_or_manifest, generation);
    if (!rc->allow_stale_crl)
      goto punt;
  }

  if (!check_aki(rc, uri, issuer, crl->akid, generation))
    goto punt;

  if (crl->crl_number == NULL) {
    log_validation_status(rc, uri, crl_number_extension_missing, generation);
    goto punt;
  }

  if (ASN1_INTEGER_cmp(crl->crl_number, asn1_zero) < 0 ||
      ASN1_INTEGER_cmp(crl->crl_number, asn1_twenty_octets) > 0) {
    log_validation_status(rc, uri, crl_number_out_of_range, generation);
    goto punt;
  }

  if (X509_CRL_get_ext_count(crl) != 2) {
    log_validation_status(rc, uri, disallowed_x509v3_extension, generation);
    goto punt;
  }

  if (!check_allowed_dn(X509_CRL_get_issuer(crl))) {
    log_validation_status(rc, uri, nonconformant_issuer_name, generation);
    if (!rc->allow_nonconformant_name)
      goto punt;
  }

  if ((revoked = X509_CRL_get_REVOKED(crl)) != NULL) {
    for (i = sk_X509_REVOKED_num(revoked) - 1; i >= 0; --i) {
      if (X509_REVOKED_get_ext_count(sk_X509_REVOKED_value(revoked, i)) > 0) {
	log_validation_status(rc, uri, disallowed_x509v3_extension, generation);
	goto punt;
      }
    }
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
 *
 * General plan here is to do basic checks on both current and backup
 * generation CRLs, then, if both generations pass all of our other
 * tests, pick the generation with the highest CRL number, to protect
 * against replay attacks.
 */
static X509_CRL *check_crl(rcynic_ctx_t *rc,
			   const uri_t *uri,
			   X509 *issuer)
{
  X509_CRL *old_crl, *new_crl, *result = NULL;
  path_t old_path, new_path;

  if (uri_to_filename(rc, uri, &new_path, &rc->new_authenticated) &&
      (new_crl = read_crl(&new_path, NULL)) != NULL)
    return new_crl;

  logmsg(rc, log_telemetry, "Checking CRL %s", uri->s);

  new_crl = check_crl_1(rc, uri, &new_path, &rc->unauthenticated,
			issuer, object_generation_current);

  old_crl = check_crl_1(rc, uri, &old_path, &rc->old_authenticated,
			issuer, object_generation_backup);

  if (!new_crl)
    result = old_crl;
  else if (!old_crl)
    result = new_crl;
  else if (ASN1_INTEGER_cmp(new_crl->crl_number, old_crl->crl_number) < 0)
    result = old_crl;
  else
    result = new_crl;

  if (result && result == new_crl)
    install_object(rc, uri, &new_path, object_generation_current);
  else if (!access(new_path.s, F_OK))
    log_validation_status(rc, uri, object_rejected, object_generation_current);

  if (result && result == old_crl)
    install_object(rc, uri, &old_path, object_generation_backup);
  else if (!result && !access(old_path.s, F_OK))
    log_validation_status(rc, uri, object_rejected, object_generation_backup);

  if (result != new_crl)
    X509_CRL_free(new_crl);
    
  if (result != old_crl)
    X509_CRL_free(old_crl);

  return result;
}


/**
 * Check digest of a CRL we've already accepted.
 */
static int check_crl_digest(const rcynic_ctx_t *rc,
			    const uri_t *uri,
			    const unsigned char *hash,
			    const size_t hashlen)
{
  X509_CRL *crl = NULL;
  hashbuf_t hashbuf;
  path_t path;
  int result;

  assert(rc && uri && hash);

  if (!uri_to_filename(rc, uri, &path, &rc->new_authenticated) ||
      (crl = read_crl(&path, &hashbuf)) == NULL)
    return 0;

  result = hashlen <= sizeof(hashbuf.h) && !memcmp(hashbuf.h, hash, hashlen);

  X509_CRL_free(crl);

  return result;
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
    code = unknown_openssl_verify_error;
    break;
  }

  log_validation_status(rctx->rc, &rctx->subject->uri, code, rctx->subject->generation);
  return ok;
}

/**
 * Check crypto aspects of a certificate, policy OID, RFC 3779 path
 * validation, and conformance to the RPKI certificate profile.
 */
static int check_x509(rcynic_ctx_t *rc,
		      STACK_OF(walk_ctx_t) *wsk,
		      const uri_t *uri,
		      X509 *x,
		      certinfo_t *certinfo,
		      const object_generation_t generation)
{
  walk_ctx_t *w = walk_ctx_stack_head(wsk);
  rcynic_x509_store_ctx_t rctx;
  EVP_PKEY *issuer_pkey = NULL, *subject_pkey = NULL;
  unsigned long flags = (X509_V_FLAG_POLICY_CHECK | X509_V_FLAG_EXPLICIT_POLICY | X509_V_FLAG_X509_STRICT);
  AUTHORITY_INFO_ACCESS *sia = NULL, *aia = NULL;
  STACK_OF(POLICYINFO) *policies = NULL;
  ASN1_BIT_STRING *ski_pubkey = NULL;
  STACK_OF(DIST_POINT) *crldp = NULL;
  BASIC_CONSTRAINTS *bc = NULL;
  hashbuf_t ski_hashbuf;
  unsigned ski_hashlen;
  int ok, crit, loc, ex_count, ret = 0;

  assert(rc && wsk && w && uri && x && w->cert);

  /*
   * Cleanup logic will explode if rctx.ctx hasn't been initialized,
   * so we need to do this before running any test that can fail.
   */
  if (!X509_STORE_CTX_init(&rctx.ctx, rc->x509_store, x, NULL))
    return 0;

  /*
   * certinfo == NULL means x is a self-signed trust anchor.
   */
  if (certinfo == NULL)
    certinfo = &w->certinfo;

  memset(certinfo, 0, sizeof(*certinfo));

  certinfo->uri = *uri;
  certinfo->generation = generation;

  if (ASN1_INTEGER_cmp(X509_get_serialNumber(x), asn1_zero) <= 0) {
    log_validation_status(rc, uri, bad_serial_number, generation);
    goto done;
  }

  if (!check_allowed_time_encoding(X509_get_notBefore(x)) ||
      !check_allowed_time_encoding(X509_get_notAfter(x))) {
    log_validation_status(rc, uri, nonconformant_asn1_time_value, generation);
    goto done;
  }

  /*
   * Apparently nothing ever looks at these fields, so there are no
   * API functions for them.  We wouldn't bother either if they
   * weren't forbidden by the RPKI certificate profile.
   */
  if (!x->cert_info || x->cert_info->issuerUID || x->cert_info->subjectUID) {
    log_validation_status(rc, uri, nonconformant_certificate_uid, generation);
    goto done;
  }

  /*
   * Keep track of allowed extensions we've seen.  Once we've
   * processed all the ones we expect, anything left is an error.
   */
  ex_count = X509_get_ext_count(x);

  /*
   * We don't use X509_check_ca() to set certinfo->ca anymore, because
   * it's not paranoid enough to enforce the RPKI certificate profile,
   * but we still call it because we need it (or something) to invoke
   * x509v3_cache_extensions() for us.
   */
  (void) X509_check_ca(x);

  if ((bc = X509_get_ext_d2i(x, NID_basic_constraints, &crit, NULL)) != NULL) {
    ex_count--;
    if (!crit || bc->ca <= 0 || bc->pathlen != NULL) {
      log_validation_status(rc, uri, malformed_basic_constraints, generation);
      goto done;
    }
  }

  certinfo->ca = bc != NULL;

  if (certinfo == &w->certinfo) {
    certinfo->ta = 1;
    if (!certinfo->ca) {
      log_validation_status(rc, uri, malformed_trust_anchor, generation);
      goto done;
    }
  }

  if ((aia = X509_get_ext_d2i(x, NID_info_access, NULL, NULL)) != NULL) {
    int n_caIssuers = 0;
    ex_count--;
    if (!extract_access_uri(rc, uri, generation, aia,
			    id_ad_caIssuers, sizeof(id_ad_caIssuers),
			    &certinfo->aia, &n_caIssuers) ||
	!certinfo->aia.s[0] ||
	sk_ACCESS_DESCRIPTION_num(aia) != n_caIssuers) {
      log_validation_status(rc, uri, malformed_aia_extension, generation);
      goto done;
    }
  }

  if (certinfo->ta && aia) {
    log_validation_status(rc, uri, aia_extension_forbidden, generation);
    goto done;
  }

  if (!certinfo->ta && !aia) {
    log_validation_status(rc, uri, aia_extension_missing, generation);
    goto done;
  }

  if ((sia = X509_get_ext_d2i(x, NID_sinfo_access, NULL, NULL)) != NULL) {
    int got_caDirectory,     got_rpkiManifest,     got_signedObject;
    int   n_caDirectory = 0,   n_rpkiManifest = 0,   n_signedObject = 0;
    ex_count--;
    ok = (extract_access_uri(rc, uri, generation, sia, id_ad_caRepository,
			     sizeof(id_ad_caRepository), &certinfo->sia, &n_caDirectory) &&
	  extract_access_uri(rc, uri, generation, sia, id_ad_rpkiManifest,
			     sizeof(id_ad_rpkiManifest), &certinfo->manifest, &n_rpkiManifest) &&
	  extract_access_uri(rc, uri, generation, sia, id_ad_signedObject,
			     sizeof(id_ad_signedObject), &certinfo->signedobject, &n_signedObject));
    got_caDirectory  = certinfo->sia.s[0]          != '\0';
    got_rpkiManifest = certinfo->manifest.s[0]     != '\0';
    got_signedObject = certinfo->signedobject.s[0] != '\0';
    ok &= sk_ACCESS_DESCRIPTION_num(sia) == n_caDirectory + n_rpkiManifest + n_signedObject;
    if (certinfo->ca)
      ok &=  got_caDirectory &&  got_rpkiManifest && !got_signedObject;
    else if (rc->allow_ee_without_signedObject)
      ok &= !got_caDirectory && !got_rpkiManifest;
    else
      ok &= !got_caDirectory && !got_rpkiManifest &&  got_signedObject;
    if (!ok) {
      log_validation_status(rc, uri, malformed_sia_extension, generation);
      goto done;
    }
  } else if (certinfo->ca || !rc->allow_ee_without_signedObject) {
    log_validation_status(rc, uri, sia_extension_missing, generation);
    goto done;
  }

  if ((crldp = X509_get_ext_d2i(x, NID_crl_distribution_points, NULL, NULL)) != NULL) {
    ex_count--;
    if (!extract_crldp_uri(rc, uri, generation, crldp, &certinfo->crldp))
      goto done;
  }

  rctx.rc = rc;
  rctx.subject = certinfo;

  if (w->certs == NULL && (w->certs = walk_ctx_stack_certs(rc, wsk)) == NULL)
    goto done;

  if (X509_get_version(x) != 2) {
    log_validation_status(rc, uri, wrong_object_version, generation);
    goto done;
  }

  if (!x->cert_info || !x->cert_info->signature || !x->cert_info->signature->algorithm ||
      OBJ_obj2nid(x->cert_info->signature->algorithm) != NID_sha256WithRSAEncryption) {
    log_validation_status(rc, uri, nonconformant_signature_algorithm, generation);
    goto done;
  }

  if (certinfo->sia.s[0] && certinfo->sia.s[strlen(certinfo->sia.s) - 1] != '/') {
    log_validation_status(rc, uri, malformed_cadirectory_uri, generation);
    goto done;
  }

  if (!w->certinfo.ta && strcmp(w->certinfo.uri.s, certinfo->aia.s))
    log_validation_status(rc, uri, aia_doesnt_match_issuer, generation);

  if (certinfo->ca && !certinfo->sia.s[0]) {
    log_validation_status(rc, uri, sia_cadirectory_uri_missing, generation);
    goto done;
  }

  if (certinfo->ca && !certinfo->manifest.s[0]) {
    log_validation_status(rc, uri, sia_manifest_uri_missing, generation);
    goto done;
  }

  if (certinfo->ca && !startswith(certinfo->manifest.s, certinfo->sia.s)) {
    log_validation_status(rc, uri, manifest_carepository_mismatch, generation);
    goto done;
  }

  if (x->skid) {
    ex_count--;
  } else {
    log_validation_status(rc, uri, ski_extension_missing, generation);
    goto done;
  }

  if (!check_allowed_dn(X509_get_subject_name(x))) {
    log_validation_status(rc, uri, nonconformant_subject_name, generation);
    if (!rc->allow_nonconformant_name)
      goto done;
  }

  if (!check_allowed_dn(X509_get_issuer_name(x))) {
    log_validation_status(rc, uri, nonconformant_issuer_name, generation);
    if (!rc->allow_nonconformant_name)
      goto done;
  }

  if ((policies = X509_get_ext_d2i(x, NID_certificate_policies, &crit, NULL)) != NULL) {
    ex_count--;
    if (!crit || sk_POLICYINFO_num(policies) != 1) {
      log_validation_status(rc, uri, malformed_certificate_policy, generation);
      goto done;
    }
  }

  if (!X509_EXTENSION_get_critical(X509_get_ext(x, X509_get_ext_by_NID(x, NID_key_usage, -1))) ||
      (x->ex_flags & EXFLAG_KUSAGE) == 0 ||
      x->ex_kusage != (certinfo->ca ? KU_KEY_CERT_SIGN | KU_CRL_SIGN : KU_DIGITAL_SIGNATURE)) {
    log_validation_status(rc, uri, bad_key_usage, generation);
    goto done;
  }
  ex_count--;

  if (X509_get_ext_by_NID(x, NID_ext_key_usage, -1) >= 0) {
    ex_count--;
    if (certinfo->ca) {
      log_validation_status(rc, uri, inappropriate_eku_extension, generation);
      goto done;
    }
  }

  if (x->rfc3779_addr) {
    ex_count--;
    if ((loc = X509_get_ext_by_NID(x, NID_sbgp_ipAddrBlock, -1)) < 0 ||
	!X509_EXTENSION_get_critical(X509_get_ext(x, loc)) ||
	!v3_addr_is_canonical(x->rfc3779_addr)) {
      log_validation_status(rc, uri, bad_ipaddrblocks, generation);
      goto done;
    }
  }

  if (x->rfc3779_asid) {
    ex_count--;
    if ((loc = X509_get_ext_by_NID(x, NID_sbgp_autonomousSysNum, -1)) < 0 ||
	!X509_EXTENSION_get_critical(X509_get_ext(x, loc)) ||
	!v3_asid_is_canonical(x->rfc3779_asid) ||
	x->rfc3779_asid->rdi != NULL) {
      log_validation_status(rc, uri, bad_asidentifiers, generation);
      goto done;
    }
  }

  if (!x->rfc3779_addr && !x->rfc3779_asid) {
    log_validation_status(rc, uri, missing_resources, generation);
    goto done;
  }

  subject_pkey = X509_get_pubkey(x);
  ok = subject_pkey != NULL;
  if (ok) {
    ASN1_OBJECT *algorithm;

    (void) X509_PUBKEY_get0_param(&algorithm, NULL, NULL, NULL, X509_get_X509_PUBKEY(x));      

    switch (OBJ_obj2nid(algorithm)) {

    case NID_rsaEncryption:
      ok = (EVP_PKEY_type(subject_pkey->type) == EVP_PKEY_RSA &&
	    BN_get_word(subject_pkey->pkey.rsa->e) == 65537);
      if (!ok)
	break;
      if (!certinfo->ca && rc->allow_1024_bit_ee_key &&
	  BN_num_bits(subject_pkey->pkey.rsa->n) == 1024)
	log_validation_status(rc, uri, ee_certificate_with_1024_bit_key, generation);
      else
	ok = BN_num_bits(subject_pkey->pkey.rsa->n) == 2048;
      break;

    case NID_X9_62_id_ecPublicKey:	/* See draft-ietf-sidr-bgpsec-algs */
      ok = !certinfo->ca;		/* All I know how to test for now */
      break;

    default:
      ok = 0;
    }
  }
  if (!ok) {
    log_validation_status(rc, uri, bad_public_key, generation);
    goto done;
  }

  if (x->skid == NULL ||
      (ski_pubkey = X509_get0_pubkey_bitstr(x)) == NULL ||
      !EVP_Digest(ski_pubkey->data, ski_pubkey->length,
		  ski_hashbuf.h, &ski_hashlen, EVP_sha1(), NULL) ||
      ski_hashlen != 20 ||
      ski_hashlen != x->skid->length ||
      memcmp(ski_hashbuf.h, x->skid->data, ski_hashlen)) {
    log_validation_status(rc, uri, ski_public_key_mismatch, generation);
    goto done;
  }

  if (x->akid) {
    ex_count--;
    if (!check_aki(rc, uri, w->cert, x->akid, generation))
      goto done;
  }

  if (!x->akid && !certinfo->ta) {
    log_validation_status(rc, uri, aki_extension_missing, generation);
    goto done;
  }

  if ((issuer_pkey = X509_get_pubkey(w->cert)) == NULL || X509_verify(x, issuer_pkey) <= 0) {
    log_validation_status(rc, uri, certificate_bad_signature, generation);
    goto done;
  }

  if (certinfo->ta) {

    if (certinfo->crldp.s[0]) {
      log_validation_status(rc, uri, trust_anchor_with_crldp, generation);
      goto done;
    }

  } else {

    if (!certinfo->crldp.s[0]) {
      log_validation_status(rc, uri, crldp_uri_missing, generation);
      goto done;
    }

    if (!certinfo->ca && !startswith(certinfo->crldp.s, w->certinfo.sia.s)) {
      log_validation_status(rc, uri, crldp_doesnt_match_issuer_sia, generation);
      goto done;
    }

    if (w->crls == NULL && ((w->crls = sk_X509_CRL_new_null()) == NULL ||
			    !sk_X509_CRL_push(w->crls, NULL))) {
      logmsg(rc, log_sys_err, "Internal allocation error setting up CRL for validation");
      goto done;
    }

    assert(sk_X509_CRL_num(w->crls) == 1);
    assert((w->crldp.s[0] == '\0') == (sk_X509_CRL_value(w->crls, 0) == NULL));

    if (strcmp(w->crldp.s, certinfo->crldp.s)) {
      X509_CRL *old_crl = sk_X509_CRL_value(w->crls, 0);
      X509_CRL *new_crl = check_crl(rc, &certinfo->crldp, w->cert);

      if (w->crldp.s[0])
	log_validation_status(rc, uri, issuer_uses_multiple_crldp_values, generation);

      if (new_crl == NULL) {
	log_validation_status(rc, uri, bad_crl, generation);
	goto done;
      }

      if (old_crl && new_crl && ASN1_INTEGER_cmp(old_crl->crl_number, new_crl->crl_number) < 0) {
	log_validation_status(rc, uri, crldp_names_newer_crl, generation);
	X509_CRL_free(old_crl);
	old_crl = NULL;
      }

      if (old_crl == NULL) {
	sk_X509_CRL_set(w->crls, 0, new_crl);
	w->crldp = certinfo->crldp;
      } else {
	X509_CRL_free(new_crl);
      }
    }

    assert(sk_X509_CRL_value(w->crls, 0));
    flags |= X509_V_FLAG_CRL_CHECK;
    X509_STORE_CTX_set0_crls(&rctx.ctx, w->crls);
  }

  if (ex_count > 0) {
    log_validation_status(rc, uri, disallowed_x509v3_extension, generation);
    goto done;
  }

  assert(w->certs != NULL);
  X509_STORE_CTX_trusted_stack(&rctx.ctx, w->certs);
  X509_STORE_CTX_set_verify_cb(&rctx.ctx, check_x509_cb);

  X509_VERIFY_PARAM_set_flags(rctx.ctx.param, flags);

  X509_VERIFY_PARAM_add0_policy(rctx.ctx.param, OBJ_txt2obj(rpki_policy_oid, 1));

  if (X509_verify_cert(&rctx.ctx) <= 0) {
    log_validation_status(rc, uri, certificate_failed_validation, generation);
    goto done;
  }

  ret = 1;

 done:
  X509_STORE_CTX_cleanup(&rctx.ctx);
  EVP_PKEY_free(issuer_pkey);
  EVP_PKEY_free(subject_pkey);
  BASIC_CONSTRAINTS_free(bc);
  sk_ACCESS_DESCRIPTION_pop_free(sia, ACCESS_DESCRIPTION_free);
  sk_ACCESS_DESCRIPTION_pop_free(aia, ACCESS_DESCRIPTION_free);
  sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
  sk_POLICYINFO_pop_free(policies, POLICYINFO_free);

  return ret;
}

/**
 * Check a signed CMS object.
 */
static int check_cms(rcynic_ctx_t *rc,
		     STACK_OF(walk_ctx_t) *wsk,
		     const uri_t *uri,
		     path_t *path,
		     const path_t *prefix,
		     CMS_ContentInfo **pcms,
		     X509 **px,
		     certinfo_t *certinfo,
		     BIO *bio,
		     const unsigned char *hash,
		     const size_t hashlen,
		     const unsigned char *expected_eContentType,
		     const size_t expected_eContentType_len,
		     const int require_inheritance,
		     const object_generation_t generation)
{
  const ASN1_OBJECT *eContentType = NULL;
  STACK_OF(CMS_SignerInfo) *signer_infos = NULL;
  CMS_ContentInfo *cms = NULL;
  CMS_SignerInfo *si = NULL;
  ASN1_OCTET_STRING *sid = NULL;
  X509_NAME *si_issuer = NULL;
  ASN1_INTEGER *si_serial = NULL;
  STACK_OF(X509_CRL) *crls = NULL;
  X509_ALGOR *signature_alg = NULL, *digest_alg = NULL;
  ASN1_OBJECT *oid = NULL;
  X509_ATTRIBUTE *si_contentType = NULL;
  hashbuf_t hashbuf;
  X509 *x = NULL;
  certinfo_t certinfo_;
  int i, result = 0;

  assert(rc && wsk && uri && path && prefix && expected_eContentType);

  if (!certinfo)
    certinfo = &certinfo_;

  if (!uri_to_filename(rc, uri, path, prefix))
    goto error;

  if (hash)
    cms = read_cms(path, &hashbuf);
  else
    cms = read_cms(path, NULL);

  if (!cms)
    goto error;

  if (hash && (hashlen > sizeof(hashbuf.h) ||
	       memcmp(hashbuf.h, hash, hashlen))) {
    log_validation_status(rc, uri, digest_mismatch, generation);
    if (!rc->allow_digest_mismatch)
      goto error;
  }

  if (!(eContentType = CMS_get0_eContentType(cms)) ||
      oid_cmp(eContentType, expected_eContentType,
	      expected_eContentType_len)) {
    log_validation_status(rc, uri, bad_cms_econtenttype, generation);
    goto error;
  }

  if (CMS_verify(cms, NULL, NULL, NULL, bio, CMS_NO_SIGNER_CERT_VERIFY) <= 0) {
    log_validation_status(rc, uri, cms_validation_failure, generation);
    goto error;
  }

  if ((crls = CMS_get1_crls(cms)) != NULL) {
    log_validation_status(rc, uri, cms_includes_crls, generation);
    goto error;
  }

  if ((signer_infos = CMS_get0_SignerInfos(cms)) == NULL ||
      sk_CMS_SignerInfo_num(signer_infos) != 1 ||
      (si = sk_CMS_SignerInfo_value(signer_infos, 0)) == NULL ||
      !CMS_SignerInfo_get0_signer_id(si, &sid, &si_issuer, &si_serial) ||
      sid == NULL || si_issuer != NULL || si_serial != NULL ||
      CMS_unsigned_get_attr_count(si) != -1) {
    log_validation_status(rc, uri, bad_cms_signer_infos, generation);
    goto error;
  }

  CMS_SignerInfo_get0_algs(si, NULL, &x, &digest_alg, &signature_alg);

  if (x == NULL) {
    log_validation_status(rc, uri, cms_signer_missing, generation);
    goto error;
  }

  X509_ALGOR_get0(&oid, NULL, NULL, signature_alg);
  i = OBJ_obj2nid(oid);
  if (i != NID_sha256WithRSAEncryption && i != NID_rsaEncryption) {
    log_validation_status(rc, uri, wrong_cms_si_signature_algorithm, generation);
    goto error;
  }

  X509_ALGOR_get0(&oid, NULL, NULL, digest_alg);
  if (OBJ_obj2nid(oid) != NID_sha256) {
    log_validation_status(rc, uri, wrong_cms_si_digest_algorithm, generation);
    goto error;
  }

  i = CMS_signed_get_attr_count(si);

  if (CMS_signed_get_attr_by_NID(si, NID_pkcs9_signingTime, -1) >= 0)
    --i;

  if (CMS_signed_get_attr_by_NID(si, NID_binary_signing_time, -1) >= 0)
    --i;

  si_contentType = CMS_signed_get_attr(si, CMS_signed_get_attr_by_NID(si, NID_pkcs9_contentType, -1));

  if (i != 2 || si_contentType == NULL ||
      CMS_signed_get_attr_by_NID(si, NID_pkcs9_messageDigest, -1) < 0) {
    log_validation_status(rc, uri, bad_cms_si_signed_attributes, generation);
    if (!rc->allow_wrong_cms_si_attributes)
      goto error;
  }

  if ((oid = X509_ATTRIBUTE_get0_data(si_contentType, 0, V_ASN1_OBJECT, NULL)) == NULL ||
      oid_cmp(oid, expected_eContentType, expected_eContentType_len)) {
    log_validation_status(rc, uri, bad_cms_si_contenttype, generation);
    goto error;
  }

  if (CMS_SignerInfo_cert_cmp(si, x)) {
    log_validation_status(rc, uri, cms_ski_mismatch, generation);
    goto error;
  }

  if (!check_x509(rc, wsk, uri, x, certinfo, generation))
    goto error;

  if (require_inheritance && x->rfc3779_addr) {
    for (i = 0; i < sk_IPAddressFamily_num(x->rfc3779_addr); i++) {
      IPAddressFamily *f = sk_IPAddressFamily_value(x->rfc3779_addr, i);
      if (f->ipAddressChoice->type != IPAddressChoice_inherit) {
	log_validation_status(rc, uri, rfc3779_inheritance_required, generation);
	goto error;
      }
    }
  }

  if (require_inheritance && x->rfc3779_asid && x->rfc3779_asid->asnum &&
      x->rfc3779_asid->asnum->type != ASIdentifierChoice_inherit) {
    log_validation_status(rc, uri, rfc3779_inheritance_required, generation);
    goto error;
  }

  if (pcms) {
    *pcms = cms;
    cms = NULL;
  }

  if (px)
    *px = x;

  result = 1;

 error:
  CMS_ContentInfo_free(cms);
  sk_X509_CRL_pop_free(crls, X509_CRL_free);

  return result;
}



/**
 * Load certificate, check against manifest, then run it through all
 * the check_x509() tests.
 */
static X509 *check_cert_1(rcynic_ctx_t *rc,
			  STACK_OF(walk_ctx_t) *wsk,
			  const uri_t *uri,
			  path_t *path,
			  const path_t *prefix,
			  certinfo_t *certinfo,
			  const unsigned char *hash,
			  const size_t hashlen,
			  object_generation_t generation)
{
  hashbuf_t hashbuf;
  X509 *x = NULL;

  assert(uri && path && wsk && certinfo);

  if (!uri_to_filename(rc, uri, path, prefix))
    return NULL;

  if (access(path->s, R_OK))
    return NULL;

  if (hash)
    x = read_cert(path, &hashbuf);
  else
    x = read_cert(path, NULL);

  if (!x) {
    logmsg(rc, log_sys_err, "Can't read certificate %s", path->s);
    goto punt;
  }

  if (hash && (hashlen > sizeof(hashbuf.h) ||
	       memcmp(hashbuf.h, hash, hashlen))) {
    log_validation_status(rc, uri, digest_mismatch, generation);
    if (!rc->allow_digest_mismatch)
      goto punt;
  }

  if (check_x509(rc, wsk, uri, x, certinfo, generation))
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
			STACK_OF(walk_ctx_t) *wsk,
			uri_t *uri,
			certinfo_t *certinfo,
			const unsigned char *hash,
			const size_t hashlen)
{
  walk_ctx_t *w = walk_ctx_stack_head(wsk);
  object_generation_t generation;
  const path_t *prefix = NULL;
  path_t path;
  X509 *x;

  assert(rc && uri && wsk && w && certinfo);

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

  if (skip_checking_this_object(rc, uri, generation))
    return NULL;

  if ((x = check_cert_1(rc, wsk, uri, &path, prefix, certinfo,
			hash, hashlen, generation)) != NULL)
    install_object(rc, uri, &path, generation);
  else if (!access(path.s, F_OK))
    log_validation_status(rc, uri, object_rejected, generation);
  else if (hash && generation == w->manifest_generation)
    log_validation_status(rc, uri, manifest_lists_missing_object, generation);

  return x;
}



/**
 * Read and check one manifest from disk.
 */
static Manifest *check_manifest_1(rcynic_ctx_t *rc,
				  STACK_OF(walk_ctx_t) *wsk,
				  const uri_t *uri,
				  path_t *path,
				  const path_t *prefix,
				  certinfo_t *certinfo,
				  const object_generation_t generation)
{
  STACK_OF(FileAndHash) *sorted_fileList = NULL;
  Manifest *manifest = NULL, *result = NULL;
  CMS_ContentInfo *cms = NULL;
  FileAndHash *fah = NULL, *fah2 = NULL;
  BIO *bio = NULL;
  X509 *x;
  int i;

  assert(rc && wsk && uri && path && prefix);

  if ((bio = BIO_new(BIO_s_mem())) == NULL) {
    logmsg(rc, log_sys_err, "Couldn't allocate BIO for manifest %s", uri->s);
    goto done;
  }

  if (!check_cms(rc, wsk, uri, path, prefix, &cms, &x, certinfo, bio, NULL, 0,
		 id_ct_rpkiManifest, sizeof(id_ct_rpkiManifest), 1, generation))
    goto done;

  if ((manifest = ASN1_item_d2i_bio(ASN1_ITEM_rptr(Manifest), bio, NULL)) == NULL) {
    log_validation_status(rc, uri, cms_econtent_decode_error, generation);
    goto done;
  }

  if (manifest->version) {
    log_validation_status(rc, uri, wrong_object_version, generation);
    goto done;
  }

  if (X509_cmp_current_time(manifest->thisUpdate) > 0) {
    log_validation_status(rc, uri, manifest_not_yet_valid, generation);
    goto done;
  }

  if (X509_cmp_current_time(manifest->nextUpdate) < 0) {
    log_validation_status(rc, uri, stale_crl_or_manifest, generation);
    if (!rc->allow_stale_manifest)
      goto done;
  }

  if (ASN1_INTEGER_cmp(manifest->manifestNumber, asn1_zero) < 0) {
    log_validation_status(rc, uri, negative_manifest_number, generation);
    goto done;
  }

  if (manifest->fileHashAlg == NULL ||
      oid_cmp(manifest->fileHashAlg, id_sha256, sizeof(id_sha256))) {
    log_validation_status(rc, uri, nonconformant_digest_algorithm, generation);
    goto done;
  }

  if ((sorted_fileList = sk_FileAndHash_dup(manifest->fileList)) == NULL) {
    logmsg(rc, log_sys_err, "Couldn't allocate shallow copy of fileList for manifest %s", uri->s);
    goto done;
  }

  (void) sk_FileAndHash_set_cmp_func(sorted_fileList, FileAndHash_name_cmp);
  sk_FileAndHash_sort(sorted_fileList);

  for (i = 0; (fah = sk_FileAndHash_value(sorted_fileList, i)) != NULL && (fah2 = sk_FileAndHash_value(sorted_fileList, i + 1)) != NULL; i++) {
    if (!strcmp((char *) fah->file->data, (char *) fah2->file->data)) {
      log_validation_status(rc, uri, duplicate_name_in_manifest, generation);
      goto done;
    }
  }

  for (i = 0; (fah = sk_FileAndHash_value(manifest->fileList, i)) != NULL; i++) {
    if (fah->hash->length != HASH_SHA256_LEN ||
	(fah->hash->flags & (ASN1_STRING_FLAG_BITS_LEFT | 7)) > ASN1_STRING_FLAG_BITS_LEFT) {
      log_validation_status(rc, uri, bad_manifest_digest_length, generation);
      goto done;
    }
  }

  result = manifest;
  manifest = NULL;

 done:
  BIO_free(bio);
  Manifest_free(manifest);
  CMS_ContentInfo_free(cms);
  sk_FileAndHash_free(sorted_fileList);
  return result;
}

/**
 * Check whether we already have a particular manifest, attempt to fetch it
 * and check issuer's signature if we don't.
 *
 * General plan here is to do basic checks on both current and backup
 * generation manifests, then, if both generations pass all of our
 * other tests, pick the generation with the highest manifest number,
 * to protect against replay attacks.
 *
 * Once we've picked the manifest we're going to use, we need to check
 * it against the CRL we've chosen.  Not much we can do if they don't
 * match besides whine about it, but we do need to whine in this case.
 */
static int check_manifest(rcynic_ctx_t *rc,
			  STACK_OF(walk_ctx_t) *wsk)
{
  walk_ctx_t *w = walk_ctx_stack_head(wsk);
  Manifest *old_manifest, *new_manifest, *result = NULL;
  certinfo_t old_certinfo, new_certinfo;
  const uri_t *uri, *crldp = NULL;
  object_generation_t generation = object_generation_null;
  path_t old_path, new_path;
  FileAndHash *fah = NULL;
  const char *crl_tail;
  int i, ok = 1;

  assert(rc && wsk && w && !w->manifest);

  uri = &w->certinfo.manifest;

  logmsg(rc, log_telemetry, "Checking manifest %s", uri->s);

  new_manifest = check_manifest_1(rc, wsk, uri, &new_path,
				  &rc->unauthenticated, &new_certinfo,
				  object_generation_current);

  old_manifest = check_manifest_1(rc, wsk, uri, &old_path,
				  &rc->old_authenticated, &old_certinfo,
				  object_generation_backup);

  if (!new_manifest)
    result = old_manifest;
  else if (!old_manifest)
    result = new_manifest;
  else if (ASN1_INTEGER_cmp(new_manifest->manifestNumber, old_manifest->manifestNumber) < 0)
    result = old_manifest;
  else
    result = new_manifest;

  if (result && result == new_manifest) {
    generation = object_generation_current;
    install_object(rc, uri, &new_path, generation);
    crldp = &new_certinfo.crldp;
  }

  if (result && result == old_manifest) {
    generation = object_generation_backup;
    install_object(rc, uri, &old_path, generation);
    crldp = &old_certinfo.crldp;
  }

  if (result) {
    crl_tail = strrchr(crldp->s, '/');
    assert(crl_tail != NULL);
    crl_tail++;

    for (i = 0; (fah = sk_FileAndHash_value(result->fileList, i)) != NULL; i++)
      if (!strcmp((char *) fah->file->data, crl_tail))
	break;

    if (!fah) {
      log_validation_status(rc, uri, crl_not_in_manifest, generation);
      if (rc->require_crl_in_manifest)
	ok = 0;
    }

    else if (!check_crl_digest(rc, crldp, fah->hash->data, fah->hash->length)) {
      log_validation_status(rc, uri, digest_mismatch, generation);
      if (!rc->allow_crl_digest_mismatch)
	ok = 0;
    }
  }

  if ((!result || result != new_manifest) && !access(new_path.s, F_OK))
    log_validation_status(rc, uri, object_rejected, object_generation_current);
  
  if (!result && !access(old_path.s, F_OK))
    log_validation_status(rc, uri, object_rejected, object_generation_backup);

  if (result != new_manifest)
    Manifest_free(new_manifest);

  if (result != old_manifest)
    Manifest_free(old_manifest);

  w->manifest = result;
  if (crldp)
    w->crldp = *crldp;
  w->manifest_generation = generation;

  return ok;
}



/**
 * Extract a ROA prefix from the ASN.1 bitstring encoding.
 */
static int extract_roa_prefix(const ROAIPAddress *ra,
			      const unsigned afi,
			      unsigned char *addr,
			      unsigned *prefixlen)
{
  unsigned length;
  long maxlen;

  assert(addr && prefixlen && ra);

  maxlen = ASN1_INTEGER_get(ra->maxLength);

  switch (afi) {
  case IANA_AFI_IPV4: length =  4; break;
  case IANA_AFI_IPV6: length = 16; break;
  default: return 0;
  }

  if (ra->IPAddress->length < 0 || ra->IPAddress->length > length ||
      maxlen < 0 || maxlen > (long) length * 8)
    return 0;

  if (ra->IPAddress->length > 0) {
    memcpy(addr, ra->IPAddress->data, ra->IPAddress->length);
    if ((ra->IPAddress->flags & 7) != 0) {
      unsigned char mask = 0xFF >> (8 - (ra->IPAddress->flags & 7));
      addr[ra->IPAddress->length - 1] &= ~mask;
    }
  }

  memset(addr + ra->IPAddress->length, 0, length - ra->IPAddress->length);

  *prefixlen = (ra->IPAddress->length * 8) - (ra->IPAddress->flags & 7);

  return 1;
}

/**
 * Read and check one ROA from disk.
 */
static int check_roa_1(rcynic_ctx_t *rc,
		       STACK_OF(walk_ctx_t) *wsk,
		       const uri_t *uri,
		       path_t *path,
		       const path_t *prefix,
		       const unsigned char *hash,
		       const size_t hashlen,
		       const object_generation_t generation)
{
  STACK_OF(IPAddressFamily) *roa_resources = NULL, *ee_resources = NULL;
  unsigned char addrbuf[ADDR_RAW_BUF_LEN];
  CMS_ContentInfo *cms = NULL;
  BIO *bio = NULL;
  ROA *roa = NULL;
  X509 *x = NULL;
  int i, j, result = 0;
  unsigned afi, *safi = NULL, safi_, prefixlen;
  ROAIPAddressFamily *rf;
  ROAIPAddress *ra;

  assert(rc && wsk && uri && path && prefix);

  if ((bio = BIO_new(BIO_s_mem())) == NULL) {
    logmsg(rc, log_sys_err, "Couldn't allocate BIO for ROA %s", uri->s);
    goto error;
  }

  if (!check_cms(rc, wsk, uri, path, prefix, &cms, &x, NULL, bio, NULL, 0,
		 id_ct_routeOriginAttestation, sizeof(id_ct_routeOriginAttestation), 
		 0, generation))
    goto error;

  if (!(roa = ASN1_item_d2i_bio(ASN1_ITEM_rptr(ROA), bio, NULL))) {
    log_validation_status(rc, uri, cms_econtent_decode_error, generation);
    goto error;
  }

  if (roa->version) {
    log_validation_status(rc, uri, wrong_object_version, generation);
    goto error;
  }

  if (ASN1_INTEGER_cmp(roa->asID, asn1_zero) < 0 ||
      ASN1_INTEGER_cmp(roa->asID, asn1_four_octets) > 0) {
    log_validation_status(rc, uri, bad_roa_asID, generation);
    goto error;
  }

  ee_resources = X509_get_ext_d2i(x, NID_sbgp_ipAddrBlock, NULL, NULL);

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
	  !extract_roa_prefix(ra, afi, addrbuf, &prefixlen) ||
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
      log_validation_status(rc, uri, roa_contains_bad_afi_value, generation);
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
    log_validation_status(rc, uri, roa_resource_not_in_ee, generation);
    goto error;
  }

  result = 1;

 error:
  BIO_free(bio);
  ROA_free(roa);
  CMS_ContentInfo_free(cms);
  sk_IPAddressFamily_pop_free(roa_resources, IPAddressFamily_free);
  sk_IPAddressFamily_pop_free(ee_resources, IPAddressFamily_free);

  return result;
}

/**
 * Check whether we already have a particular ROA, attempt to fetch it
 * and check issuer's signature if we don't.
 */
static void check_roa(rcynic_ctx_t *rc,
		      STACK_OF(walk_ctx_t) *wsk,
		      const uri_t *uri,
		      const unsigned char *hash,
		      const size_t hashlen)
{
  walk_ctx_t *w = walk_ctx_stack_head(wsk);
  path_t path;

  assert(rc && wsk && w && uri);

  if (uri_to_filename(rc, uri, &path, &rc->new_authenticated) &&
      !access(path.s, F_OK))
    return;

  logmsg(rc, log_telemetry, "Checking ROA %s", uri->s);

  if (check_roa_1(rc, wsk, uri, &path, &rc->unauthenticated,
		  hash, hashlen, object_generation_current)) {
    install_object(rc, uri, &path, object_generation_current);
    return;
  }

  if (!access(path.s, F_OK))
    log_validation_status(rc, uri, object_rejected, object_generation_current);
  else if (hash)
    log_validation_status(rc, uri, manifest_lists_missing_object, object_generation_current);

  if (check_roa_1(rc, wsk, uri, &path, &rc->old_authenticated,
		  hash, hashlen, object_generation_backup)) {
    install_object(rc, uri, &path, object_generation_backup);
    return;
  }

  if (!access(path.s, F_OK))
    log_validation_status(rc, uri, object_rejected, object_generation_backup);
  else if (hash && w->manifest_generation == object_generation_backup)
    log_validation_status(rc, uri, manifest_lists_missing_object, object_generation_backup);
}



/**
 * Read and check one Ghostbuster record from disk.
 */
static int check_ghostbuster_1(rcynic_ctx_t *rc,
			       STACK_OF(walk_ctx_t) *wsk,
			       const uri_t *uri,
			       path_t *path,
			       const path_t *prefix,
			       const unsigned char *hash,
			       const size_t hashlen,
			       const object_generation_t generation)
{
  CMS_ContentInfo *cms = NULL;
  BIO *bio = NULL;
  X509 *x;
  int result = 0;

  assert(rc && wsk && uri && path && prefix);

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

  if (!check_cms(rc, wsk, uri, path, prefix, &cms, &x, NULL, bio, NULL, 0,
		 id_ct_rpkiGhostbusters, sizeof(id_ct_rpkiGhostbusters),
		 1, generation))
    goto error;

#if 0
  /*
   * Here is where we would read the VCard from the bio returned by
   * CMS_verify() so that we could check the VCard.
   */
#endif

  result = 1;

 error:
  BIO_free(bio);
  CMS_ContentInfo_free(cms);

  return result;
}

/**
 * Check whether we already have a particular Ghostbuster record,
 * attempt to fetch it and check issuer's signature if we don't.
 */
static void check_ghostbuster(rcynic_ctx_t *rc,
			      STACK_OF(walk_ctx_t) *wsk,
			      const uri_t *uri,
			      const unsigned char *hash,
			      const size_t hashlen)
{
  walk_ctx_t *w = walk_ctx_stack_head(wsk);
  path_t path;

  assert(rc && wsk && w && uri);

  if (uri_to_filename(rc, uri, &path, &rc->new_authenticated) &&
      !access(path.s, F_OK))
    return;

  logmsg(rc, log_telemetry, "Checking Ghostbuster record %s", uri->s);

  if (check_ghostbuster_1(rc, wsk, uri, &path, &rc->unauthenticated,
			  hash, hashlen, object_generation_current)) {
    install_object(rc, uri, &path, object_generation_current);
    return;
  }

  if (!access(path.s, F_OK))
    log_validation_status(rc, uri, object_rejected, object_generation_current);
  else if (hash)
    log_validation_status(rc, uri, manifest_lists_missing_object, object_generation_current);

  if (check_ghostbuster_1(rc, wsk, uri, &path, &rc->old_authenticated,
			  hash, hashlen, object_generation_backup)) {
    install_object(rc, uri, &path, object_generation_backup);
    return;
  }

  if (!access(path.s, F_OK))
    log_validation_status(rc, uri, object_rejected, object_generation_backup);
  else if (hash && w->manifest_generation == object_generation_backup)
    log_validation_status(rc, uri, manifest_lists_missing_object, object_generation_backup);
}



static void walk_cert(rcynic_ctx_t *, STACK_OF(walk_ctx_t) *);

/**
 * rsync callback for fetching SIA tree.
 */
static void rsync_sia_callback(rcynic_ctx_t *rc,
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

    if ((wsk = walk_ctx_stack_clone(wsk)) == NULL) {
      logmsg(rc, log_sys_err, "walk_ctx_stack_clone() failed, probably memory exhaustion, blundering onwards without forking stack");
      return;
    }

    walk_ctx_stack_pop(wsk);
    task_add(rc, walk_cert, wsk);
    return;

  case rsync_status_failed:
    log_validation_status(rc, uri, rsync_transfer_failed, object_generation_null);
    break;

  case rsync_status_timed_out:
    log_validation_status(rc, uri, rsync_transfer_timed_out, object_generation_null);
    break;

  case rsync_status_skipped:
    log_validation_status(rc, uri, rsync_transfer_skipped, object_generation_null);
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
	log_validation_status(rc, &w->certinfo.uri, sia_manifest_uri_missing, w->certinfo.generation);
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
	check_roa(rc, wsk, &uri, hash, hashlen);
	walk_ctx_loop_next(rc, wsk);
	continue;
      }

      if (endswith(uri.s, ".gbr")) {
	check_ghostbuster(rc, wsk, &uri, hash, hashlen);
	walk_ctx_loop_next(rc, wsk);
	continue;
      }

      if (endswith(uri.s, ".cer")) {
	certinfo_t certinfo;
	X509 *x = check_cert(rc, wsk, &uri, &certinfo, hash, hashlen);
	if (!walk_ctx_stack_push(wsk, x, &certinfo))
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
static int check_ta(rcynic_ctx_t *rc, X509 *x, const uri_t *uri,
		    const path_t *path1, const path_t *path2,
		    const object_generation_t generation)
{
  STACK_OF(walk_ctx_t) *wsk = NULL;
  walk_ctx_t *w = NULL;

  assert(rc && x && uri && path1 && path2);

  if ((wsk = walk_ctx_stack_new()) == NULL) {
    logmsg(rc, log_sys_err, "Couldn't allocate walk context stack");
    return 0;
  }

  if ((w = walk_ctx_stack_push(wsk, x, NULL)) == NULL) {
    logmsg(rc, log_sys_err, "Couldn't push walk context stack");
    walk_ctx_stack_free(wsk);
    return 0;
  }

  if (!check_x509(rc, wsk, uri, x, NULL, generation)) {
    log_validation_status(rc, uri, object_rejected, generation);
    walk_ctx_stack_free(wsk);
    return 1;
  }

  logmsg(rc, log_telemetry, "Copying trust anchor %s to %s", path1->s, path2->s);

  if (!mkdir_maybe(rc, path2) || !cp_ln(rc, path1, path2)) {
    walk_ctx_stack_free(wsk);
    return 0;
  }

  log_validation_status(rc, uri, object_accepted, generation);

  task_add(rc, walk_cert, wsk);

  while (sk_task_t_num(rc->task_queue) > 0 || sk_rsync_ctx_t_num(rc->rsync_queue) > 0) {
    task_run_q(rc);
    rsync_mgr(rc);
  }

  return 1;
}



/**
 * Read a trust anchor from disk and compare with known public key.
 * NB: EVP_PKEY_cmp() returns 1 for match, not 0 like every other
 * xyz_cmp() function in the entire OpenSSL library.  Go figure.
 */
static X509 *read_ta(rcynic_ctx_t *rc,
		     const uri_t *uri,
		     const path_t *path,
		     const EVP_PKEY *pkey,
		     object_generation_t generation)

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
  log_validation_status(rc, uri, object_rejected, generation);
  X509_free(x);
  return NULL;
}



/**
 * Write detailed log of what we've done as an XML file.
 */
static int write_xml_file(const rcynic_ctx_t *rc,
			  const char *xmlfile)
{
  int i, j, use_stdout, ok;
  char hostname[HOSTNAME_MAX];
  mib_counter_t code;
  timestamp_t ts;
  FILE *f = NULL;
  path_t xmltemp;

  if (xmlfile == NULL)
    return 1;
  
  use_stdout = !strcmp(xmlfile, "-");

  logmsg(rc, log_telemetry, "Writing XML summary to %s",
	 (use_stdout ? "standard output" : xmlfile));

  if (use_stdout) {
    f = stdout;
    ok = 1;
  } else if (snprintf(xmltemp.s, sizeof(xmltemp.s), "%s.%u.tmp", xmlfile, (unsigned) getpid()) >= sizeof(xmltemp.s)) {
    logmsg(rc, log_usage_err, "Filename \"%s\" is too long, not writing XML", xmlfile);
    return 0;
  } else {
    ok = (f = fopen(xmltemp.s, "w")) != NULL;
  }

  ok &= gethostname(hostname, sizeof(hostname)) == 0;

  if (ok)
    ok &= fprintf(f, "<?xml version=\"1.0\" ?>\n"
		  "<rcynic-summary date=\"%s\" rcynic-version=\"%s\""
		  " summary-version=\"%d\" reporting-hostname=\"%s\">\n"
		  "  <labels>\n",
		  time_to_string(&ts, NULL),
		  svn_id, XML_SUMMARY_VERSION, hostname) != EOF;

  for (j = 0; ok && j < MIB_COUNTER_T_MAX; ++j)
    ok &= fprintf(f, "    <%s kind=\"%s\">%s</%s>\n",
		  mib_counter_label[j], mib_counter_kind[j],
		  (mib_counter_desc[j]
		   ? mib_counter_desc[j]
		   : X509_verify_cert_error_string(mib_counter_openssl[j])),
		  mib_counter_label[j]) != EOF;

  if (ok)
    ok &= fprintf(f, "  </labels>\n") != EOF;

#if AVL_PARANOIA
  (void) sk_validation_status_t_set_cmp_func(rc->validation_status, validation_status_cmp_creation_order);
  sk_validation_status_t_sort(rc->validation_status);
#endif

  for (i = 0; ok && i < sk_validation_status_t_num(rc->validation_status); i++) {
    validation_status_t *v = sk_validation_status_t_value(rc->validation_status, i);
    assert(v);

    (void) time_to_string(&ts, &v->timestamp);

    for (code = (mib_counter_t) 0; ok && code < MIB_COUNTER_T_MAX; code++) {
      if (validation_status_get_code(v, code)) {
	if (ok)
	  ok &= fprintf(f, "  <validation_status timestamp=\"%s\" status=\"%s\"",
			ts.s, mib_counter_label[code]) != EOF;
	if (ok && (v->generation == object_generation_current ||
		   v->generation == object_generation_backup))
	  ok &= fprintf(f, " generation=\"%s\"",
			object_generation_label[v->generation]) != EOF;
	if (ok)
	  ok &= fprintf(f, ">%s</validation_status>\n", v->uri.s) != EOF;
      }
    }
  }

  for (i = 0; ok && i < sk_rsync_history_t_num(rc->rsync_history); i++) {
    rsync_history_t *h = sk_rsync_history_t_value(rc->rsync_history, i);
    assert(h);

    if (ok)
      ok &= fprintf(f, "  <rsync_history") != EOF;
    if (ok && h->started)
      ok &= fprintf(f, " started=\"%s\"",
		    time_to_string(&ts, &h->started)) != EOF;
    if (ok && h->finished)
      ok &= fprintf(f, " finished=\"%s\"",
		    time_to_string(&ts, &h->finished)) != EOF;
    if (ok && h->status != rsync_status_done)
      ok &= fprintf(f, " error=\"%u\"", (unsigned) h->status) != EOF;
    if (ok)
      ok &= fprintf(f, ">%s%s</rsync_history>\n",
		    h->uri.s, (h->final_slash ? "/" : "")) != EOF;
  }

  if (ok)
    ok &= fprintf(f, "</rcynic-summary>\n") != EOF;

  if (f && !use_stdout)
    ok &= fclose(f) != EOF;

  if (ok && !use_stdout)
    ok &= rename(xmltemp.s, xmlfile) == 0;

  if (!ok)
    logmsg(rc, log_sys_err, "Couldn't write XML summary to %s: %s",
	   (use_stdout ? "standard output" : xmlfile), strerror(errno));

  if (!ok && !use_stdout)
    (void) unlink(xmltemp.s);

  return ok;
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
  int opt_auth = 0, opt_unauth = 0, keep_lockfile = 0;
  char *cfg_file = "rcynic.conf";
  char *lockfile = NULL, *xmlfile = NULL;
  int c, i, j, ret = 1, jitter = 600, lockfd = -1;
  STACK_OF(CONF_VALUE) *cfg_section = NULL;
  CONF *cfg_handle = NULL;
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
  rc.allow_digest_mismatch = 1;
  rc.allow_crl_digest_mismatch = 1;
  rc.allow_object_not_in_manifest = 1;
  rc.allow_nonconformant_name = 1;
  rc.allow_ee_without_signedObject = 1;
  rc.allow_1024_bit_ee_key = 1;
  rc.allow_wrong_cms_si_attributes = 1;
  rc.max_parallel_fetches = 1;
  rc.max_retries = 3;
  rc.retry_wait_min = 30;
  rc.run_rsync = 1;
  rc.rsync_timeout = 300;
  rc.max_select_time = 30;

#define QQ(x,y)   rc.priority[x] = y;
  LOG_LEVELS;
#undef QQ

  if (!set_directory(&rc, &rc.authenticated,   "rcynic-data/authenticated", 0) ||
      !set_directory(&rc, &rc.unauthenticated, "rcynic-data/unauthenticated/", 1))
    goto done;

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  while ((c = getopt(argc, argv, "a:c:l:sej:u:Vx:")) > 0) {
    switch (c) {
    case 'a':
      opt_auth = 1;
      if (!set_directory(&rc, &rc.authenticated, optarg, 0))
	goto done;
      break;
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
    case 'u':
      opt_unauth = 1;
      if (!set_directory(&rc, &rc.unauthenticated, optarg, 1))
	goto done;
      break;
    case 'V':
      puts(svn_id);
      ret = 0;
      goto done;
    case 'x':
      xmlfile = strdup(optarg);
      break;
    default:
      logmsg(&rc, log_usage_err,
	     "usage: %s [-c configfile] [-s] [-e] [-l loglevel] [-j jitter] [-V]",
	     rc.jane);
      goto done;
    }
  }

  if (!(asn1_zero          = s2i_ASN1_INTEGER(NULL, "0x0")) ||
      !(asn1_four_octets   = s2i_ASN1_INTEGER(NULL, "0xFFFFFFFF")) ||
      !(asn1_twenty_octets = s2i_ASN1_INTEGER(NULL, "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")) ||
      !(NID_binary_signing_time = OBJ_create("1.2.840.113549.1.9.16.2.46",
					    "id-aa-binarySigningTime",
					    "id-aa-binarySigningTime"))) {
    logmsg(&rc, log_sys_err, "Couldn't initialize ASN.1 constants!");
    goto done;
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

    if (!opt_auth &&
	!name_cmp(val->name, "authenticated") &&
    	!set_directory(&rc, &rc.authenticated, val->value, 0))
      goto done;

    else if (!opt_unauth &&
	     !name_cmp(val->name, "unauthenticated") &&
	     !set_directory(&rc, &rc.unauthenticated, val->value, 1))
      goto done;

    else if (!name_cmp(val->name, "rsync-timeout") &&
	     !configure_integer(&rc, &rc.rsync_timeout, val->value))
	goto done;

    else if (!name_cmp(val->name, "max-parallel-fetches") &&
	     !configure_integer(&rc, &rc.max_parallel_fetches, val->value))
      goto done;

    else if (!name_cmp(val->name, "max-select-time") &&
	     !configure_unsigned_integer(&rc, &rc.max_select_time, val->value))
      goto done;

    else if (!name_cmp(val->name, "rsync-program"))
      rc.rsync_program = strdup(val->value);

    else if (!name_cmp(val->name, "lockfile"))
      lockfile = strdup(val->value);

    else if (!name_cmp(val->name, "keep-lockfile") &&
	     !configure_boolean(&rc, &keep_lockfile, val->value))
      goto done;

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

    else if (!xmlfile && !name_cmp(val->name, "xml-summary"))
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

    else if (!name_cmp(val->name, "allow-digest-mismatch") &&
	     !configure_boolean(&rc, &rc.allow_digest_mismatch, val->value))
      goto done;

    else if (!name_cmp(val->name, "allow-crl-digest-mismatch") &&
	     !configure_boolean(&rc, &rc.allow_crl_digest_mismatch, val->value))
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

    else if (!name_cmp(val->name, "allow-nonconformant-name") &&
	     !configure_boolean(&rc, &rc.allow_nonconformant_name, val->value))
      goto done;

    else if (!name_cmp(val->name, "allow-ee-without-signedObject") &&
	     !configure_boolean(&rc, &rc.allow_ee_without_signedObject, val->value))
      goto done;

    else if (!name_cmp(val->name, "allow-1024-bit-ee-key") &&
	     !configure_boolean(&rc, &rc.allow_1024_bit_ee_key, val->value))
      goto done;

    else if (!name_cmp(val->name, "allow-wrong-cms-si-attributes") &&
	     !configure_boolean(&rc, &rc.allow_wrong_cms_si_attributes, val->value))
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

  if ((rc.rsync_history = sk_rsync_history_t_new(rsync_history_cmp)) == NULL) {
    logmsg(&rc, log_sys_err, "Couldn't allocate rsync_history stack");
    goto done;
  }

  if ((rc.validation_status = sk_validation_status_t_new_null()) == NULL) {
    logmsg(&rc, log_sys_err, "Couldn't allocate validation_status stack");
    goto done;
  }

#if AVL_PARANOIA
  (void) sk_validation_status_t_set_cmp_func(rc.validation_status, validation_status_cmp_uri);
#endif

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
      filename_to_uri(&uri, path1.s);
      if ((x = read_cert(&path1, NULL)) == NULL) {
	log_validation_status(&rc, &uri, unreadable_trust_anchor, generation);
	continue;
      }
      hash = X509_subject_name_hash(x);
      for (j = 0; j < INT_MAX; j++) {
	if (snprintf(path2.s, sizeof(path2.s), "%s%lx.%d.cer",
		     rc.new_authenticated.s, hash, j) >= sizeof(path2.s)) {
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
	filename_to_uri(&uri, fn);
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
      if (endswith(uri.s, "/")) {
	log_validation_status(&rc, &uri, malformed_tal_uri, object_generation_null);
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

    if (!check_ta(&rc, x, &uri, &path1, &path2, generation))
      goto done;
  }

  if (!finalize_directories(&rc))
    goto done;

  if (prune && rc.run_rsync &&
      !prune_unauthenticated(&rc, &rc.unauthenticated,
			     strlen(rc.unauthenticated.s))) {
    logmsg(&rc, log_sys_err, "Trouble pruning old unauthenticated data");
    goto done;
  }

  if (!write_xml_file(&rc, xmlfile))
    goto done;

  ret = 0;

 done:
  log_openssl_errors(&rc);

  /*
   * Do NOT free cfg_section, NCONF_free() takes care of that
   */
  sk_validation_status_t_pop_free(rc.validation_status, validation_status_t_free);
  sk_rsync_history_t_pop_free(rc.rsync_history, rsync_history_t_free);
  validation_status_t_free(rc.validation_status_in_waiting);
  X509_STORE_free(rc.x509_store);
  NCONF_free(cfg_handle);
  CONF_modules_free();
  BIO_free(bio);
  EVP_cleanup();
  ERR_free_strings();
  if (rc.rsync_program)
    free(rc.rsync_program);
  if (lockfile && lockfd >= 0 && !keep_lockfile)
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
