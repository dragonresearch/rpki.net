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

#ifndef FILENAME_MAX
#define	FILENAME_MAX	1024
#endif

#define	SIZEOF_RSYNC	(sizeof("rsync://") - 1)

/**
 * Maximum length of an URI.
 */
#define	URI_MAX		(FILENAME_MAX + SIZEOF_RSYNC)

/**
 * Maximum number of times we try to kill an inferior process before
 * giving up.
 */
#define	KILL_MAX	10

#ifndef	HOST_NAME_MAX
#define	HOST_NAME_MAX	256
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
  QV(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)		\
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

#define MIB_COUNTERS							 \
  QQ(backup_cert_accepted,		"Backup certificates accepted")  \
  QQ(backup_cert_rejected,		"Backup certificates rejected")  \
  QQ(backup_crl_accepted,		"Backup CRLs accepted")		 \
  QQ(backup_crl_rejected,		"Backup CRLs rejected")		 \
  QQ(current_cert_accepted,		"Current certificates accepted") \
  QQ(current_cert_rejected,		"Current certificates rejected") \
  QQ(current_crl_accepted,		"Current CRLs accepted")	 \
  QQ(current_crl_rejected,		"Current CRLs rejected")	 \
  QQ(current_manifest_accepted,		"Current Manifests accepted")    \
  QQ(current_manifest_rejected,		"Current Manifests rejected")    \
  QQ(backup_manifest_accepted,		"Backup Manifests accepted")     \
  QQ(backup_manifest_rejected,		"Backup Manifests rejected")     \
  QQ(rsync_failed,			"rsync transfers failed")	 \
  QQ(rsync_succeeded,			"rsync transfers succeeded")	 \
  QQ(rsync_timed_out,			"rsync transfers timed out")	 \
  QQ(stale_crl,				"Stale CRLs")			 \
  QQ(malformed_sia,			"Malformed SIA extensions")	 \
  QQ(sia_missing,			"SIA extensions missing")	 \
  QQ(aia_missing,			"AIA extensions missing")	 \
  QQ(crldp_missing,			"CRLDP extensions missing")	 \
  QQ(aia_mismatch,			"Mismatched AIA extensions")	 \
  QQ(unknown_verify_error,		"Unknown OpenSSL verify error")	 \
  QQ(current_cert_recheck,		"Certificates rechecked")	 \
  QQ(manifest_invalid_ee,		"Invalid manifest certificates") \
  QQ(manifest_invalid_cms,		"Manifest validation failures")  \
  QQ(manifest_decode_error,		"Manifest decode errors")        \
  QQ(stale_manifest,			"Stale manifests")               \
  QQ(manifest_not_yet_valid,		"Manifests not yet valid")       \
  QQ(manifest_bad_econtenttype,		"Bad manifest eContentType")     \
  QQ(manifest_missing_signer,		"Missing manifest signers")      \
  QQ(certificate_digest_mismatch,	"Certificate digest mismatches") \
  QQ(crl_digest_mismatch,		"CRL digest mismatches")	 \
  QQ(crl_not_in_manifest,               "CRL not listed in manifest")    \
  QQ(roa_invalid_ee,			"Invalid ROA certificates")	 \
  QQ(roa_invalid_cms,			"ROA validation failures")	 \
  QQ(roa_decode_error,			"ROA decode errors")		 \
  QQ(roa_bad_econtenttype,		"Bad ROA eContentType")		 \
  QQ(roa_missing_signer,		"Missing ROA signers")		 \
  QQ(roa_digest_mismatch,		"ROA digest mismatches")	 \
  QQ(current_roa_accepted,		"Current ROAs accepted")	 \
  QQ(current_roa_rejected,		"Current ROAs rejected")	 \
  QQ(backup_roa_accepted,		"Backup ROAs accepted")		 \
  QQ(backup_roa_rejected,		"Backup ROAs rejected")		 \
  QQ(malformed_roa_addressfamily,       "Malformed ROA addressFamilys")	 \
  QQ(manifest_wrong_version,            "Wrong manifest versions")	 \
  QQ(roa_wrong_version,			"Wrong ROA versions")		 \
  MIB_COUNTERS_FROM_OPENSSL

#define QV(x) QQ(mib_openssl_##x, 0)

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
 * Per-host MIB counter object.
 * hostname[] must be first element.
 */
typedef struct host_counter {
  char hostname[URI_MAX];
  unsigned long counters[MIB_COUNTER_T_MAX];
} host_mib_counter_t;

/**
 * Structure to hold data parsed out of a certificate.
 */
typedef struct certinfo {
  int ca, ta;
  char uri[URI_MAX], sia[URI_MAX], aia[URI_MAX], crldp[URI_MAX], manifest[URI_MAX];
} certinfo_t;

/**
 * Program context that would otherwise be a mess of global variables.
 */
typedef struct rcynic_ctx {
  char *authenticated, *old_authenticated, *unauthenticated;
  char *jane, *rsync_program;
  STACK *rsync_cache, *host_counters, *backup_cache;
  int indent, use_syslog, allow_stale_crl, allow_stale_manifest, use_links;
  int require_crl_in_manifest, rsync_timeout, priority[LOG_LEVEL_T_MAX];
  log_level_t log_level;
  X509_STORE *x509_store;
} rcynic_ctx_t;

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
  const certinfo_t *subj;
} rcynic_x509_store_ctx_t;

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

/** 2.16.840.1.101.3.4.2.1 */
static const unsigned char id_sha256[] =
  {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};

/**
 * RPKI certificate policy OID in form suitable for use with
 * X509_VERIFY_PARAM_add0_policy().
 */
static const char rpki_policy_oid[] = "1.3.6.1.5.5.7.14.2";



/*
 * ASN.1 templates.  Not sure that ASN1_EXP_OPT() is the right macro
 * for these defaulted "version" fields, but it's what the examples
 * for this construction use.  Probably doesn't matter since this
 * program only decodes manifests, never encodes them.
 */

typedef struct FileAndHash_st {
  ASN1_IA5STRING *file;
  ASN1_BIT_STRING *hash;
} FileAndHash;

DECLARE_STACK_OF(FileAndHash)

ASN1_SEQUENCE(FileAndHash) = {
  ASN1_SIMPLE(FileAndHash, file, ASN1_IA5STRING),
  ASN1_SIMPLE(FileAndHash, hash, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(FileAndHash)

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

DECLARE_ASN1_FUNCTIONS(FileAndHash)
DECLARE_ASN1_FUNCTIONS(Manifest)

IMPLEMENT_ASN1_FUNCTIONS(FileAndHash)
IMPLEMENT_ASN1_FUNCTIONS(Manifest)

#define sk_FileAndHash_new(st)			SKM_sk_new(FileAndHash, (st))
#define sk_FileAndHash_new_null()		SKM_sk_new_null(FileAndHash)
#define sk_FileAndHash_free(st)			SKM_sk_free(FileAndHash, (st))
#define sk_FileAndHash_num(st)			SKM_sk_num(FileAndHash, (st))
#define sk_FileAndHash_value(st, i)		SKM_sk_value(FileAndHash, (st), (i))
#define sk_FileAndHash_set(st, i, val)		SKM_sk_set(FileAndHash, (st), (i), (val))
#define sk_FileAndHash_zero(st)			SKM_sk_zero(FileAndHash, (st))
#define sk_FileAndHash_push(st, val)		SKM_sk_push(FileAndHash, (st), (val))
#define sk_FileAndHash_unshift(st, val)		SKM_sk_unshift(FileAndHash, (st), (val))
#define sk_FileAndHash_find(st, val)		SKM_sk_find(FileAndHash, (st), (val))
#define sk_FileAndHash_find_ex(st, val)		SKM_sk_find_ex(FileAndHash, (st), (val))
#define sk_FileAndHash_delete(st, i)		SKM_sk_delete(FileAndHash, (st), (i))
#define sk_FileAndHash_delete_ptr(st, ptr)	SKM_sk_delete_ptr(FileAndHash, (st), (ptr))
#define sk_FileAndHash_insert(st, val, i)	SKM_sk_insert(FileAndHash, (st), (val), (i))
#define sk_FileAndHash_set_cmp_func(st, cmp)	SKM_sk_set_cmp_func(FileAndHash, (st), (cmp))
#define sk_FileAndHash_dup(st)			SKM_sk_dup(FileAndHash, st)
#define sk_FileAndHash_pop_free(st, free_func)	SKM_sk_pop_free(FileAndHash, (st), (free_func))
#define sk_FileAndHash_shift(st)		SKM_sk_shift(FileAndHash, (st))
#define sk_FileAndHash_pop(st)			SKM_sk_pop(FileAndHash, (st))
#define sk_FileAndHash_sort(st)			SKM_sk_sort(FileAndHash, (st))
#define sk_FileAndHash_is_sorted(st)		SKM_sk_is_sorted(FileAndHash, (st))

typedef struct ROAIPAddress_st {
  ASN1_BIT_STRING *IPAddress;
  ASN1_INTEGER *maxLength;
} ROAIPAddress;

DECLARE_STACK_OF(ROAIPAddress)

ASN1_SEQUENCE(ROAIPAddress) = {
  ASN1_SIMPLE(ROAIPAddress, IPAddress, ASN1_BIT_STRING),
  ASN1_EXP_OPT(ROAIPAddress, maxLength, ASN1_INTEGER, 0)
} ASN1_SEQUENCE_END(ROAIPAddress)

typedef struct ROAIPAddressFamily_st {
  ASN1_OCTET_STRING *addressFamily;
  STACK_OF(ROAIPAddress) *addresses;
} ROAIPAddressFamily;

DECLARE_STACK_OF(ROAIPAddressFamily)

ASN1_SEQUENCE(ROAIPAddressFamily) = {
  ASN1_SIMPLE(ROAIPAddressFamily, addressFamily, ASN1_OCTET_STRING),
  ASN1_SEQUENCE_OF(ROAIPAddressFamily, addresses, ROAIPAddress)
} ASN1_SEQUENCE_END(ROAIPAddressFamily)

typedef struct ROA_st {
  ASN1_INTEGER *version, *asID;
  STACK_OF(ROAIPAddressFamily) *ipAddrBlocks;
} ROA;

ASN1_SEQUENCE(ROA) = {
  ASN1_EXP_OPT(ROA, version, ASN1_INTEGER, 0),
  ASN1_SIMPLE(ROA, asID, ASN1_INTEGER),
  ASN1_SEQUENCE_OF(ROA, ipAddrBlocks, ROAIPAddressFamily)
} ASN1_SEQUENCE_END(ROA)

DECLARE_ASN1_FUNCTIONS(ROAIPAddress)
DECLARE_ASN1_FUNCTIONS(ROAIPAddressFamily)
DECLARE_ASN1_FUNCTIONS(ROA)

IMPLEMENT_ASN1_FUNCTIONS(ROAIPAddress)
IMPLEMENT_ASN1_FUNCTIONS(ROAIPAddressFamily)
IMPLEMENT_ASN1_FUNCTIONS(ROA)

#define sk_ROAIPAddress_new(st)				SKM_sk_new(ROAIPAddress, (st))
#define sk_ROAIPAddress_new_null()			SKM_sk_new_null(ROAIPAddress)
#define sk_ROAIPAddress_free(st)			SKM_sk_free(ROAIPAddress, (st))
#define sk_ROAIPAddress_num(st)				SKM_sk_num(ROAIPAddress, (st))
#define sk_ROAIPAddress_value(st, i)			SKM_sk_value(ROAIPAddress, (st), (i))
#define sk_ROAIPAddress_set(st, i, val)			SKM_sk_set(ROAIPAddress, (st), (i), (val))
#define sk_ROAIPAddress_zero(st)			SKM_sk_zero(ROAIPAddress, (st))
#define sk_ROAIPAddress_push(st, val)			SKM_sk_push(ROAIPAddress, (st), (val))
#define sk_ROAIPAddress_unshift(st, val)		SKM_sk_unshift(ROAIPAddress, (st), (val))
#define sk_ROAIPAddress_find(st, val)			SKM_sk_find(ROAIPAddress, (st), (val))
#define sk_ROAIPAddress_find_ex(st, val)		SKM_sk_find_ex(ROAIPAddress, (st), (val))
#define sk_ROAIPAddress_delete(st, i)			SKM_sk_delete(ROAIPAddress, (st), (i))
#define sk_ROAIPAddress_delete_ptr(st, ptr)		SKM_sk_delete_ptr(ROAIPAddress, (st), (ptr))
#define sk_ROAIPAddress_insert(st, val, i)		SKM_sk_insert(ROAIPAddress, (st), (val), (i))
#define sk_ROAIPAddress_set_cmp_func(st, cmp)		SKM_sk_set_cmp_func(ROAIPAddress, (st), (cmp))
#define sk_ROAIPAddress_dup(st)				SKM_sk_dup(ROAIPAddress, st)
#define sk_ROAIPAddress_pop_free(st, free_func)		SKM_sk_pop_free(ROAIPAddress, (st), (free_func))
#define sk_ROAIPAddress_shift(st)			SKM_sk_shift(ROAIPAddress, (st))
#define sk_ROAIPAddress_pop(st)				SKM_sk_pop(ROAIPAddress, (st))
#define sk_ROAIPAddress_sort(st)			SKM_sk_sort(ROAIPAddress, (st))
#define sk_ROAIPAddress_is_sorted(st)			SKM_sk_is_sorted(ROAIPAddress, (st))

#define sk_ROAIPAddressFamily_new(st)			SKM_sk_new(ROAIPAddressFamily, (st))
#define sk_ROAIPAddressFamily_new_null()		SKM_sk_new_null(ROAIPAddressFamily)
#define sk_ROAIPAddressFamily_free(st)			SKM_sk_free(ROAIPAddressFamily, (st))
#define sk_ROAIPAddressFamily_num(st)			SKM_sk_num(ROAIPAddressFamily, (st))
#define sk_ROAIPAddressFamily_value(st, i)		SKM_sk_value(ROAIPAddressFamily, (st), (i))
#define sk_ROAIPAddressFamily_set(st, i, val)		SKM_sk_set(ROAIPAddressFamily, (st), (i), (val))
#define sk_ROAIPAddressFamily_zero(st)			SKM_sk_zero(ROAIPAddressFamily, (st))
#define sk_ROAIPAddressFamily_push(st, val)		SKM_sk_push(ROAIPAddressFamily, (st), (val))
#define sk_ROAIPAddressFamily_unshift(st, val)		SKM_sk_unshift(ROAIPAddressFamily, (st), (val))
#define sk_ROAIPAddressFamily_find(st, val)		SKM_sk_find(ROAIPAddressFamily, (st), (val))
#define sk_ROAIPAddressFamily_find_ex(st, val)		SKM_sk_find_ex(ROAIPAddressFamily, (st), (val))
#define sk_ROAIPAddressFamily_delete(st, i)		SKM_sk_delete(ROAIPAddressFamily, (st), (i))
#define sk_ROAIPAddressFamily_delete_ptr(st, ptr)	SKM_sk_delete_ptr(ROAIPAddressFamily, (st), (ptr))
#define sk_ROAIPAddressFamily_insert(st, val, i)	SKM_sk_insert(ROAIPAddressFamily, (st), (val), (i))
#define sk_ROAIPAddressFamily_set_cmp_func(st, cmp)	SKM_sk_set_cmp_func(ROAIPAddressFamily, (st), (cmp))
#define sk_ROAIPAddressFamily_dup(st)			SKM_sk_dup(ROAIPAddressFamily, st)
#define sk_ROAIPAddressFamily_pop_free(st, free_func)	SKM_sk_pop_free(ROAIPAddressFamily, (st), (free_func))
#define sk_ROAIPAddressFamily_shift(st)			SKM_sk_shift(ROAIPAddressFamily, (st))
#define sk_ROAIPAddressFamily_pop(st)			SKM_sk_pop(ROAIPAddressFamily, (st))
#define sk_ROAIPAddressFamily_sort(st)			SKM_sk_sort(ROAIPAddressFamily, (st))
#define sk_ROAIPAddressFamily_is_sorted(st)		SKM_sk_is_sorted(ROAIPAddressFamily, (st))



/**
 * Logging.
 */
static void logmsg(const rcynic_ctx_t *rc, 
		   const log_level_t level, 
		   const char *fmt, ...)
{
  char tad[sizeof("00:00:00")+1];
  time_t tad_time;
  va_list ap;

  assert(rc && fmt);

  if (rc->log_level < level)
    return;

  va_start(ap, fmt);

  if (rc->use_syslog) {
    vsyslog(rc->priority[level], fmt, ap);
  } else {
    time(&tad_time);
    strftime(tad, sizeof(tad), "%H:%M:%S", localtime(&tad_time));
    fprintf(stderr, "%s: ", tad);
    if (rc->jane)
      fprintf(stderr, "%s: ", rc->jane);
    if (rc->indent)
      fprintf(stderr, "%*s", rc->indent, " ");
    vfprintf(stderr, fmt, ap);
    putc('\n', stderr);
  }

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
      logmsg(rc, log_sys_err, "OpenSSL error %s:%d: %s", file, line, error, data);
    else
      logmsg(rc, log_sys_err, "OpenSSL error %s:%d", file, line, error);
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

/**
 * strdup() a string and push it onto a stack.
 */
static int sk_push_strdup(STACK *sk, const char *str)
{
  char *s = strdup(str);

  if (s && sk_push(sk, s))
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
  return uri && !strncmp(uri, "rsync://", SIZEOF_RSYNC);
}

/**
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

/**
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

/**
 * Copy a file
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

/**
 * Link a file
 */
static int ln(const char *source, const char *target)
{
  unlink(target);
  return link(source, target) == 0;
}

/**
 * Install an object.  It'd be nice if we could just use link(), but
 * that would require us to trust rsync never to do anything bad.  For
 * now we just copy in the simplest way possible.  Come back to this
 * if profiling shows a hotspot here.
 *
 * Well, ok, profiling didn't show an issue, but inode exhaustion did.
 * So we now make copy vs link a configuration choice.
 */
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

  if (rc->use_links ? !ln(source, target) : !cp(source, target)) {
    logmsg(rc, log_sys_err, "Couldn't %s %s to %s",
	   (rc->use_links ? "link" : "copy"), source, target);
    return 0;
  }

  logmsg(rc, log_telemetry, "Accepted%*s%s", space, " ", uri);
  return 1;
}

/**
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

/**
 * Iterator over URIs in our copy of a SIA collection.
 * *iterator should be zero when first called.
 */
static FileAndHash *next_uri(const rcynic_ctx_t *rc, 
			     const char *base_uri,
			     const char *prefix,
			     char *uri,
			     const size_t urilen,
			     const Manifest *manifest,
			     int *iterator)
{
  FileAndHash *fah = NULL;

  assert(base_uri && prefix && uri && manifest && iterator);

  while ((fah = sk_FileAndHash_value(manifest->fileList, *iterator)) != NULL) {
    ++*iterator;
    if (strlen(base_uri) + strlen(fah->file->data) >= urilen) {
      logmsg(rc, log_data_err, "URI %s%s too long, skipping", base_uri, fah->file->data);
      continue;
    }
    strcpy(uri, base_uri);
    strcat(uri, fah->file->data);
    return fah;
  }

  *iterator = 0;
  return NULL;
}

/**
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

/**
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
  return ret;
}



/**
 * Maintain a cache of URIs we've already fetched.
 */
static int rsync_cached(const rcynic_ctx_t *rc,
			const char *uri)
{
  char *s, buffer[URI_MAX];

  assert(rc && rc->rsync_cache);
  strcpy(buffer, uri);
  if ((s = strrchr(buffer, '/')) != NULL && s[1] == '\0')
    *s = '\0';
  while (sk_find(rc->rsync_cache, buffer) < 0) {
    if ((s = strrchr(buffer, '/')) == NULL)
      return 0;
    *s = '\0';
  }
  return 1;
}

/**
 * Run rsync.  This is fairly nasty, because we need to:
 *
 * @li Construct the argument list for rsync;
 *
 * @li Run rsync in a child process;
 *
 * @li Sit listening to rsync's output, logging whatever we get;
 *
 * @li Impose an optional time limit on rsync's execution time
 *
 * @li Clean up from (b), (c), and (d); and
 *
 * @li Keep track of which URIs we've already fetched, so we don't
 *     have to do it again.
 *
 * Taken all together, this is pretty icky.  Breaking it into separate
 * functions wouldn't help much.  Don't read this on a full stomach.
 */
static int rsync(const rcynic_ctx_t *rc,
		 const char * const *args,
		 const char *uri)
{
  static const char *rsync_cmd[] = {
    "rsync", "--update", "--times", "--copy-links", "--itemize-changes", NULL
  };

  const char *argv[100];
  char *s, *b, buffer[URI_MAX * 4], path[FILENAME_MAX];
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

  assert(strlen(uri) > SIZEOF_RSYNC);
  if (rsync_cached(rc, uri + SIZEOF_RSYNC)) {
    logmsg(rc, log_verbose, "rsync cache hit for %s", uri);
    return 1;
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
      n += i;
      assert(n < sizeof(buffer));
      buffer[n] = '\0';
      for (b = buffer; (s = strchr(b, '\n')) != NULL; b = s) {
	*s++ = '\0';
	logmsg(rc, log_telemetry, "%s", b);
      }
      i = strlen(b);
      assert(i < sizeof(buffer) && b + i < buffer + sizeof(buffer));
      if (b == buffer && i == sizeof(buffer) - 1) {
	logmsg(rc, log_telemetry, "%s\\", b);
	i = 0;
      }
      if (i > 0) {
	memmove(buffer, b, i);
      }
    }
    if (n == 0 || (n < 0 && errno != EAGAIN))
      break;
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

  assert(strlen(uri) > SIZEOF_RSYNC);
  strcpy(buffer, uri + SIZEOF_RSYNC);
  if ((s = strrchr(buffer, '/')) != NULL && s[1] == '\0')
    *s = '\0';
  if (!sk_push_strdup(rc->rsync_cache, buffer))
    logmsg(rc, log_sys_err, "Couldn't cache URI %s, blundering onward", uri);

  return ret;
}

/**
 * rsync a single file (CRL, manifest, ROA, whatever).
 */
static int rsync_file(const rcynic_ctx_t *rc, const char *uri)
{
  return rsync(rc, NULL, uri);
}

/**
 * rsync an SIA collection.
 */
static int rsync_sia(const rcynic_ctx_t *rc, const char *uri)
{
  static const char * const rsync_args[] = { "--recursive", "--delete", NULL };
  return rsync(rc, rsync_args, uri);
}



/**
 * Clean up old stuff from previous rsync runs.  --delete doesn't help
 * if the URI changes and we never visit the old URI again.
 */
static int prune_unauthenticated(const rcynic_ctx_t *rc,
				 const char *name,
				 const size_t baselen)
{
  char path[FILENAME_MAX];
  struct dirent *d;
  size_t len;
  DIR *dir;
  int need_slash;

  assert(rc && name && baselen > 0);
  len = strlen(name);
  assert(len >= baselen && len < sizeof(path));
  need_slash = name[len - 1] != '/';

  if (rsync_cached(rc, name + baselen)) {
    logmsg(rc, log_debug, "prune: cache hit for %s, not cleaning", name);
    return 1;
  }

  if (rmdir(name) == 0) {
    logmsg(rc, log_debug, "prune: removed %s", name);
    return 1;
  }

  switch (errno) {
  case ENOENT:
    logmsg(rc, log_debug, "prune: nonexistant %s", name);
    return 1;
  case ENOTEMPTY:
    break;
  default:
    logmsg(rc, log_debug, "prune: other error %s: %s", name, strerror(errno));
    return 0;
  }

  if ((dir = opendir(name)) == NULL)
    return 0;

  while ((d = readdir(dir)) != NULL) {
    if (d->d_name[0] == '.' && (d->d_name[1] == '\0' || (d->d_name[1] == '.' && d->d_name[2] == '\0')))
      continue;
    if (len + strlen(d->d_name) + need_slash >= sizeof(path)) {
      logmsg(rc, log_debug, "prune: %s%s%s too long", name, (need_slash ? "/" : ""), d->d_name);
      goto done;
    }
    strcpy(path, name);
    if (need_slash)
      strcat(path, "/");
    strcat(path, d->d_name);
    switch (d->d_type) {
    case DT_DIR:
      if (!prune_unauthenticated(rc, path, baselen))
	goto done;
      continue;
    default:
      if (rsync_cached(rc, path + baselen)) {
	logmsg(rc, log_debug, "prune: cache hit %s", path);
	continue;
      }
      if (unlink(path) < 0) {
	logmsg(rc, log_debug, "prune: removing %s failed: %s", path, strerror(errno));
	goto done;
      }
      logmsg(rc, log_debug, "prune: removed %s", path);
      continue;
    }
  }

  if (rmdir(name) < 0 && errno != ENOTEMPTY)
    logmsg(rc, log_debug, "prune: couldn't remove %s: %s", name, strerror(errno));

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
static void *read_file_with_hash(const char *filename,
				 const ASN1_ITEM *it,
				 const EVP_MD *md,
				 unsigned char *hash,
				 const size_t hashlen)
{
  void *result = NULL;
  BIO *b;

  if ((b = BIO_new_file(filename, "rb")) == NULL)
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
    memset(hash, 0, hashlen);
    BIO_gets(b, hash, hashlen);
  }    

 error:
  BIO_free_all(b);
  return result;
}

/**
 * Read and hash a certificate.
 */
static X509 *read_cert(const char *filename, unsigned char *hash, const size_t hashlen)
{
  return read_file_with_hash(filename, ASN1_ITEM_rptr(X509), NULL, hash, hashlen);
}

/**
 * Read and hash a CRL.
 */
static X509_CRL *read_crl(const char *filename, unsigned char *hash, const size_t hashlen)
{
  return read_file_with_hash(filename, ASN1_ITEM_rptr(X509_CRL), NULL, hash, hashlen);
}

/**
 * Read and hash a CMS message.
 */
static CMS_ContentInfo *read_cms(const char *filename, unsigned char *hash, const size_t hashlen)
{
  return read_file_with_hash(filename, ASN1_ITEM_rptr(CMS_ContentInfo), NULL, hash, hashlen);
}



/**
 * Extract CRLDP data from a certificate.
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

/**
 * Extract SIA or AIA data from a certificate.
 */
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
    if (!oid_cmp(a->method, oid, oidlen) &&
	is_rsync((char *) a->location->d.uniformResourceIdentifier->data) &&
	urilen > a->location->d.uniformResourceIdentifier->length) {
      strcpy(uri, (char *) a->location->d.uniformResourceIdentifier->data);
      return;
    }
  }
}

/**
 * Parse interesting stuff from a certificate.
 */
static void parse_cert(X509 *x, certinfo_t *c, const char *uri)
{
  STACK_OF(DIST_POINT) *crldp;
  AUTHORITY_INFO_ACCESS *xia;

  assert(x != NULL && c != NULL && uri != NULL);
  memset(c, 0, sizeof(*c));

  c->ca = X509_check_ca(x) == 1;

  assert(strlen(uri) < sizeof(c->uri));
  strcpy(c->uri, uri);

  if ((xia = X509_get_ext_d2i(x, NID_info_access, NULL, NULL)) != NULL) {
    extract_access_uri(xia, id_ad_caIssuers, sizeof(id_ad_caIssuers), c->aia, sizeof(c->aia));
    sk_ACCESS_DESCRIPTION_pop_free(xia, ACCESS_DESCRIPTION_free);
  }

  if ((xia = X509_get_ext_d2i(x, NID_sinfo_access, NULL, NULL)) != NULL) {
    extract_access_uri(xia, id_ad_caRepository, sizeof(id_ad_caRepository), c->sia, sizeof(c->sia));
    extract_access_uri(xia, id_ad_rpkiManifest, sizeof(id_ad_rpkiManifest), c->manifest, sizeof(c->manifest));
    sk_ACCESS_DESCRIPTION_pop_free(xia, ACCESS_DESCRIPTION_free);
  }

  if ((crldp = X509_get_ext_d2i(x, NID_crl_distribution_points,
				NULL, NULL)) != NULL) {
    extract_crldp_uri(crldp, c->crldp, sizeof(c->crldp));
    sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
  }
}



/**
 * Attempt to read and check one CRL from disk.
 */

static X509_CRL *check_crl_1(const rcynic_ctx_t *rc,
			     const char *uri,
			     char *path, const int pathlen,
			     const char *prefix,
			     X509 *issuer,
			     const unsigned char *hash,
			     const size_t hashlen)
{
  unsigned char hashbuf[EVP_MAX_MD_SIZE];
  X509_CRL *crl = NULL;
  EVP_PKEY *pkey;
  int ret;

  assert(uri && path && issuer && hashlen <= sizeof(hashbuf));

  if (!uri_to_filename(uri, path, pathlen, prefix))
    goto punt;

  if (hash)
    crl = read_crl(path, hashbuf, sizeof(hashbuf));
  else
    crl = read_crl(path, NULL, 0);

  if (!crl)
    goto punt;

  if (hash && memcmp(hashbuf, hash, hashlen)) {
    logmsg(rc, log_data_err, "Manifest digest mismatch for CRL %s", uri);
    mib_increment(rc, uri, crl_digest_mismatch);
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
			   const char *uri,
			   X509 *issuer,
			   const unsigned char *hash,
			   const size_t hashlen)
{
  char path[FILENAME_MAX];
  X509_CRL *crl;

  if (uri_to_filename(uri, path, sizeof(path), rc->authenticated)) {
    unsigned char hashbuf[EVP_MAX_MD_SIZE];
    if (hash)
      crl = read_crl(path, hashbuf, sizeof(hashbuf));
    else
      crl = read_crl(path, NULL, 0);
    if (crl)
      return crl;
  }

  logmsg(rc, log_telemetry, "Checking CRL %s", uri);

  rsync_file(rc, uri);

  if ((crl = check_crl_1(rc, uri, path, sizeof(path), rc->unauthenticated,
			 issuer, hash, hashlen))) {
    install_object(rc, uri, path, 5);
    mib_increment(rc, uri, current_crl_accepted);
    return crl;
  } else if (!access(path, F_OK)) {
    mib_increment(rc, uri, current_crl_rejected);
  }

  if ((crl = check_crl_1(rc, uri, path, sizeof(path), rc->old_authenticated,
			 issuer, hash, hashlen))) {
    install_object(rc, uri, path, 5);
    mib_increment(rc, uri, backup_crl_accepted);
    return crl;
  } else if (!access(path, F_OK)) {
    mib_increment(rc, uri, backup_crl_rejected);
  }

  return NULL;
}



/**
 * Validation callback function for use with x509_verify_cert().
 */
static int check_x509_cb(int ok, X509_STORE_CTX *ctx)
{
  rcynic_x509_store_ctx_t *rctx = (rcynic_x509_store_ctx_t *) ctx;

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
     * This may not be an error at all.  CRLs don't really "expire",
     * although the signatures over them do.  What OpenSSL really
     * means by this error is just "it's now later than this source
     * said it intended to publish a new CRL.  Unclear whether this
     * should be an error; current theory is that it should not be.
     */
    logmsg(rctx->rc, log_data_err, "Stale CRL %s while checking %s",
	   rctx->subj->crldp, rctx->subj->uri);
    mib_increment(rctx->rc, rctx->subj->uri, stale_crl);
    if (rctx->rc->allow_stale_crl)
      ok = 1;
    return ok;

#define QV(x)							\
  case x:							\
    mib_increment(rctx->rc, rctx->subj->uri, mib_openssl_##x);	\
    break;

    /*
     * Increment counters for all known OpenSSL verify errors except
     * the ones we handle explicitly above.
     */
    MIB_COUNTERS_FROM_OPENSSL;
#undef	QV

  default:
    mib_increment(rctx->rc, rctx->subj->uri, unknown_verify_error);
    break;
  }

  if (!ok)
    logmsg(rctx->rc, log_data_err,
	   "Callback depth %d error %d cert %p issuer %p crl %p: %s",
	   ctx->error_depth, ctx->error, ctx->current_cert,
	   ctx->current_issuer, ctx->current_crl,
	   X509_verify_cert_error_string(ctx->error));
  return ok;
}

/**
 * Check crypto aspects of a certificate, including policy checks
 * and RFC 3779 path validation.
 */
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

  if ((crl = check_crl(rc, subj->crldp, issuer, NULL, 0)) == NULL) {
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
  X509_STORE_CTX_set_verify_cb(&rctx.ctx, check_x509_cb);

  X509_VERIFY_PARAM_set_flags(rctx.ctx.param,
			      X509_V_FLAG_CRL_CHECK |
			      X509_V_FLAG_POLICY_CHECK |
			      X509_V_FLAG_EXPLICIT_POLICY |
			      X509_V_FLAG_X509_STRICT);

  X509_VERIFY_PARAM_add0_policy(rctx.ctx.param, OBJ_txt2obj(rpki_policy_oid, 1));

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

/**
 * Check a certificate for conformance to the RPKI certificate profile.
 */
static X509 *check_cert_1(const rcynic_ctx_t *rc,
			  const char *uri,
			  char *path,
			  const int pathlen,
			  const char *prefix,
			  STACK_OF(X509) *certs,
			  const certinfo_t *issuer,
			  certinfo_t *subj,
			  const unsigned char *hash,
			  const size_t hashlen)
{
  unsigned char hashbuf[EVP_MAX_MD_SIZE];
  X509 *x = NULL;

  assert(uri && path && certs && issuer && subj);

  if (!uri_to_filename(uri, path, pathlen, prefix)) {
    logmsg(rc, log_data_err, "Can't convert URI %s to filename", uri);
    return NULL;
  }

  if (access(path, R_OK))
    return NULL;

  if (hash)
    x = read_cert(path, hashbuf, sizeof(hashbuf));
  else
    x = read_cert(path, NULL, 0);

  if (!x) {
    logmsg(rc, log_sys_err, "Can't read certificate %s", path);
    goto punt;
  }

  if (hash && memcmp(hashbuf, hash, hashlen)) {
    logmsg(rc, log_data_err, "Manifest digest mismatch for certificate %s", uri);
    mib_increment(rc, uri, certificate_digest_mismatch);
    goto punt;
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

/**
 * Try to find a good copy of a certificate either in fresh data or in
 * backup data from a previous run of this program.
 */
static X509 *check_cert(rcynic_ctx_t *rc,
			char *uri,
			STACK_OF(X509) *certs,
			const certinfo_t *issuer,
			certinfo_t *subj,
			const char *prefix,
			const int backup,
			const unsigned char *hash,
			const size_t hashlen)
{
  char path[FILENAME_MAX];
  X509 *x;

  assert(rc && uri && certs && issuer && subj && prefix);

  /*
   * If target file already exists and we're not here to recheck with
   * better data, just get out now.
   */

  if (uri_to_filename(uri, path, sizeof(path), rc->authenticated) && 
      !access(path, R_OK)) {
    if (backup || sk_find(rc->backup_cache, uri) < 0)
      return NULL;
    mib_increment(rc, uri, current_cert_recheck);
    logmsg(rc, log_telemetry, "Rechecking cert %s", uri);
  } else {
    logmsg(rc, log_telemetry, "Checking cert %s", uri);
  }

  rc->indent++;

  if ((x = check_cert_1(rc, uri, path, sizeof(path), prefix,
			certs, issuer, subj, hash, hashlen)) != NULL) {
    install_object(rc, uri, path, 5);
    mib_increment(rc, uri,
		  (backup ? backup_cert_accepted : current_cert_accepted));
    if (!backup)
      sk_delete(rc->backup_cache, sk_find(rc->backup_cache, uri));
    else if (!sk_push_strdup(rc->backup_cache, uri))
      logmsg(rc, log_sys_err, "Couldn't cache URI %s, blundering onward", uri);
      
  } else if (!access(path, F_OK)) {
    mib_increment(rc, uri,
		  (backup ? backup_cert_rejected : current_cert_rejected));
  }

  rc->indent--;

  return x;
}



/**
 * Read and check one manifest from disk.
 */
static Manifest *check_manifest_1(const rcynic_ctx_t *rc,
				  const char *uri,
				  char *path,
				  const int pathlen,
				  const char *prefix,
				  STACK_OF(X509) *certs)
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

  if (!uri_to_filename(uri, path, pathlen, prefix) ||
      (cms = read_cms(path, NULL, 0)) == NULL)
    goto done;

  if ((eContentType = CMS_get0_eContentType(cms)) == NULL ||
      oid_cmp(eContentType, id_ct_rpkiManifest, sizeof(id_ct_rpkiManifest))) {
    logmsg(rc, log_data_err, "Bad manifest %s eContentType", uri);
    mib_increment(rc, uri, manifest_bad_econtenttype);
    goto done;
  }

  if ((bio = BIO_new(BIO_s_mem())) == NULL) {
    logmsg(rc, log_sys_err, "Couldn't allocate BIO for manifest %s", uri);
    goto done;
  }

  if (CMS_verify(cms, NULL, NULL, NULL, bio, CMS_NO_SIGNER_CERT_VERIFY) <= 0) {
    logmsg(rc, log_data_err, "Validation failure for manifest %s CMS message", uri);
    mib_increment(rc, uri, manifest_invalid_cms);
    goto done;
  }

  if ((signers = CMS_get0_signers(cms)) == NULL || sk_X509_num(signers) != 1) {
    logmsg(rc, log_data_err, "Couldn't extract signers from manifest %s CMS", uri);
    mib_increment(rc, uri, manifest_missing_signer);
    goto done;
  }

  parse_cert(sk_X509_value(signers, 0), &certinfo, uri);

  if ((crl_tail = strrchr(certinfo.crldp, '/')) == NULL) {
    logmsg(rc, log_data_err, "Couldn't find trailing slash in %s CRLDP for manifest %s", certinfo.crldp, uri);
    goto done;
  }
  crl_tail++;

  if ((manifest = ASN1_item_d2i_bio(ASN1_ITEM_rptr(Manifest), bio, NULL)) == NULL) {
    logmsg(rc, log_data_err, "Failure decoding manifest %s", uri);
    mib_increment(rc, uri, manifest_decode_error);
    goto done;
  }

  if (manifest->version) {
    logmsg(rc, log_data_err, "Manifest %s version should be defaulted zero, not %ld", ASN1_INTEGER_get(manifest->version));
    mib_increment(rc, uri, manifest_wrong_version);
    goto done;
  }

  if (X509_cmp_current_time(manifest->thisUpdate) > 0) {
    logmsg(rc, log_data_err, "Manifest %s not yet valid", uri);
    mib_increment(rc, uri, manifest_not_yet_valid);
    goto done;
  }

  if (X509_cmp_current_time(manifest->nextUpdate) < 0) {
    logmsg(rc, log_data_err, "Stale manifest %s", uri);
    mib_increment(rc, uri, stale_manifest);
    if (!rc->allow_stale_manifest)
      goto done;
  }

  if (manifest->fileHashAlg == NULL ||
      oid_cmp(manifest->fileHashAlg, id_sha256, sizeof(id_sha256)))
    goto done;

  for (i = 0; (fah = sk_FileAndHash_value(manifest->fileList, i)) != NULL; i++)
    if (!strcmp(fah->file->data, crl_tail))
      break;

  if (fah) {
    crl = check_crl(rc, certinfo.crldp, sk_X509_value(certs, sk_X509_num(certs) - 1),
		    fah->hash->data, fah->hash->length);
  } else {
    logmsg(rc, log_data_err, "Couldn't find CRL %s in manifest %s", certinfo.crldp, uri);
    mib_increment(rc, uri, crl_not_in_manifest);
    if (rc->require_crl_in_manifest)
      goto done;
    crl = check_crl(rc, certinfo.crldp, sk_X509_value(certs, sk_X509_num(certs) - 1),
		    NULL, 0);
  }

  if (!crl) {
    logmsg(rc, log_data_err, "Bad CRL %s for manifest %s EE certificate", certinfo.crldp, uri);
    goto done;
  }

  if ((crls = sk_X509_CRL_new_null()) == NULL || !sk_X509_CRL_push(crls, crl))
    goto done;
  crl = NULL;

  if (!(initialized_store_ctx = X509_STORE_CTX_init(&rctx.ctx, rc->x509_store, sk_X509_value(signers, 0), NULL)))
    goto done;
  
  rctx.rc = rc;
  rctx.subj = &certinfo;

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
    logmsg(rc, log_data_err, "Validation failure for manifest %s EE certificate",uri);
    mib_increment(rc, uri, manifest_invalid_ee);
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
				const char *uri,
				STACK_OF(X509) *certs)
{
  CMS_ContentInfo *cms = NULL;
  Manifest *manifest = NULL;
  char path[FILENAME_MAX];
  BIO *bio = NULL;

  if (uri_to_filename(uri, path, sizeof(path), rc->authenticated) &&
      (cms = read_cms(path, NULL, 0)) != NULL &&
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

  logmsg(rc, log_telemetry, "Checking manifest %s", uri);

  rsync_file(rc, uri);

  if ((manifest = check_manifest_1(rc, uri, path, sizeof(path),
				   rc->unauthenticated, certs))) {
    install_object(rc, uri, path, 5);
    mib_increment(rc, uri, current_manifest_accepted);
    return manifest;
  } else if (!access(path, F_OK)) {
    mib_increment(rc, uri, current_manifest_rejected);
  }

  if ((manifest = check_manifest_1(rc, uri, path, sizeof(path),
				   rc->old_authenticated, certs))) {
    install_object(rc, uri, path, 5);
    mib_increment(rc, uri, backup_manifest_accepted);
    return manifest;
  } else if (!access(path, F_OK)) {
    mib_increment(rc, uri, backup_manifest_rejected);
  }

  return NULL;
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
		       const char *uri,
		       char *path,
		       const int pathlen,
		       const char *prefix,
		       STACK_OF(X509) *certs,
		       const unsigned char *hash,
		       const size_t hashlen)
{
  unsigned char hashbuf[EVP_MAX_MD_SIZE], addrbuf[ADDR_RAW_BUF_LEN];
  const ASN1_OBJECT *eContentType = NULL;
  STACK_OF(IPAddressFamily) *roa_resources = NULL, *ee_resources = NULL;
  STACK_OF(X509_CRL) *crls = NULL;
  STACK_OF(X509) *signers = NULL;
  CMS_ContentInfo *cms = NULL;
  X509_CRL *crl = NULL;
  ROA *roa = NULL;
  BIO *bio = NULL;
  rcynic_x509_store_ctx_t rctx;
  certinfo_t certinfo;
  int i, j, initialized_store_ctx = 0, result = 0;
  unsigned afi, *safi = NULL, safi_, prefixlen;
  ROAIPAddressFamily *rf;
  ROAIPAddress *ra;

  assert(rc && uri && path && prefix && certs && sk_X509_num(certs));

  if (!uri_to_filename(uri, path, pathlen, prefix))
    goto error;

  if (hash)
    cms = read_cms(path, hashbuf, sizeof(hashbuf));
  else
    cms = read_cms(path, NULL, 0);

  if (!cms)
    goto error;

  if (hash && memcmp(hashbuf, hash, hashlen)) {
    logmsg(rc, log_data_err, "Manifest digest mismatch for ROA %s", uri);
    mib_increment(rc, uri, roa_digest_mismatch);
    goto error;
  }

  if (!(eContentType = CMS_get0_eContentType(cms)) ||
      oid_cmp(eContentType, id_ct_routeOriginAttestation,
	      sizeof(id_ct_routeOriginAttestation))) {
    logmsg(rc, log_data_err, "Bad ROA %s eContentType", uri);
    mib_increment(rc, uri, roa_bad_econtenttype);
    goto error;
  }

  if ((bio = BIO_new(BIO_s_mem())) == NULL) {
    logmsg(rc, log_sys_err, "Couldn't allocate BIO for ROA %s", uri);
    goto error;
  }

  if (CMS_verify(cms, NULL, NULL, NULL, bio, CMS_NO_SIGNER_CERT_VERIFY) <= 0) {
    logmsg(rc, log_data_err, "Validation failure for ROA %s CMS message", uri);
    mib_increment(rc, uri, roa_invalid_cms);
    goto error;
  }

  if (!(signers = CMS_get0_signers(cms)) || sk_X509_num(signers) != 1) {
    logmsg(rc, log_data_err, "Couldn't extract signers from ROA %s CMS", uri);
    mib_increment(rc, uri, roa_missing_signer);
    goto error;
  }

  parse_cert(sk_X509_value(signers, 0), &certinfo, uri);

  if (!(roa = ASN1_item_d2i_bio(ASN1_ITEM_rptr(ROA), bio, NULL))) {
    logmsg(rc, log_data_err, "Failure decoding ROA %s", uri);
    mib_increment(rc, uri, roa_decode_error);
    goto error;
  }

  if (roa->version) {
    logmsg(rc, log_data_err, "ROA %s version should be defaulted zero, not %ld", uri, ASN1_INTEGER_get(roa->version));
    mib_increment(rc, uri, roa_wrong_version);
    goto error;
  }

  /*
   * ROA issuer doesn't need rights to the ASN, so we don't need to
   * check the asID field.
   */

  ee_resources = X509_get_ext_d2i(sk_X509_value(signers, 0), NID_sbgp_ipAddrBlock, NULL, NULL);

  if (!(roa_resources = sk_IPAddressFamily_new_null()))
    goto error;

  for (i = 0; i < sk_ROAIPAddressFamily_num(roa->ipAddrBlocks); i++) {
    rf = sk_ROAIPAddressFamily_value(roa->ipAddrBlocks, i);
    if (!rf || !rf->addressFamily || rf->addressFamily->length < 2 || rf->addressFamily->length > 3) {
      logmsg(rc, log_data_err, "ROA %s addressFamily length should be 2 or 3", uri);
      mib_increment(rc, uri, malformed_roa_addressfamily);
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
	logmsg(rc, log_data_err, "Failed to copy resources from ROA %s into resource set", uri);
	goto error;
      }
    }
  }

  if (!v3_addr_canonize(roa_resources)) {
    logmsg(rc, log_data_err, "Failed to put resources from ROA %s into canonical resource set form", uri);
    goto error;
  }

  if (!v3_addr_subset(roa_resources, ee_resources)) {
    logmsg(rc, log_data_err, "ROA %s resources are not a subset of its signing EE certificate's resources", uri);
    goto error;
  }

  if (!(crl = check_crl(rc, certinfo.crldp, sk_X509_value(certs, sk_X509_num(certs) - 1), NULL, 0))) {
    logmsg(rc, log_data_err, "Bad CRL %s for ROA %s EE certificate", certinfo.crldp, uri);
    goto error;
  }

  if (!(crls = sk_X509_CRL_new_null()) || !sk_X509_CRL_push(crls, crl))
    goto error;
  crl = NULL;

  if (!(initialized_store_ctx = X509_STORE_CTX_init(&rctx.ctx, rc->x509_store, sk_X509_value(signers, 0), NULL)))
    goto error;
  
  rctx.rc = rc;
  rctx.subj = &certinfo;

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
    logmsg(rc, log_data_err, "Validation failure for ROA %s EE certificate",uri);
    mib_increment(rc, uri, roa_invalid_ee);
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
		      const char *uri,
		      STACK_OF(X509) *certs,
		      const unsigned char *hash,
		      const size_t hashlen)
{
  char path[FILENAME_MAX];

  if (uri_to_filename(uri, path, sizeof(path), rc->authenticated) &&
      !access(path, F_OK))
    return;

  logmsg(rc, log_telemetry, "Checking ROA %s", uri);

  rsync_file(rc, uri);

  if (check_roa_1(rc, uri, path, sizeof(path), rc->unauthenticated,
		  certs, hash, hashlen)) {
    install_object(rc, uri, path, 5);
    mib_increment(rc, uri, current_roa_accepted);
    return;
  } else if (!access(path, F_OK)) {
    mib_increment(rc, uri, current_roa_rejected);
  }

  if (check_roa_1(rc, uri, path, sizeof(path), rc->old_authenticated,
		  certs, hash, hashlen)) {
    install_object(rc, uri, path, 5);
    mib_increment(rc, uri, backup_roa_accepted);
    return;
  } else if (!access(path, F_OK)) {
    mib_increment(rc, uri, backup_roa_rejected);
  }
}



static void walk_cert(rcynic_ctx_t *rc,
		      const certinfo_t *parent,
		      STACK_OF(X509) *certs);

/**
 * Recursive walk of certificate hierarchy (core of the program).  The
 * daisy chain recursion is to avoid having to duplicate the stack
 * manipulation and error handling.
 */
static void walk_cert_1(rcynic_ctx_t *rc,
			char *uri,
			STACK_OF(X509) *certs,
			const certinfo_t *issuer,
			certinfo_t *subj,
			const char *prefix,
			const int backup,
			const unsigned char *hash,
			const size_t hashlen)
{
  X509 *x;

  if ((x = check_cert(rc, uri, certs, issuer, subj, prefix, backup, hash, hashlen)) == NULL)
    return;

  if (!sk_X509_push(certs, x)) {
    logmsg(rc, log_sys_err,
	   "Internal allocation failure recursing over certificate");
    return;
  }

  walk_cert(rc, subj, certs);
  X509_free(sk_X509_pop(certs));
}

/**
 * Recursive walk of certificate hierarchy (core of the program).  The
 * daisy chain recursion is to avoid having to duplicate the stack
 * manipulation and error handling.
 */

static void walk_cert(rcynic_ctx_t *rc,
		      const certinfo_t *parent,
		      STACK_OF(X509) *certs)
{
  assert(parent && certs);

  if (parent->sia[0] && parent->ca) {
    int n_cert = sk_X509_num(certs);
    char uri[URI_MAX];
    certinfo_t child;
    int iterator = 0;
    Manifest *manifest = NULL;
    FileAndHash *fah;

    rc->indent++;

    rsync_sia(rc, parent->sia);

    if (!parent->manifest[0]) {

      logmsg(rc, log_data_err, "Parent certificate does not specify a manifest, skipping collection");

    } else if ((manifest = check_manifest(rc, parent->manifest, certs)) == NULL) {

      logmsg(rc, log_data_err, "Couldn't get manifest %s, skipping collection", parent->manifest);

    } else {

      logmsg(rc, log_debug, "Walking unauthenticated store");
      while ((fah = next_uri(rc, parent->sia, rc->unauthenticated, uri, sizeof(uri), manifest, &iterator)) != NULL)
	if (has_suffix(uri, ".cer"))
	  walk_cert_1(rc, uri, certs, parent, &child, rc->unauthenticated, 0, fah->hash->data, fah->hash->length);
	else if (has_suffix(uri, ".roa"))
	  check_roa(rc, uri, certs, fah->hash->data, fah->hash->length);
	else if (!has_suffix(uri, ".crl"))
	  logmsg(rc, log_telemetry, "Don't know how to check object %s, ignoring", uri);
      logmsg(rc, log_debug, "Done walking unauthenticated store");

      logmsg(rc, log_debug, "Walking old authenticated store");
      while ((fah = next_uri(rc, parent->sia, rc->old_authenticated, uri, sizeof(uri), manifest, &iterator)) != NULL)
	if (has_suffix(uri, ".cer"))
	  walk_cert_1(rc, uri, certs, parent, &child, rc->old_authenticated, 1, fah->hash->data, fah->hash->length);
	else if (has_suffix(uri, ".roa"))
	  check_roa(rc, uri, certs, fah->hash->data, fah->hash->length);
	else if (!has_suffix(uri, ".crl"))
	  logmsg(rc, log_telemetry, "Don't know how to check object %s, ignoring", uri);
      logmsg(rc, log_debug, "Done walking old authenticated store");

      Manifest_free(manifest);
    }

    assert(sk_X509_num(certs) == n_cert);

    rc->indent--;
  }
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
  char *cfg_file = "rcynic.conf", path[FILENAME_MAX];
  char *lockfile = NULL, *xmlfile = NULL;
  int c, i, j, ret = 1, jitter = 600, lockfd = -1;
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
  rc.allow_stale_crl = 1;
  rc.allow_stale_manifest = 1;

#define QQ(x,y)   rc.priority[x] = y;
  LOG_LEVELS;
#undef QQ

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  while ((c = getopt(argc, argv, "c:l:stpj:V")) > 0) {
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

    else if (!name_cmp(val->name, "require-crl-in-manifest") &&
	     !configure_boolean(&rc, &rc.require_crl_in_manifest, val->value))
      goto done;

    else if (!name_cmp(val->name, "use-links") &&
	     !configure_boolean(&rc, &rc.use_links, val->value))
      goto done;

    else if (!name_cmp(val->name, "prune") &&
	     !configure_boolean(&rc, &prune, val->value))
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

  if ((rc.rsync_cache = sk_new(uri_cmp)) == NULL) {
    logmsg(&rc, log_sys_err, "Couldn't allocate rsync_cache stack");
    goto done;
  }

  if ((rc.backup_cache = sk_new(uri_cmp)) == NULL) {
    logmsg(&rc, log_sys_err, "Couldn't allocate backup_cache stack");
    goto done;
  }

  if ((xmlfile) &&
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

    if ((x = read_cert(val->value, NULL, 0)) == NULL) {
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
	!(rc.use_links ? ln(val->value, path) : cp(val->value, path))) {
      logmsg(&rc, log_sys_err, "Couldn't %s trust anchor %s",
	     (rc.use_links ? "link" : "copy"), val->value);
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

  if (prune && !prune_unauthenticated(&rc, rc.unauthenticated,
				      strlen(rc.unauthenticated))) {
    logmsg(&rc, log_sys_err, "Trouble pruning old unauthenticated data");
    goto done;
  }

  ret = 0;

 done:
  log_openssl_errors(&rc);

  if (sk_num(rc.host_counters) > 0) {

    char tad[sizeof("2006-10-13T11:22:33Z") + 1];
    char hostname[HOST_NAME_MAX];
    time_t tad_time = time(0);
    struct tm *tad_tm = gmtime(&tad_time);
    int ok = 1, use_stdout = !strcmp(xmlfile, "-");
    FILE *f;

    strftime(tad, sizeof(tad), "%Y-%m-%dT%H:%M:%SZ", tad_tm);

    ok &= gethostname(hostname, sizeof(hostname)) == 0;

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
		    "  <labels>\n"
		    "    <hostname>Hostname</hostname>\n",
		    tad, svn_id, XML_SUMMARY_VERSION, hostname) != EOF;

    for (j = 0; ok && j < MIB_COUNTER_T_MAX; ++j)
      ok &= fprintf(f, "    <%s>%s</%s>\n", mib_counter_label[j],
		    (mib_counter_desc[j]
		     ? mib_counter_desc[j]
		     : X509_verify_cert_error_string(mib_counter_openssl[j])),
		    mib_counter_label[j]) != EOF;

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

    if (f && !use_stdout)
      ok &= fclose(f) != EOF;

    if (!ok)
      logmsg(&rc, log_sys_err, "Couldn't write XML summary to %s: %s",
	     xmlfile, strerror(errno));

  }

  /*
   * Do NOT free cfg_section, NCONF_free() takes care of that
   */
  sk_X509_pop_free(certs, X509_free);
  sk_pop_free(rc.rsync_cache, free);
  sk_pop_free(rc.backup_cache, free);
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
    logmsg(&rc, log_telemetry,
	   "Finished, elapsed time %d:%02d:%02d",
	   (finish - start) / 3600,
	   (finish - start) / 60 % 60,
	   (finish - start) % 60);
  }

  return ret;
}
