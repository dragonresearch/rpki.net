/*
 * This module started out as the core of Peter Shannon's "Python
 * OpenSSL Wrappers" package, an excellent but somewhat dated package
 * which I encountered while looking for some halfway sane way to cram
 * RFC 3779 certificate support code into Python.
 *
 * At this point enough of the code has been added or rewritten that
 * it's unclear (either way) whether this code properly qualifies as a
 * derivative work.  Given that both Peter's original code and all of
 * subsequent changes to it were done under something equivalent to a
 * BSD license, this may not matter very much, but the following
 * attempts to give proper credit to all concerned.
 *
 ****
 *
 * Copyright (C) 2015--2016  Parsons Government Services ("PARSONS")
 * Portions copyright (C) 2014  Dragon Research Labs ("DRL")
 * Portions copyright (C) 2009--2013  Internet Systems Consortium ("ISC")
 * Portions copyright (C) 2006--2008  American Registry for Internet Numbers ("ARIN")
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notices and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND PARSONS, DRL, ISC, AND ARIN
 * DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT
 * SHALL PARSONS, DRL, ISC, OR ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
 * CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 ****
 *
 * Portions Copyright (c) 2001, 2002, Peter Shannon
 * All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *      * Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      * Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 *      * The name of the contributors may be used to endorse or promote
 *        products derived from this software without specific prior
 *        written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS
 *  OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* $Id$ */

#define	PY_SSIZE_T_CLEAN 1
#include <Python.h>
#include <datetime.h>

#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/cms.h>

#include <rpki/roa.h>
#include <rpki/manifest.h>

#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/*
 * GCC attribute to let us tell GCC not to whine about unused formal
 * parameters when we're in maximal warning mode.
 */
#ifdef __GNUC__
#define	GCC_UNUSED	__attribute__((unused))
#else
define	GCC_UNUSED
#endif

/*
 * Maximum size of a raw IP (v4 or v6) address, in bytes.
 */
#define RAW_IPADDR_BUFLEN    16

/*
 * Maximum size of an ASN.1 Integer converted from a Python Long, in bytes.
 */
#define MAX_ASN1_INTEGER_LEN    20

/*
 * How many bytes is a SHA256 digest?
 */
#define	HASH_SHA256_LEN		32

/* Digests */
#define SHA1_DIGEST           4
#define SHA256_DIGEST         6
#define SHA384_DIGEST         7
#define SHA512_DIGEST         8

/* Object format */
#define SHORTNAME_FORMAT      1
#define LONGNAME_FORMAT       2
#define OIDNAME_FORMAT        3

/* AsymmetricParam EC curves */
#define EC_P256_CURVE         NID_X9_62_prime256v1

/* Object check functions */
#define POW_X509_Check(op)              PyObject_TypeCheck(op, &POW_X509_Type)
#define POW_X509StoreCTX_Check(op)      PyObject_TypeCheck(op, &POW_X509StoreCTX_Type)
#define POW_CRL_Check(op)               PyObject_TypeCheck(op, &POW_CRL_Type)
#define POW_Asymmetric_Check(op)        PyObject_TypeCheck(op, &POW_Asymmetric_Type)
#define POW_AsymmetricParams_Check(op)	PyObject_TypeCheck(op, &POW_AsymmetricParams_Type)
#define POW_Digest_Check(op)            PyObject_TypeCheck(op, &POW_Digest_Type)
#define POW_CMS_Check(op)               PyObject_TypeCheck(op, &POW_CMS_Type)
#define POW_IPAddress_Check(op)         PyObject_TypeCheck(op, &POW_IPAddress_Type)
#define POW_ROA_Check(op)               PyObject_TypeCheck(op, &POW_ROA_Type)
#define POW_Manifest_Check(op)          PyObject_TypeCheck(op, &POW_Manifest_Type)
#define POW_ROA_Check(op)               PyObject_TypeCheck(op, &POW_ROA_Type)

static char pow_module__doc__ [] =
  "Python interface to RFC-3779-enabled OpenSSL.  This code is intended\n"
  "to support the rpki.net toolset.\n"
  "\n"
  "This code started out life as Peter Shannon's excellent \"Python OpenSSL\n"
  "Wrappers\" package.  It has been extensively modified since then, to add\n"
  "support for things needed for the RPKI protocols, to upgrade the code\n"
  "to use modern (circa Python 2.7) classes, and to remove code not\n"
  "needed for RPKI work.\n"
  ;

/*
 * Handle NIDs we wish OpenSSL knew about.  This is carefully (we
 * hope) written to do nothing at all for any NID that OpenSSL knows
 * about; the intent is just to add definitions for things OpenSSL
 * doesn't know about yet.  Of necessity, this is a bit gross, since
 * it confounds runtime static variables with predefined macro names,
 * but we try to put all the magic associated with this in one place.
 */

#ifndef NID_ad_rpkiManifest
static int NID_ad_rpkiManifest;
#endif

#ifndef NID_ad_signedObject
static int NID_ad_signedObject;
#endif

#ifndef NID_ad_rpkiNotify
static int NID_ad_rpkiNotify;
#endif

#ifndef    NID_ct_ROA
static int NID_ct_ROA;
#endif

#ifndef    NID_ct_rpkiManifest
static int NID_ct_rpkiManifest;
#endif

#ifndef    NID_ct_rpkiGhostbusters
static int NID_ct_rpkiGhostbusters;
#endif

#ifndef	   NID_cp_ipAddr_asNumber
static int NID_cp_ipAddr_asNumber;
#endif

#ifndef    NID_id_kp_bgpsec_router
static int NID_id_kp_bgpsec_router;
#endif

#ifndef    NID_binary_signing_time
static int NID_binary_signing_time;
#endif

static const struct {
  int *nid;
  const char *oid;
  const char *sn;
  const char *ln;
} missing_nids[] = {

#ifndef NID_ad_rpkiManifest
  {&NID_ad_rpkiManifest, "1.3.6.1.5.5.7.48.10", "id-ad-rpkiManifest", "RPKI Manifest"},
#endif

#ifndef NID_ad_signedObject
  {&NID_ad_signedObject, "1.3.6.1.5.5.7.48.11", "id-ad-signedObject", "Signed Object"},
#endif

#ifndef NID_ad_rpkiNotify
  {&NID_ad_rpkiNotify,   "1.3.6.1.5.5.7.48.13", "id-ad-rpkiNotify",   "RPKI RRDP Notification"},
#endif

#ifndef NID_ct_ROA
  {&NID_ct_ROA, "1.2.840.113549.1.9.16.1.24", "id-ct-routeOriginAttestation", "ROA eContent"},
#endif

#ifndef NID_ct_rpkiManifest
  {&NID_ct_rpkiManifest, "1.2.840.113549.1.9.16.1.26", "id-ct-rpkiManifest", "RPKI Manifest eContent"},
#endif

#ifndef NID_ct_rpkiGhostbusters
  {&NID_ct_rpkiGhostbusters, "1.2.840.113549.1.9.16.1.35", "id-ct-rpkiGhostbusters", "RPKI Ghostbusters eContent"},
#endif

#ifndef NID_cp_ipAddr_asNumber
  {&NID_cp_ipAddr_asNumber, "1.3.6.1.5.5.7.14.2", "id-cp-ipAddr-asNumber", "RPKI Certificate Policy"},
#endif

#ifndef NID_id_kp_bgpsec_router
  {&NID_id_kp_bgpsec_router,  "1.3.6.1.5.5.7.3.30", "id-kp-bgpsec-router", "BGPSEC Router Certificate"},
#endif

#ifndef NID_binary_signing_time
  {&NID_binary_signing_time, "1.2.840.113549.1.9.16.2.46", "id-aa-binarySigningTime", "CMS Binary Signing Time"},
#endif

};

/*
 * IP versions.
 */

typedef struct ipaddress_version {
  unsigned version;
  unsigned afi;
  unsigned af;
  unsigned length;
} ipaddress_version;

static const ipaddress_version ipaddress_version_4 = {
  4, IANA_AFI_IPV4, AF_INET, 4
};

static const ipaddress_version ipaddress_version_6 = {
  6, IANA_AFI_IPV6, AF_INET6, 16
};

static const ipaddress_version * const ipaddress_versions[] = {
  &ipaddress_version_4, &ipaddress_version_6
};

/*
 * Names of bits in the KeyUsage BitString (RFC 5280 4.2.1.3).
 */

static const char * const key_usage_bit_names[] = {
  "digitalSignature",           /* (0) */
  "nonRepudiation",             /* (1) */
  "keyEncipherment",            /* (2) */
  "dataEncipherment",           /* (3) */
  "keyAgreement",               /* (4) */
  "keyCertSign",                /* (5) */
  "cRLSign",                    /* (6) */
  "encipherOnly",               /* (7) */
  "decipherOnly",               /* (8) */
  NULL
};

/*
 * Exception objects.
 */

static PyObject
  *ErrorObject,
  *OpenSSLErrorObject,
  *POWErrorObject,
  *NotVerifiedErrorObject,
  *ValidationErrorObject;

/*
 * Constructor for customized datetime class.
 */

static PyObject *custom_datetime;

/*
 * "ex_data" index for pointer we want to attach to X509_STORE_CTX so
 * we can extract it in callbacks.
 */

static int x509_store_ctx_ex_data_idx = -1;

/*
 * ASN.1 "constants" constructed at runtime.
 */

static const ASN1_INTEGER *asn1_zero, *asn1_four_octets, *asn1_twenty_octets;

/*
 * Declarations of type objects (definitions come later).
 */

static PyTypeObject
  POW_X509_Type,
  POW_X509StoreCTX_Type,
  POW_CRL_Type,
  POW_Asymmetric_Type,
  POW_AsymmetricParams_Type,
  POW_Digest_Type,
  POW_CMS_Type,
  POW_IPAddress_Type,
  POW_ROA_Type,
  POW_Manifest_Type,
  POW_ROA_Type,
  POW_PKCS10_Type;

/*
 * Object internals.
 */

typedef struct {
  PyObject_HEAD
  unsigned char address[16];
  const struct ipaddress_version *type;
} ipaddress_object;

typedef struct {
  PyObject_HEAD
  X509 *x509;
} x509_object;

typedef struct {
  PyObject_HEAD
  X509_STORE_CTX *ctx;
  X509_STORE *store;
} x509_store_ctx_object;

typedef struct {
  PyObject_HEAD
  X509_CRL *crl;
} crl_object;

typedef struct {
  PyObject_HEAD
  EVP_PKEY *pkey;
} asymmetric_object;

typedef struct {
  PyObject_HEAD
  EVP_PKEY *pkey;
} asymmetric_params_object;

typedef struct {
  PyObject_HEAD
  EVP_MD_CTX digest_ctx;
  int digest_type;
} digest_object;

typedef struct {
  PyObject_HEAD
  CMS_ContentInfo *cms;
} cms_object;

typedef struct {
  cms_object cms;               /* Subclass of CMS */
  ROA *roa;
} roa_object;

typedef struct {
  cms_object cms;               /* Subclass of CMS */
  Manifest *manifest;
} manifest_object;

typedef struct {
  PyObject_HEAD
  X509_REQ *pkcs10;
  X509_EXTENSIONS *exts;
} pkcs10_object;

/*
 * Container for a generic extension, including a destructor.
 */

typedef struct {
  void (*destructor)(void *);
  void *value;
  int nid;
  int critical;
} extension_wrapper;



/*
 * Utility functions.
 */

/*
 * Minimal intervention debug-by-printf() hack, use only for good.
 */

#if 0
#define KVETCH(_msg_)           write(2, _msg_ "\n", sizeof(_msg_))
#else
#define KVETCH(_msg_)           ((void) 0)
#endif

#if 0
#define ENTERING(_name_)        KVETCH("Entering " #_name_ "()")
#else
#define ENTERING(_name_)        ((void) 0)
#endif

/*
 * Error handling macros.  All of macros assume that there's a cleanup
 * label named "error" which these macros can use as a goto target.
 */

#define lose(_msg_)                                                     \
  do {                                                                  \
    PyErr_SetString(POWErrorObject, (_msg_));                           \
    goto error;                                                         \
  } while (0)

#define lose_no_memory()                                                \
  do {                                                                  \
    PyErr_NoMemory();                                                   \
    goto error;                                                         \
  } while (0)

#define lose_type_error(_msg_)                                          \
  do {                                                                  \
    PyErr_SetString(PyExc_TypeError, (_msg_));                          \
    goto error;                                                         \
  } while (0)

#define lose_value_error(_msg_)                                         \
  do {                                                                  \
    PyErr_SetString(PyExc_ValueError, (_msg_));                         \
    goto error;                                                         \
  } while (0)

#define lose_openssl_error(_msg_)                                       \
  do {                                                                  \
    set_openssl_exception(OpenSSLErrorObject, (_msg_), 0);              \
    goto error;                                                         \
  } while (0)

#define lose_not_verified(_msg_)                                        \
  do {                                                                  \
    PyErr_SetString(NotVerifiedErrorObject, (_msg_));                   \
    goto error;                                                         \
  } while (0)

#define lose_validation_error(_msg_)					\
  do {                                                                  \
    PyErr_SetString(ValidationErrorObject, (_msg_));			\
    goto error;                                                         \
  } while (0)

#define assert_no_unhandled_openssl_errors()                            \
  do {                                                                  \
    if (ERR_peek_error()) {                                             \
      set_openssl_exception(OpenSSLErrorObject, NULL, __LINE__);        \
      goto error;                                                       \
    }                                                                   \
  } while (0)

#define POW_assert(_cond_)                                              \
  do {                                                                  \
    if (!(_cond_)) {                                                    \
      (void) PyErr_Format(POWErrorObject,                               \
                          "Assertion %s failed at " __FILE__ ":%d",     \
                          #_cond_, __LINE__);                           \
      goto error;                                                       \
    }                                                                   \
  } while (0)

/*
 * Consolidate some tedious EVP-related switch statements.
 */

static const EVP_MD *
evp_digest_factory(int digest_type)
{
  switch (digest_type) {
  case SHA1_DIGEST:     return EVP_sha1();
  case SHA256_DIGEST:   return EVP_sha256();
  case SHA384_DIGEST:   return EVP_sha384();
  case SHA512_DIGEST:   return EVP_sha512();
  default:              return NULL;
  }
}

/*
 * Raise an exception with data pulled from the OpenSSL error stack.
 * Exception value is a tuple with some internal structure.
 *
 * If a string error message is supplied, that string is the first
 * element of the exception value tuple.
 *
 * If a non-zero line number is supplied, a string listing this as an
 * unhandled exception detected at that line will be the next element
 * of the exception value tuple (or the first, if no error message was
 * supplied).
 *
 * Remainder of exception value tuple is zero or more tuples, each
 * representing one error from the stack.
 *
 * Each error tuple contains six slots:
 * - the numeric error code
 * - string translation of numeric error code ("reason")
 * - name of library in which error occurred
 * - name of function in which error occurred
 * - name of file in which error occurred
 * - line number in file where error occurred
 */

static void
set_openssl_exception(PyObject *error_class, const char *msg, const int unhandled_line)
{
  PyObject *errtuple = NULL;
  PyObject *errlist = NULL;
  unsigned long err;
  const char *file;
  int line;

  if ((errlist = PyList_New(0)) == NULL)
    return;

  if (msg) {
    PyObject *s = PyString_FromString(msg);
    (void) PyList_Append(errlist, s);
    Py_XDECREF(s);
  }

  if (unhandled_line) {
    PyObject *s = PyString_FromFormat("Unhandled OpenSSL error at " __FILE__ ":%d!", unhandled_line);
    (void) PyList_Append(errlist, s);
    Py_XDECREF(s);
  }

  while ((err = ERR_get_error_line(&file, &line)) != 0) {
    PyObject *t = Py_BuildValue("(issssi)",
                                err,
                                ERR_reason_error_string(err),
                                ERR_lib_error_string(err),
                                ERR_func_error_string(err),
                                file,
                                line);
    (void) PyList_Append(errlist, t);
    Py_XDECREF(t);
  }

  if ((errtuple = PyList_AsTuple(errlist)) != NULL)
    PyErr_SetObject(error_class, errtuple);

  Py_XDECREF(errtuple);
  Py_XDECREF(errlist);
}

static X509_NAME *
x509_object_helper_set_name(PyObject *dn_obj)
{
  PyObject *rdn_obj = NULL;
  PyObject *pair_obj = NULL;
  PyObject *type_obj = NULL;
  PyObject *value_obj = NULL;
  X509_NAME *name = NULL;
  char *type_str, *value_str;
  int asn1_type, i, j;

  if ((name = X509_NAME_new()) == NULL)
    lose_no_memory();

  for (i = 0; i < PySequence_Size(dn_obj); i++) {

    if ((rdn_obj = PySequence_GetItem(dn_obj, i)) == NULL)
      goto error;

    if (!PySequence_Check(rdn_obj) || PySequence_Size(rdn_obj) == 0)
      lose_type_error("Each RDN must be a sequence with at least one element");

    for (j = 0; j < PySequence_Size(rdn_obj); j++) {

      if ((pair_obj = PySequence_GetItem(rdn_obj, j)) == NULL)
        goto error;

      if (!PySequence_Check(pair_obj) || PySequence_Size(pair_obj) != 2)
        lose_type_error("Each name entry must be a two-element sequence");

      if ((type_obj  = PySequence_GetItem(pair_obj, 0)) == NULL ||
          (type_str  = PyString_AsString(type_obj))     == NULL ||
          (value_obj = PySequence_GetItem(pair_obj, 1)) == NULL ||
          (value_str = PyString_AsString(value_obj))    == NULL)
        goto error;

      if ((asn1_type = ASN1_PRINTABLE_type((unsigned char *) value_str, -1)) != V_ASN1_PRINTABLESTRING)
        asn1_type = V_ASN1_UTF8STRING;

      if (!X509_NAME_add_entry_by_txt(name, type_str, asn1_type,
                                      (unsigned char *) value_str,
                                      strlen((char *) value_str),
                                      -1, (j ? -1 : 0)))
        lose("Unable to add name entry");

      Py_XDECREF(pair_obj);
      Py_XDECREF(type_obj);
      Py_XDECREF(value_obj);
      pair_obj = type_obj = value_obj = NULL;
    }

    Py_XDECREF(rdn_obj);
    rdn_obj = NULL;
  }

  return name;

 error:
  X509_NAME_free(name);
  Py_XDECREF(rdn_obj);
  Py_XDECREF(pair_obj);
  Py_XDECREF(type_obj);
  Py_XDECREF(value_obj);
  return NULL;
}

static PyObject *
x509_object_helper_get_name(X509_NAME *name, int format)
{
  X509_NAME_ENTRY *ne = NULL;
  PyObject *result = NULL;
  PyObject *rdn = NULL;
  PyObject *item = NULL;
  const char *oid = NULL;
  char oidbuf[512];
  int i, set = -1;

  /*
   * Overall theory here: multi-value RDNs are very rare in the wild.
   * We should support them, so we don't throw an exception if handed
   * one in a BPKI certificate, but with minimal effort.  What we care
   * about here is optimizing for the common case of single-valued RDNs.
   */

  if ((result = PyTuple_New(X509_NAME_entry_count(name))) == NULL)
    goto error;

  for (i = 0; i < X509_NAME_entry_count(name); i++) {

    if ((ne = X509_NAME_get_entry(name, i)) == NULL)
      lose("Couldn't get certificate name");

    if (ne->set < 0 || ne->set < set || ne->set > set + 1)
      lose("X509_NAME->set value out of expected range");

    switch (format) {
    case SHORTNAME_FORMAT:
      oid = OBJ_nid2sn(OBJ_obj2nid(X509_NAME_ENTRY_get_object(ne)));
      break;
    case LONGNAME_FORMAT:
      oid = OBJ_nid2ln(OBJ_obj2nid(X509_NAME_ENTRY_get_object(ne)));
      break;
    case OIDNAME_FORMAT:
      oid = NULL;
      break;
    default:
      lose("Unknown name format");
    }

    if (oid == NULL) {
      if (OBJ_obj2txt(oidbuf, sizeof(oidbuf), X509_NAME_ENTRY_get_object(ne), 1) <= 0)
        lose_openssl_error("Couldn't translate OID");
      oid = oidbuf;
    }

    if (ne->set > set) {

      set++;
      if ((item = Py_BuildValue("((ss#))", oid, ASN1_STRING_data(X509_NAME_ENTRY_get_data(ne)),
                                (Py_ssize_t) ASN1_STRING_length(X509_NAME_ENTRY_get_data(ne)))) == NULL)
        goto error;
      PyTuple_SET_ITEM(result, set, item);
      item = NULL;

    } else {

      if ((rdn = PyTuple_GetItem(result, set)) == NULL)
        goto error;
      (void) _PyTuple_Resize(&rdn, PyTuple_Size(rdn) + 1);
      PyTuple_SET_ITEM(result, set, rdn);
      if (rdn == NULL)
        goto error;
      if ((item = Py_BuildValue("(ss#)", oid, ASN1_STRING_data(X509_NAME_ENTRY_get_data(ne)),
                                (Py_ssize_t) ASN1_STRING_length(X509_NAME_ENTRY_get_data(ne)))) == NULL)
        goto error;
      PyTuple_SetItem(rdn, PyTuple_Size(rdn) - 1, item);
      rdn = item = NULL;

    }
  }

  if (++set != PyTuple_Size(result)) {
    if (set < 0 || set > PyTuple_Size(result))
      lose("Impossible set count for DN, something went horribly wrong");
    _PyTuple_Resize(&result, set);
  }

  return result;

 error:
  Py_XDECREF(item);
  Py_XDECREF(result);
  return NULL;
}

static STACK_OF(X509) *
x509_helper_iterable_to_stack(PyObject *iterable)
{
  STACK_OF(X509) *stack = NULL;
  PyObject *iterator = NULL;
  PyObject *item = NULL;

  if ((stack = sk_X509_new_null()) == NULL)
    lose_no_memory();

  if (iterable != Py_None) {

    if ((iterator = PyObject_GetIter(iterable)) == NULL)
      goto error;

    while ((item = PyIter_Next(iterator)) != NULL) {

      if (!POW_X509_Check(item))
        lose_type_error("Expected an X509 object");

      if (!sk_X509_push(stack, ((x509_object *) item)->x509))
        lose("Couldn't add X509 object to stack");

      Py_XDECREF(item);
      item = NULL;
    }
  }

  Py_XDECREF(iterator);
  return stack;

 error:
  Py_XDECREF(iterator);
  Py_XDECREF(item);
  sk_X509_free(stack);
  return NULL;
}

/*
 * Pull items off an OpenSSL STACK and put them into a Python tuple.
 * Assumes that handler is stealing the OpenSSL references to the
 * items in the STACK, so shifts consumed frames off the stack so that
 * the appropriate _pop_free() destructor can clean up on failures.
 * This is OK because all current uses of this function are processing
 * the result of OpenSSL xxx_get1_xxx() methods which we have to free
 * in any case.
 */

static x509_object *x509_object_new_helper(PyTypeObject *, X509 *);
static crl_object  *crl_object_new_helper (PyTypeObject *, X509_CRL *);

static PyObject *
stack_to_tuple_helper(_STACK *sk, PyObject *(*handler)(void *))
{
  PyObject *result = NULL;
  PyObject *obj = NULL;
  int i;

  if ((result = PyTuple_New(sk_num(sk))) == NULL)
    goto error;

  for (i = 0; sk_num(sk); i++) {
    if ((obj = handler(sk_value(sk, 0))) == NULL)
      goto error;
    sk_shift(sk);
    if (PyTuple_SetItem(result, i, obj) != 0)
      goto error;
    obj = NULL;
  }

  return result;

 error:

  Py_XDECREF(obj);
  return NULL;
}

static PyObject *
stack_to_tuple_helper_get_x509(void *cert)
{
  x509_object *obj;

  ENTERING(stack_to_tuple_helper_get_x509);

  if ((obj = x509_object_new_helper(NULL, cert)) == NULL)
    return NULL;

  return (PyObject *) obj;
}

static PyObject *
stack_to_tuple_helper_get_crl(void *crl)
{
  crl_object *obj;

  ENTERING(stack_to_tuple_helper_get_crl);

  if ((obj = crl_object_new_helper(NULL, crl)) == NULL)
    return NULL;

  return (PyObject *) obj;
}

/*
 * Time conversion functions.  Obvious mapping into Python data types
 * is datetime, or, rather, our customized rpki.sundial.datetime.
 *
 * Unsuprisingly, it's easiest for us to map between GeneralizedTime
 * (as restricted by RFC 5280) and datetime.  Conversion between
 * GeneralizedTime and UTCTime is handled automatically according to
 * the RFC 5280 rules for those ASN.1 types where it's required.
 */

static PyObject *
ASN1_TIME_to_Python(ASN1_TIME *t)
{
  ASN1_GENERALIZEDTIME *g = NULL;
  PyObject *result = NULL;
  int year, month, day, hour, minute, second;

  if ((g = ASN1_TIME_to_generalizedtime(t, NULL)) == NULL)
    lose_openssl_error("Couldn't convert ASN.1 TIME");

  if (sscanf((char *) g->data, "%4d%2d%2d%2d%2d%2dZ",
             &year, &month, &day, &hour, &minute, &second) != 6)
    lose("Couldn't scan ASN.1 TIME value");
  
  if (custom_datetime != NULL && custom_datetime != Py_None)
    result = PyObject_CallFunction(custom_datetime, "iiiiii",
                                   year, month, day, hour, minute, second);
  else
    result = PyDateTime_FromDateAndTime(year, month, day, hour, minute, second, 0);
  
 error:
  ASN1_GENERALIZEDTIME_free(g);
  return result;
}

static ASN1_TIME *
Python_to_ASN1_TIME(PyObject *arg, const int object_requires_utctime)
{
  char buf[sizeof("20010401123456Z") + 1];
  ASN1_TIME *result = NULL;
  const char *s = NULL;
  int ok;
  
  if (PyDateTime_Check(arg)) {
    if (snprintf(buf, sizeof(buf), "%4d%02d%02d%02d%02d%02dZ", 
                 PyDateTime_GET_YEAR(arg),
                 PyDateTime_GET_MONTH(arg),
                 PyDateTime_GET_DAY(arg),
                 PyDateTime_DATE_GET_HOUR(arg),
                 PyDateTime_DATE_GET_MINUTE(arg),
                 PyDateTime_DATE_GET_SECOND(arg)) >= (int) sizeof(buf))
      lose("Internal error -- GeneralizedTime buffer too small");
    s = buf;
  }

  if (s == NULL && (s = PyString_AsString(arg)) == NULL)
    goto error;

  if (strlen(s) < 10)
    lose_type_error("String is too short to parse as a valid ASN.1 TIME");

  if ((result = ASN1_TIME_new()) == NULL)
    lose_no_memory();

  if (object_requires_utctime &&
      ((s[0] == '1' && s[1] == '9' && s[2] > '4') ||
       (s[0] == '2' && s[1] == '0' && s[2] < '5')))
    ok = ASN1_UTCTIME_set_string(result, s + 2);
  else
    ok = ASN1_GENERALIZEDTIME_set_string(result, s);

  if (ok)
    return result;

 error:
  ASN1_TIME_free(result);
  return NULL;
}

/*
 * Extract a Python string from a memory BIO.
 */
static PyObject *
BIO_to_PyString_helper(BIO *bio)
{
  char *ptr = NULL;
  Py_ssize_t len = 0;

  if ((len = BIO_get_mem_data(bio, &ptr)) == 0)
    lose_openssl_error("Unable to get BIO data");

  return Py_BuildValue("s#", ptr, len);

 error:
  return NULL;
}

static PyObject *
read_from_string_helper(PyObject *(*object_read_helper)(PyTypeObject *, BIO *),
                        PyTypeObject *type,
                        PyObject *args)
{
  PyObject *result = NULL;
  char *src = NULL;
  BIO *bio = NULL;
  Py_ssize_t len = 0;

  if (!PyArg_ParseTuple(args, "s#", &src, &len))
    goto error;

  if ((bio = BIO_new_mem_buf(src, len)) == NULL)
    lose_no_memory();

  result = object_read_helper(type, bio);

 error:
  BIO_free(bio);
  return result;
}

static PyObject *
read_from_file_helper(PyObject *(*object_read_helper)(PyTypeObject *, BIO *),
                      PyTypeObject *type,
                      PyObject *args)
{
  const char *filename = NULL;
  PyObject *result = NULL;
  BIO *bio = NULL;

  if (!PyArg_ParseTuple(args, "s", &filename))
    goto error;

  if ((bio = BIO_new_file(filename, "rb")) == NULL)
    lose_openssl_error("Could not open file");

  result = object_read_helper(type, bio);

 error:
  BIO_free(bio);
  return result;
}

/*
 * Simplify entries in method definition tables.  See the "Common
 * Object Structures" section of the API manual for available flags.
 */
#define Define_Method(__python_name__, __c_name__, __flags__) \
  { #__python_name__, (PyCFunction) __c_name__, __flags__, __c_name__##__doc__ }

#define Define_Class_Method(__python_name__, __c_name__, __flags__) \
  Define_Method(__python_name__, __c_name__, (__flags__) | METH_CLASS)

/*
 * Convert an ASN1_INTEGER into a Python integer or long.
 */
static PyObject *
ASN1_INTEGER_to_PyLong(ASN1_INTEGER *arg)
{
  PyObject *result = NULL;
  PyObject *obj = NULL;

  if ((obj = _PyLong_FromByteArray(ASN1_STRING_data(arg),
                                   ASN1_STRING_length(arg),
                                   0, 0)) != NULL)
    result = PyNumber_Int(obj);

  Py_XDECREF(obj);
  return result;
}

/*
 * Convert a Python long to an ASN1_INTEGER.
 * This is just nasty, do not read on a full stomach.
 *
 * Maximum size of integer to be converted here is taken from RFC 5280
 * 4.1.2.2, which sets a maximum of 20 octets for an X.509 certificate
 * serial number.
 *
 * In theory we could use _PyLong_NumBits() to determine the length of
 * the long before converting, and raise OverflowError if it's too big.
 * Hmm.
 */
static ASN1_INTEGER *
PyLong_to_ASN1_INTEGER(PyObject *arg)
{
  PyObject *obj = NULL;
  ASN1_INTEGER *a = NULL;
  unsigned char buf[MAX_ASN1_INTEGER_LEN];
  size_t len;

  memset(buf, 0, sizeof(buf));

  /*
   * Make sure argument is a PyLong small enough that its length (in
   * bits!)  doesn't overflow a size_t (which is a mis-use of size_t,
   * but take that up with whoever wrote _PyLong_NumBits()...).
   */
  if ((obj = PyNumber_Long(arg)) == NULL ||
      (len = _PyLong_NumBits(obj)) == (size_t) -1)
    goto error;

  /*
   * Next make sure it's a non-negative integer small enough to fit in
   * our buffer.  If we really thought we needed to support larger
   * integers we could allocate this dynamically, but we don't, so
   * it's not worth the overhead.
   *
   * Paranoia: We can't convert len to bytes yet, because that
   * requires rounding up and we don't know yet that we have enough
   * headroom to do that arithmetic without overflowing a size_t.
   */
  if (_PyLong_Sign(obj) < 0 || (len / 8) + 1 > sizeof(buf)) {
    PyErr_SetObject(PyExc_OverflowError, obj);
    goto error;
  }

  /*
   * Now that we know we're dealing with a sane number of bits,
   * convert it to bytes.
   */
  len = (len + 7) / 8;

  /*
   * Extract that many bytes.
   */
  if (_PyLong_AsByteArray((PyLongObject *) obj, buf, len, 0, 0) < 0)
    goto error;

  /*
   * We're done with the PyLong now.
   */
  Py_XDECREF(obj);
  obj = NULL;

  /*
   * Generate the ASN1_INTEGER and return it.
   */
  if ((a = ASN1_INTEGER_new()) == NULL ||
      (a->length < (int) len + 1 && (a->data = OPENSSL_realloc(a->data, len + 1)) == NULL))
    lose_no_memory();

  a->type = V_ASN1_INTEGER;
  a->length = len;
  a->data[len] = 0;
  memcpy(a->data, buf, len);

  return a;

 error:
  Py_XDECREF(obj);
  ASN1_INTEGER_free(a);
  return NULL;
}

/*
 * Handle missing NIDs.
 */

static int
create_missing_nids(void)
{
  int i;

  for (i = 0; i < (int) (sizeof(missing_nids) / sizeof(*missing_nids)); i++)
    if ((*missing_nids[i].nid = OBJ_txt2nid(missing_nids[i].oid)) == NID_undef &&
        (*missing_nids[i].nid = OBJ_create(missing_nids[i].oid,
                                           missing_nids[i].sn,
                                           missing_nids[i].ln)) == NID_undef)
      return 0;

  return 1;
}

/*
 * Convert an OpenSSL OID to a Python string.
 */

static PyObject *
ASN1_OBJECT_to_PyString(const ASN1_OBJECT *oid)
{
  PyObject *result = NULL;
  char buf[512];

  ENTERING(ASN1_OBJECT_to_PyString);

  if (OBJ_obj2txt(buf, sizeof(buf), oid, 1) <= 0)
    lose_openssl_error("Couldn't translate OID");

  result = PyString_FromString(buf);

 error:
  return result;
}

/*
 * RFC 5480 2.1.1 requires EC keys to use namedCurve rather than
 * specificCurve.  For some reason OpenSSL defaults to specificCurve,
 * and there's no function in the high-level API to change this.  So
 * this is icky, but I don't see how to do better without API support.
 *
 * This can be called on any EVP_PKEY, but only whacks EC keys, so the
 * rest of the code can just call this and not worry about what kind
 * of key it has.
 */

static void
whack_ec_key_to_namedCurve(EVP_PKEY *pkey)
{
  EC_KEY *ec_key;

  ENTERING(whack_ec_key_to_namedCurve);

  if (pkey != NULL &&
      EVP_PKEY_id(pkey) == EVP_PKEY_EC &&
      (ec_key = EVP_PKEY_get0(pkey)) != NULL)
    EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);
}



/*
 * Validation status codes.  Still under construction.  Conceptually
 * modeled after rcynic's validation status database, implementation
 * somewhat different due to language issues and desire to keep the C
 * side of this as simple as possible.  Depends on support from the
 * Python side (see rpki/POW/__init__.py).
 */

/*
 * Add code to status object, throwing an error if something goes
 * horribly wrong.
 */

#define record_validation_status(_status_, _code_)              \
  do {                                                          \
    if (!_record_validation_status(_status_, #_code_))          \
      goto error;                                               \
  } while (0)

static int
_record_validation_status(PyObject *status, const char *code)
{
  if (status == Py_None)
    return 1;
  PyObject *value = PyString_FromString(code);
  if (value == NULL)
    return 0;
  int result = PySet_Add(status, value);
  Py_XDECREF(value);
  return result == 0;
}



/*
 * Detail checking functions.  These are only used by the relying
 * party code, and only when the caller of one of the verification
 * functions has requested detailed checking by passing in a result
 * status set object.
 */

/*
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

/*
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

/*
 * Compare filename fields of two FileAndHash structures.
 */

static int check_manifest_FileAndHash_name_cmp(const FileAndHash * const *a, const FileAndHash * const *b)
{
  return strcmp((char *) (*a)->file->data, (char *) (*b)->file->data);
}

/*
 * Check a lot of pesky low-level things about RPKI CRLs.
 */

static int check_crl(X509_CRL *crl,
                     X509 *issuer,
                     PyObject *status)
{
  STACK_OF(X509_REVOKED) *revoked;
  AUTHORITY_KEYID *aki = NULL;
  EVP_PKEY *pkey;
  int i, ret = 0;

  if (crl->crl == NULL ||
      crl->crl->sig_alg == NULL || crl->crl->sig_alg->algorithm == NULL ||
      OBJ_obj2nid(crl->crl->sig_alg->algorithm) != NID_sha256WithRSAEncryption)
    record_validation_status(status, NONCONFORMANT_SIGNATURE_ALGORITHM);

  if (!check_allowed_time_encoding(X509_CRL_get_lastUpdate(crl)) ||
      !check_allowed_time_encoding(X509_CRL_get_nextUpdate(crl)))
    record_validation_status(status, NONCONFORMANT_ASN1_TIME_VALUE);

  if ((aki = X509_CRL_get_ext_d2i(crl, NID_authority_key_identifier, NULL, NULL)) == NULL)
    record_validation_status(status, AKI_EXTENSION_MISSING);
  else if (aki->keyid == NULL || aki->serial != NULL || aki->issuer != NULL)
    record_validation_status(status, AKI_EXTENSION_WRONG_FORMAT);

  if (X509_CRL_get_ext_count(crl) > 2)
    record_validation_status(status, DISALLOWED_X509V3_EXTENSION);

  if (!check_allowed_dn(X509_CRL_get_issuer(crl)))
    record_validation_status(status, NONCONFORMANT_ISSUER_NAME);

  if ((revoked = X509_CRL_get_REVOKED(crl)) != NULL)
    for (i = sk_X509_REVOKED_num(revoked) - 1; i >= 0; --i)
      if (X509_REVOKED_get_ext_count(sk_X509_REVOKED_value(revoked, i)) > 0)
        record_validation_status(status, DISALLOWED_X509V3_EXTENSION);

  if ((pkey = X509_get_pubkey(issuer)) != NULL) {
    ret = X509_CRL_verify(crl, pkey) > 0;
    EVP_PKEY_free(pkey);
  }

 error:
  AUTHORITY_KEYID_free(aki);
  return ret;
}

/*
 * Extract one datum from a CMS_SignerInfo.
 */

static void *extract_si_datum(CMS_SignerInfo *si,
			      int *n,
			      const int optional,
			      const int nid,
			      const int asn1_type)
{
  int i = CMS_signed_get_attr_by_NID(si, nid, -1);
  void *result = NULL;
  X509_ATTRIBUTE *a;

  if (i < 0 && optional)
    return NULL;

  if (i >= 0 &&
      CMS_signed_get_attr_by_NID(si, nid, i) < 0 &&
      (a = CMS_signed_get_attr(si, i)) != NULL &&
      X509_ATTRIBUTE_count(a) == 1 &&
      (result = X509_ATTRIBUTE_get0_data(a, 0, asn1_type, NULL)) != NULL)
    --*n;
  else
    *n = -1;

  return result;
}

/*
 * Check a lot of pesky low-level things about RPKI CMS objects.
 *
 * We already have code elsewhere for checking X.509 certificates, so
 * we assume that the caller has already used use that code to check
 * the embedded EE certificate.
 */

static int check_cms(CMS_ContentInfo *cms,
                     PyObject *status)
{
  STACK_OF(CMS_SignerInfo) *signer_infos = NULL;
  CMS_SignerInfo *si = NULL;
  ASN1_OCTET_STRING *sid = NULL;
  X509_NAME *si_issuer = NULL;
  ASN1_INTEGER *si_serial = NULL;
  STACK_OF(X509_CRL) *crls = NULL;
  STACK_OF(X509) *certs = NULL;
  X509_ALGOR *signature_alg = NULL, *digest_alg = NULL;
  ASN1_OBJECT *oid = NULL;
  X509 *x = NULL;
  int i, ret = 0;

  if ((crls = CMS_get1_crls(cms)) != NULL)
    record_validation_status(status, CMS_INCLUDES_CRLS);

  if ((signer_infos = CMS_get0_SignerInfos(cms)) == NULL ||
      sk_CMS_SignerInfo_num(signer_infos) != 1 ||
      (si = sk_CMS_SignerInfo_value(signer_infos, 0)) == NULL ||
      !CMS_SignerInfo_get0_signer_id(si, &sid, &si_issuer, &si_serial) ||
      sid == NULL || si_issuer != NULL || si_serial != NULL ||
      CMS_unsigned_get_attr_count(si) != -1)
    record_validation_status(status, BAD_CMS_SIGNER_INFOS);

  if (si != NULL)
    CMS_SignerInfo_get0_algs(si, NULL, &x, &digest_alg, &signature_alg);

  if (x == NULL)
    record_validation_status(status, CMS_SIGNER_MISSING);
  else if ((certs = CMS_get1_certs(cms)) == NULL ||
      sk_X509_num(certs) != 1 ||
      X509_cmp(x, sk_X509_value(certs, 0)))
    record_validation_status(status, BAD_CMS_SIGNER);

  X509_ALGOR_get0(&oid, NULL, NULL, signature_alg);
  i = OBJ_obj2nid(oid);
  if (i != NID_sha256WithRSAEncryption && i != NID_rsaEncryption)
    record_validation_status(status, WRONG_CMS_SI_SIGNATURE_ALGORITHM);

  X509_ALGOR_get0(&oid, NULL, NULL, digest_alg);
  if (OBJ_obj2nid(oid) != NID_sha256)
    record_validation_status(status, WRONG_CMS_SI_DIGEST_ALGORITHM);

  i = CMS_signed_get_attr_count(si);

  (void) extract_si_datum(si, &i, 1, NID_pkcs9_signingTime,   V_ASN1_UTCTIME);
  (void) extract_si_datum(si, &i, 1, NID_binary_signing_time, V_ASN1_INTEGER);
  oid =  extract_si_datum(si, &i, 0, NID_pkcs9_contentType,   V_ASN1_OBJECT);
  (void) extract_si_datum(si, &i, 0, NID_pkcs9_messageDigest, V_ASN1_OCTET_STRING);

  if (i != 0)
    record_validation_status(status, BAD_CMS_SI_SIGNED_ATTRIBUTES);

  if (OBJ_cmp(oid, CMS_get0_eContentType(cms)) != 0)
    record_validation_status(status, BAD_CMS_SI_CONTENTTYPE);

  if (si != NULL && x != NULL && CMS_SignerInfo_cert_cmp(si, x))
    record_validation_status(status, CMS_SKI_MISMATCH);

  ret = 1;

 error:
  sk_X509_CRL_pop_free(crls, X509_CRL_free);
  sk_X509_pop_free(certs, X509_free);

  return ret;
}

/*
 * Check a lot of pesky low-level things about RPKI manifests.
 */

#warning Almost everything in this function could be done in Python

static int check_manifest(CMS_ContentInfo *cms,
                          Manifest *manifest,
                          PyObject *status)
{
  STACK_OF(FileAndHash) *sorted_fileList = NULL;
  FileAndHash *fah1 = NULL, *fah2 = NULL;
  STACK_OF(X509) *certs = NULL;
  int i, ret = 0;

  if (manifest == NULL)
    lose_not_verified("Can't check an unverified manifest");

  if (OBJ_obj2nid(CMS_get0_eContentType(cms)) != NID_ct_rpkiManifest)
    record_validation_status(status, BAD_CMS_ECONTENTTYPE);

#warning Can check value in Python, but not whether encoding was defaulted
  if (manifest->version)
    record_validation_status(status, WRONG_OBJECT_VERSION);

  if ((certs = CMS_get1_certs(cms)) == NULL || sk_X509_num(certs) != 1)
    record_validation_status(status, BAD_CMS_SIGNER);

  if (ASN1_INTEGER_cmp(manifest->manifestNumber, asn1_zero) < 0 ||
      ASN1_INTEGER_cmp(manifest->manifestNumber, asn1_twenty_octets) > 0)
    record_validation_status(status, BAD_MANIFEST_NUMBER);

  if (OBJ_obj2nid(manifest->fileHashAlg) != NID_sha256)
    record_validation_status(status, NONCONFORMANT_DIGEST_ALGORITHM);

  if ((sorted_fileList = sk_FileAndHash_dup(manifest->fileList)) == NULL)
    lose_no_memory();

  (void) sk_FileAndHash_set_cmp_func(sorted_fileList, check_manifest_FileAndHash_name_cmp);
  sk_FileAndHash_sort(sorted_fileList);

  for (i = 0; ((fah1 = sk_FileAndHash_value(sorted_fileList, i + 0)) != NULL &&
               (fah2 = sk_FileAndHash_value(sorted_fileList, i + 1)) != NULL); i++)
    if (!strcmp((char *) fah1->file->data, (char *) fah2->file->data))
      record_validation_status(status, DUPLICATE_NAME_IN_MANIFEST);

  for (i = 0; (fah1 = sk_FileAndHash_value(manifest->fileList, i)) != NULL; i++)
    if (fah1->hash->length != HASH_SHA256_LEN ||
	(fah1->hash->flags & (ASN1_STRING_FLAG_BITS_LEFT | 7)) > ASN1_STRING_FLAG_BITS_LEFT)
      record_validation_status(status, BAD_MANIFEST_DIGEST_LENGTH);

  ret = 1;

 error:
  sk_FileAndHash_free(sorted_fileList);
  sk_X509_pop_free(certs, X509_free);

  return ret;
}

/*
 * Extract a ROA prefix from the ASN.1 bitstring encoding.
 */
static int check_roa_extract_roa_prefix(const ROAIPAddress *ra,
                                        const unsigned afi,
                                        unsigned char *addr,
                                        unsigned *prefixlen,
                                        unsigned *max_prefixlen)
{
  unsigned length;
  long maxlen;

  assert(ra && addr && prefixlen && max_prefixlen);

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
  *max_prefixlen = ra->maxLength ? (unsigned) maxlen : *prefixlen;

  return 1;
}

/*
 * Check a lot of pesky low-level things about RPKI ROAs.
 */

static int check_roa(CMS_ContentInfo *cms,
                     ROA *roa,
                     PyObject *status)
{
  STACK_OF(IPAddressFamily) *roa_resources = NULL, *ee_resources = NULL;
  unsigned afi, *safi = NULL, safi_, prefixlen, max_prefixlen;
  unsigned char addrbuf[RAW_IPADDR_BUFLEN];
  STACK_OF(X509) *certs = NULL;
  ROAIPAddressFamily *rf;
  ROAIPAddress *ra;
  int i, j, result = 0;

  if (roa == NULL)
    lose_not_verified("Can't check an unverified ROA");

#warning Could be done in Python
  if (OBJ_obj2nid(CMS_get0_eContentType(cms)) != NID_ct_ROA)
    record_validation_status(status, BAD_CMS_ECONTENTTYPE);

  if (roa->version)
    record_validation_status(status, WRONG_OBJECT_VERSION);

#warning Could be done in Python
  if (ASN1_INTEGER_cmp(roa->asID, asn1_zero) < 0 ||
      ASN1_INTEGER_cmp(roa->asID, asn1_four_octets) > 0)
    record_validation_status(status, BAD_ROA_ASID);

#warning Could be done in Python
  if ((certs = CMS_get1_certs(cms)) == NULL || sk_X509_num(certs) != 1)
    record_validation_status(status, BAD_CMS_SIGNER);

  if ((ee_resources = X509_get_ext_d2i(sk_X509_value(certs, 0), NID_sbgp_ipAddrBlock, NULL, NULL)) == NULL)
    record_validation_status(status, BAD_IPADDRBLOCKS);

  /*
   * Convert ROA prefixes to resource set.  This goes on a bit.
   */

  if ((roa_resources = sk_IPAddressFamily_new_null()) == NULL)
    lose_no_memory();

  for (i = 0; i < sk_ROAIPAddressFamily_num(roa->ipAddrBlocks); i++) {
    rf = sk_ROAIPAddressFamily_value(roa->ipAddrBlocks, i);

    if (rf == NULL || rf->addressFamily == NULL)
      lose_no_memory();

    if (rf->addressFamily->length < 2 || rf->addressFamily->length > 3)
      record_validation_status(status, MALFORMED_ROA_ADDRESSFAMILY);

    afi = (rf->addressFamily->data[0] << 8) | (rf->addressFamily->data[1]);
    if (rf->addressFamily->length == 3)
      *(safi = &safi_) = rf->addressFamily->data[2];

    for (j = 0; j < sk_ROAIPAddress_num(rf->addresses); j++) {
      ra = sk_ROAIPAddress_value(rf->addresses, j);

      if (ra == NULL ||
	  !check_roa_extract_roa_prefix(ra, afi, addrbuf, &prefixlen, &max_prefixlen) ||
	  !v3_addr_add_prefix(roa_resources, afi, safi, addrbuf, prefixlen))
        record_validation_status(status, ROA_RESOURCES_MALFORMED);

      else if (max_prefixlen < prefixlen)
        record_validation_status(status, ROA_MAX_PREFIXLEN_TOO_SHORT);
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

    if ((afi = v3_addr_get_afi(f)) == 0)
      record_validation_status(status, ROA_CONTAINS_BAD_AFI_VALUE);

    if (f->ipAddressChoice->type == IPAddressChoice_addressesOrRanges) {
      IPAddressOrRanges *aors = f->ipAddressChoice->u.addressesOrRanges;

      sk_IPAddressOrRange_sort(aors);

      for (j = 0; j < sk_IPAddressOrRange_num(aors) - 1; j++) {
	IPAddressOrRange *a = sk_IPAddressOrRange_value(aors, j);
	IPAddressOrRange *b = sk_IPAddressOrRange_value(aors, j + 1);
	unsigned char a_min[RAW_IPADDR_BUFLEN], a_max[RAW_IPADDR_BUFLEN];
	unsigned char b_min[RAW_IPADDR_BUFLEN], b_max[RAW_IPADDR_BUFLEN];
	int a_len, b_len;

	if ((a_len = v3_addr_get_range(a, afi, a_min, a_max, RAW_IPADDR_BUFLEN)) == 0 ||
	    (b_len = v3_addr_get_range(b, afi, b_min, b_max, RAW_IPADDR_BUFLEN)) == 0 ||
            a_len != b_len)
          record_validation_status(status, ROA_RESOURCES_MALFORMED);

	if (memcmp(a_max, b_max, a_len) >= 0) {
	  (void) sk_IPAddressOrRange_delete(aors, j + 1);
	  IPAddressOrRange_free(b);
	  --j;
	}
      }
    }
  }

  if (!v3_addr_canonize(roa_resources))
    record_validation_status(status, ROA_RESOURCES_MALFORMED);

  if (ee_resources == NULL || !v3_addr_subset(roa_resources, ee_resources))
    record_validation_status(status, ROA_RESOURCE_NOT_IN_EE);

  result = 1;

 error:
  sk_IPAddressFamily_pop_free(roa_resources, IPAddressFamily_free);
  sk_IPAddressFamily_pop_free(ee_resources, IPAddressFamily_free);
  sk_X509_pop_free(certs, X509_free);

  return result;
}



/*
 * Extension functions.
 */

#define EXTENSION_GET_KEY_USAGE__DOC__                                  \
  "Return a FrozenSet of strings representing the KeyUsage settings\n"  \
  "for this object, or None if the object has no KeyUsage\n"            \
  "extension.  The bits have the same names as in RFC 5280.\n"

static PyObject *
extension_get_key_usage(X509_EXTENSION *ext_)
{
  ASN1_BIT_STRING *ext = NULL;
  PyObject *result = NULL;
  PyObject *token = NULL;
  int bit = -1;

  ENTERING(extension_get_key_usage);

  if (!ext_)
    Py_RETURN_NONE;

  if ((ext = X509V3_EXT_d2i(ext_)) == NULL)
    lose_openssl_error("Couldn't parse KeyUsage extension");

  if ((result = PyFrozenSet_New(NULL)) == NULL)
    goto error;

  for (bit = 0; key_usage_bit_names[bit] != NULL; bit++) {
    if (ASN1_BIT_STRING_get_bit(ext, bit) &&
        ((token = PyString_FromString(key_usage_bit_names[bit])) == NULL ||
         PySet_Add(result, token) < 0))
      goto error;
    Py_XDECREF(token);
    token = NULL;
  }

  ASN1_BIT_STRING_free(ext);
  return result;

 error:
  ASN1_BIT_STRING_free(ext);
  Py_XDECREF(token);
  Py_XDECREF(result);
  return NULL;
}

#define EXTENSION_SET_KEY_USAGE__DOC__							\
  "Argument \"iterable\" should be an iterable object which returns zero or more\n"     \
  "strings naming bits to be enabled.  The bits have the same names as in RFC 5280.\n"  \
  "\n"                                                                                  \
  "Optional argument \"critical\" is a boolean indicating whether the extension\n"      \
  "should be marked as critical or not.  RFC 5280 4.2.1.3 says this extension SHOULD\n" \
  "be marked as critical when used, so the default is True.\n"

static void
extension_set_key_usage_destructor(void *value)
{
  ASN1_BIT_STRING_free(value);
}

static extension_wrapper
extension_set_key_usage(PyObject *args)
{
  ASN1_BIT_STRING *ext = NULL;
  PyObject *iterable = NULL;
  PyObject *critical = Py_True;
  PyObject *iterator = NULL;
  PyObject *item = NULL;
  const char *token;
  int bit = -1;

  extension_wrapper result = {extension_set_key_usage_destructor};

  ENTERING(extension_set_key_usage);

  if ((ext = ASN1_BIT_STRING_new()) == NULL)
    lose_no_memory();

  if (!PyArg_ParseTuple(args, "O|O", &iterable, &critical) ||
      (iterator = PyObject_GetIter(iterable)) == NULL)
    goto error;

  while ((item = PyIter_Next(iterator)) != NULL) {

    if ((token = PyString_AsString(item)) == NULL)
      goto error;

    for (bit = 0; key_usage_bit_names[bit] != NULL; bit++)
      if (!strcmp(token, key_usage_bit_names[bit]))
        break;

    if (key_usage_bit_names[bit] == NULL)
      lose("Unrecognized KeyUsage token");

    if (!ASN1_BIT_STRING_set_bit(ext, bit, 1))
      lose_no_memory();

    Py_XDECREF(item);
    item = NULL;
  }

  result.value = ext;
  result.nid = NID_key_usage;
  result.critical = PyObject_IsTrue(critical);
  ext = NULL;

 error:                         /* Fall through */
  ASN1_BIT_STRING_free(ext);
  Py_XDECREF(iterator);
  Py_XDECREF(item);
  return result;
}

#define EXTENSION_GET_BASIC_CONSTRAINTS__DOC__                                  \
  "If there is no BasicConstraints extension, this method returns None.\n"      \
  "\n"                                                                          \
  "Otherwise, this method returns a two-element tuple.  The first element\n"    \
  "of the tuple is a boolean representing the extension's cA value; the\n"      \
  "second element of the tuple is either an integer representing the\n"         \
  "pathLenConstraint value or None if there is no pathLenConstraint.\n"

static PyObject *
extension_get_basic_constraints(X509_EXTENSION *ext_)
{
  BASIC_CONSTRAINTS *ext = NULL;
  PyObject *result = NULL;

  ENTERING(extension_get_basic_constraints);

  if (!ext_)
    Py_RETURN_NONE;

  if ((ext = X509V3_EXT_d2i(ext_)) == NULL)
    lose_openssl_error("Couldn't parse BasicConstraints extension");

  if (ext->pathlen == NULL)
    result = Py_BuildValue("(NO)", PyBool_FromLong(ext->ca), Py_None);
  else
    result = Py_BuildValue("(Nl)", PyBool_FromLong(ext->ca), ASN1_INTEGER_get(ext->pathlen));

 error:
  BASIC_CONSTRAINTS_free(ext);
  return result;
}

#define EXTENSION_SET_BASIC_CONSTRAINTS__DOC__                                  \
  "First argument \"ca\" is a boolean indicating whether the certificate\n"     \
  "is a CA certificate or not.\n"                                               \
  "\n"                                                                          \
  "Optional second argument \"pathLenConstraint\" is a non-negative integer\n"  \
  "specifying the pathLenConstraint value for this certificate; this value\n"   \
  "may only be set for CA certificates."                                        \
  "\n"                                                                          \
  "Optional third argument \"critical\" specifies whether the extension\n"      \
  "should be marked as critical.  RFC 5280 4.2.1.9 requires that CA\n"          \
  "certificates mark this extension as critical, so the default is True.\n"

static void
extension_set_basic_constraints_destructor(void *value)
{
  BASIC_CONSTRAINTS_free(value);
}

static extension_wrapper
extension_set_basic_constraints(PyObject *args)
{
  BASIC_CONSTRAINTS *ext = NULL;
  PyObject *is_ca = NULL;
  PyObject *pathlen_obj = Py_None;
  PyObject *critical = Py_True;
  long pathlen = -1;

  extension_wrapper result = {extension_set_basic_constraints_destructor};

  ENTERING(extension_set_basic_constraints);

  if (!PyArg_ParseTuple(args, "O|OO", &is_ca, &pathlen_obj, &critical))
    goto error;

  if (pathlen_obj != Py_None && (pathlen = PyInt_AsLong(pathlen_obj)) < 0)
    lose_value_error("Bad pathLenConstraint value");

  if ((ext = BASIC_CONSTRAINTS_new()) == NULL)
    lose_no_memory();

  ext->ca = PyObject_IsTrue(is_ca) ? 0xFF : 0;

  if (pathlen_obj != Py_None &&
      ((ext->pathlen == NULL && (ext->pathlen = ASN1_INTEGER_new()) == NULL) ||
       !ASN1_INTEGER_set(ext->pathlen, pathlen)))
    lose_no_memory();

  result.value = ext;
  result.nid = NID_basic_constraints;
  result.critical = PyObject_IsTrue(critical);
  ext = NULL;

 error:                         /* Fall through */
  BASIC_CONSTRAINTS_free(ext);
  return result;
}

#define	EXTENSION_GET_SIA__DOC__                                                \
  "If there is no SIA extension, this method returns None.\n"                   \
  "\n"                                                                          \
  "Otherwise, it returns a tuple containing four values:\n"                     \
  "caRepository URIs, rpkiManifest URIs, signedObject, and rpkiNotify URIs.\n"  \
  "Each of these values is a tuple of strings, representing an ordered\n"       \
  "sequence of URIs.  Any or all of these sequences may be empty.\n"            \
  "\n"                                                                          \
  "Any other accessMethods are ignored, as are any non-URI accessLocations.\n"

static PyObject *
extension_get_sia(X509_EXTENSION *ext_)
{
  AUTHORITY_INFO_ACCESS *ext = NULL;
  PyObject *result = NULL;
  PyObject *result_caRepository = NULL;
  PyObject *result_rpkiManifest = NULL;
  PyObject *result_signedObject = NULL;
  PyObject *result_rpkiNotify   = NULL;
  int n_caRepository = 0;
  int n_rpkiManifest = 0;
  int n_signedObject = 0;
  int n_rpkiNotify   = 0;
  const char *uri;
  PyObject *obj;
  int i, nid;

  ENTERING(extension_get_sia);

  if (!ext_)
    Py_RETURN_NONE;

  if ((ext = X509V3_EXT_d2i(ext_)) == NULL)
    lose_openssl_error("Couldn't parse SubjectInformationAccess extension");

  /*
   * Easiest to do this in two passes, first pass just counts URIs.
   */

  for (i = 0; i < sk_ACCESS_DESCRIPTION_num(ext); i++) {
    ACCESS_DESCRIPTION *a = sk_ACCESS_DESCRIPTION_value(ext, i);
    if (a->location->type != GEN_URI)
      continue;
    nid = OBJ_obj2nid(a->method);
    if (nid == NID_caRepository)
      n_caRepository++;
    else if (nid == NID_ad_rpkiManifest)
      n_rpkiManifest++;
    else if (nid == NID_ad_signedObject)
      n_signedObject++;
    else if (nid == NID_ad_rpkiNotify)
      n_rpkiNotify++;
  }

  if (((result_caRepository = PyTuple_New(n_caRepository)) == NULL) ||
      ((result_rpkiManifest = PyTuple_New(n_rpkiManifest)) == NULL) ||
      ((result_signedObject = PyTuple_New(n_signedObject)) == NULL) ||
      ((result_rpkiNotify   = PyTuple_New(n_rpkiNotify))   == NULL))
    goto error;

  n_caRepository = n_rpkiManifest = n_signedObject = n_rpkiNotify = 0;

  for (i = 0; i < sk_ACCESS_DESCRIPTION_num(ext); i++) {
    ACCESS_DESCRIPTION *a = sk_ACCESS_DESCRIPTION_value(ext, i);
    if (a->location->type != GEN_URI)
      continue;
    nid = OBJ_obj2nid(a->method);
    uri = (char *) ASN1_STRING_data(a->location->d.uniformResourceIdentifier);
    if (nid == NID_caRepository) {
      if ((obj = PyString_FromString(uri)) == NULL)
        goto error;
      PyTuple_SET_ITEM(result_caRepository, n_caRepository++, obj);
      continue;
    }
    if (nid == NID_ad_rpkiManifest) {
      if ((obj = PyString_FromString(uri)) == NULL)
        goto error;
      PyTuple_SET_ITEM(result_rpkiManifest, n_rpkiManifest++, obj);
      continue;
    }
    if (nid == NID_ad_signedObject) {
      if ((obj = PyString_FromString(uri)) == NULL)
        goto error;
      PyTuple_SET_ITEM(result_signedObject, n_signedObject++, obj);
      continue;
    }
    if (nid == NID_ad_rpkiNotify) {
      if ((obj = PyString_FromString(uri)) == NULL)
        goto error;
      PyTuple_SET_ITEM(result_rpkiNotify, n_rpkiNotify++, obj);
      continue;
    }
  }

  result = Py_BuildValue("(OOOO)",
                         result_caRepository,
                         result_rpkiManifest,
                         result_signedObject,
                         result_rpkiNotify);

 error:
  AUTHORITY_INFO_ACCESS_free(ext);
  Py_XDECREF(result_caRepository);
  Py_XDECREF(result_rpkiManifest);
  Py_XDECREF(result_signedObject);
  Py_XDECREF(result_rpkiNotify);
  return result;
}

#define EXTENSION_SET_SIA__DOC__                                        \
  "This method takes four arguments: \"caRepository\"\n,"               \
  "\"rpkiManifest\", \"signedObject\", and \"rpkiNotify\".\n"           \
  "Each of these should be an iterable which returns URIs.\n"           \
  "\n"                                                                  \
  "None is acceptable as an alternate way of specifying an empty\n"     \
  "collection of URIs for a particular argument.\n"

static void
extension_set_sia_destructor(void *value)
{
  AUTHORITY_INFO_ACCESS_free(value);
}

static extension_wrapper
extension_set_sia(PyObject *args, PyObject *kwds)
{
  static char *kwlist[] = {"caRepository", "rpkiManifest", "signedObject", "rpkiNotify", NULL};
  AUTHORITY_INFO_ACCESS *ext = NULL;
  PyObject *caRepository = Py_None;
  PyObject *rpkiManifest = Py_None;
  PyObject *signedObject = Py_None;
  PyObject *rpkiNotify   = Py_None;
  PyObject *iterator = NULL;
  ASN1_OBJECT *oid = NULL;
  PyObject **pobj = NULL;
  PyObject *item = NULL;
  ACCESS_DESCRIPTION *a = NULL;
  int i, nid = NID_undef;
  Py_ssize_t urilen;
  char *uri;

  extension_wrapper result = {extension_set_sia_destructor};

  ENTERING(extension_set_sia);

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "|OOOO", kwlist,
                                   &caRepository, &rpkiManifest, &signedObject, &rpkiNotify))
    goto error;

  if ((ext = AUTHORITY_INFO_ACCESS_new()) == NULL)
    lose_no_memory();

  /*
   * This is going to want refactoring, because it's ugly, because we
   * want to reuse code for AIA, and because it'd be nice to support a
   * single URI as an abbreviation for a collection containing one URI.
   */

  for (i = 0; i < 4; i++) {
    switch (i) {
    case 0: pobj = &caRepository; nid = NID_caRepository;    break;
    case 1: pobj = &rpkiManifest; nid = NID_ad_rpkiManifest; break;
    case 2: pobj = &signedObject; nid = NID_ad_signedObject; break;
    case 3: pobj = &rpkiNotify;   nid = NID_ad_rpkiNotify;   break;
    }

    if (*pobj == Py_None)
      continue;

    if ((oid = OBJ_nid2obj(nid)) == NULL)
      lose_openssl_error("Couldn't find SIA accessMethod OID");

    if ((iterator = PyObject_GetIter(*pobj)) == NULL)
      goto error;

    while ((item = PyIter_Next(iterator)) != NULL) {

      if (PyString_AsStringAndSize(item, &uri, &urilen) < 0)
        goto error;

      if ((a = ACCESS_DESCRIPTION_new()) == NULL ||
          (a->method = OBJ_dup(oid)) == NULL ||
          (a->location->d.uniformResourceIdentifier = ASN1_IA5STRING_new()) == NULL ||
          !ASN1_OCTET_STRING_set(a->location->d.uniformResourceIdentifier,
                                 (unsigned char *) uri, urilen))
        lose_no_memory();

      a->location->type = GEN_URI;

      if (!sk_ACCESS_DESCRIPTION_push(ext, a))
        lose_no_memory();

      a = NULL;
      Py_XDECREF(item);
      item = NULL;
    }

    Py_XDECREF(iterator);
    iterator = NULL;
  }

  result.value = ext;
  result.nid = NID_sinfo_access;
  result.critical = 0;
  ext = NULL;

 error:                         /* Fall through */
  AUTHORITY_INFO_ACCESS_free(ext);
  ACCESS_DESCRIPTION_free(a);
  Py_XDECREF(item);
  Py_XDECREF(iterator);
  return result;
}

#define EXTENSION_GET_EKU__DOC__                                                \
  "Return a FrozenSet of object identifiers representing the\n"                 \
  "ExtendedKeyUsage settings for this object, or None if the object\n"          \
  "has no ExtendedKeyUsage extension.\n"

static PyObject *
extension_get_eku(X509_EXTENSION *ext_)
{
  EXTENDED_KEY_USAGE *ext = NULL;
  PyObject *result = NULL;
  PyObject *oid = NULL;
  int i;

  ENTERING(extension_get_eku);

  if (!ext_)
    Py_RETURN_NONE;

  if ((ext = X509V3_EXT_d2i(ext_)) == NULL)
    lose_openssl_error("Couldn't parse ExtendedKeyUsage extension");

  if ((result = PyFrozenSet_New(NULL)) == NULL)
    goto error;

  for (i = 0; i < sk_ASN1_OBJECT_num(ext); i++) {
    if ((oid = ASN1_OBJECT_to_PyString(sk_ASN1_OBJECT_value(ext, i))) == NULL ||
        PySet_Add(result, oid) < 0)
      goto error;
    Py_XDECREF(oid);
    oid = NULL;
  }

  sk_ASN1_OBJECT_pop_free(ext, ASN1_OBJECT_free);
  return result;

 error:
  sk_ASN1_OBJECT_pop_free(ext, ASN1_OBJECT_free);
  Py_XDECREF(oid);
  Py_XDECREF(result);
  return NULL;
}

#define EXTENSION_SET_EKU__DOC__                                                        \
  "Argument \"iterable\" should be an iterable object which returns one or more\n"      \
  "object identifiers.\n"                                                               \
  "\n"                                                                                  \
  "Optional argument \"critical\" is a boolean indicating whether the extension\n"      \
  "should be marked as critical or not.  RFC 6487 4.8.5 says this extension\n"          \
  "MUST NOT be marked as non-critical when used, so the default is False.\n"

static void
extension_set_eku_destructor(void *value)
{
  sk_ASN1_OBJECT_pop_free(value, ASN1_OBJECT_free);
}

static extension_wrapper
extension_set_eku(PyObject *args)
{
  EXTENDED_KEY_USAGE *ext = NULL;
  PyObject *iterable = NULL;
  PyObject *critical = Py_False;
  PyObject *iterator = NULL;
  PyObject *item = NULL;
  ASN1_OBJECT *obj = NULL;
  const char *txt;

  extension_wrapper result = {extension_set_eku_destructor};

  ENTERING(extension_set_eku);

  if ((ext = sk_ASN1_OBJECT_new_null()) == NULL)
    lose_no_memory();

  if (!PyArg_ParseTuple(args, "O|O", &iterable, &critical) ||
      (iterator = PyObject_GetIter(iterable)) == NULL)
    goto error;

  while ((item = PyIter_Next(iterator)) != NULL) {

    if ((txt = PyString_AsString(item)) == NULL)
      goto error;

    if ((obj = OBJ_txt2obj(txt, 1)) == NULL)
      lose("Couldn't parse OID");
    
    if (!sk_ASN1_OBJECT_push(ext, obj))
      lose_no_memory();

    obj = NULL;
    Py_XDECREF(item);
    item = NULL;
  }

  if (sk_ASN1_OBJECT_num(ext) < 1)
    lose("Empty ExtendedKeyUsage extension");

  result.value = ext;
  result.nid = NID_ext_key_usage;
  result.critical = PyObject_IsTrue(critical);
  ext = NULL;

 error:                         /* Fall through */
  sk_ASN1_OBJECT_pop_free(ext, ASN1_OBJECT_free);
  Py_XDECREF(item);
  Py_XDECREF(iterator);
  return result;
}

#define EXTENSION_GET_SKI__DOC__                                        \
  "Return the Subject Key Identifier (SKI) value for this object,\n"    \
  "or None if the object has no SKI extension.\n"

static PyObject *
extension_get_ski(X509_EXTENSION *ext_)
{
  ASN1_OCTET_STRING *ext = NULL;
  PyObject *result = NULL;

  ENTERING(extension_get_ski);

  if (!ext_)
    Py_RETURN_NONE;

  if ((ext = X509V3_EXT_d2i(ext_)) == NULL)
    lose_openssl_error("Couldn't parse SubjectKeyIdentifier extension");

  result = Py_BuildValue("s#", ASN1_STRING_data(ext),
                         (Py_ssize_t) ASN1_STRING_length(ext));

 error:                         /* Fall through */
  ASN1_OCTET_STRING_free(ext);
  return result;
}

#define EXTENSION_SET_SKI__DOC__                                                \
  "Set the Subject Key Identifier (SKI) value for this object.\n"

static void
extension_set_ski_destructor(void *value)
{
  ASN1_OCTET_STRING_free(value);
}

static extension_wrapper
extension_set_ski(PyObject *args)
{
  ASN1_OCTET_STRING *ext = NULL;
  const unsigned char *buf = NULL;
  Py_ssize_t len;

  extension_wrapper result = {extension_set_ski_destructor};

  ENTERING(extension_set_ski);

  if (!PyArg_ParseTuple(args, "s#", &buf, &len))
    goto error;

  if ((ext = ASN1_OCTET_STRING_new()) == NULL ||
      !ASN1_OCTET_STRING_set(ext, buf, len))
    lose_no_memory();

  /*
   * RFC 5280 says this MUST be non-critical.
   */

  result.value = ext;
  result.nid = NID_subject_key_identifier;
  result.critical = 0;
  ext = NULL;

 error:
  ASN1_OCTET_STRING_free(ext);
  return result;
}

#define EXTENSION_GET_AKI__DOC__                                                \
  "Return the Authority Key Identifier (AKI) keyid value for this object,\n"    \
  "or None if the object  has no AKI extension or has an AKI extension with\n"  \
  "no keyIdentifier value.\n"

static PyObject *
extension_get_aki(X509_EXTENSION *ext_)
{
  AUTHORITY_KEYID *ext = NULL;
  PyObject *result = NULL;

  ENTERING(extension_get_aki);

  if (!ext_)
    Py_RETURN_NONE;

  if ((ext = X509V3_EXT_d2i(ext_)) == NULL)
    lose_openssl_error("Couldn't parse AuthorityKeyIdentifier extension");

  result = Py_BuildValue("s#", ASN1_STRING_data(ext->keyid),
                         (Py_ssize_t) ASN1_STRING_length(ext->keyid));

 error:                         /* Fall through */
  AUTHORITY_KEYID_free(ext);
  return result;
}

#define EXTENSION_SET_AKI__DOC__                                                \
  "Set the Authority Key Identifier (AKI) value for this object.\n"             \
  "\n"                                                                          \
  "We only support the keyIdentifier method, as that's the only form\n"         \
  "which is legal for RPKI certificates.\n"

static void
extension_set_aki_destructor(void *value)
{
  AUTHORITY_KEYID_free(value);
}

static extension_wrapper
extension_set_aki(PyObject *args)
{
  AUTHORITY_KEYID *ext = NULL;
  const unsigned char *buf = NULL;
  Py_ssize_t len;

  extension_wrapper result = {extension_set_aki_destructor};

  ENTERING(extension_set_aki);

  assert (exts);

  if (!PyArg_ParseTuple(args, "s#", &buf, &len))
    goto error;

  if ((ext = AUTHORITY_KEYID_new()) == NULL ||
      (ext->keyid == NULL && (ext->keyid = ASN1_OCTET_STRING_new()) == NULL) ||
      !ASN1_OCTET_STRING_set(ext->keyid, buf, len))
    lose_no_memory();

  /*
   * RFC 5280 says this MUST be non-critical.
   */

  result.value = ext;
  result.nid = NID_authority_key_identifier;
  result.critical = 0;
  ext = NULL;

 error:
  AUTHORITY_KEYID_free(ext);
  return result;
}



/*
 * IPAddress object.
 */

static PyObject *
ipaddress_object_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  static char *kwlist[] = {"initializer", "version", NULL};
  ipaddress_object *self = NULL;
  PyObject *init = NULL;
  PyObject *pylong = NULL;
  int version = 0;
  const char *s = NULL;
  int v;

  ENTERING(ipaddress_object_new);

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|i", kwlist, &init, &version) ||
      (self = (ipaddress_object *) type->tp_alloc(type, 0)) == NULL)
    goto error;

  if (POW_IPAddress_Check(init)) {
    ipaddress_object *src = (ipaddress_object *) init;
    memcpy(self->address, src->address, sizeof(self->address));
    self->type = src->type;
    return (PyObject *) self;
  }

  if ((s = PyString_AsString(init)) == NULL)
    PyErr_Clear();
  else if (version == 0)
    version = strchr(s, ':') ? 6 : 4;

  self->type = NULL;

  for (v = 0; v < (int) (sizeof(ipaddress_versions)/sizeof(*ipaddress_versions)); v++)
    if ((unsigned) version == ipaddress_versions[v]->version)
      self->type = ipaddress_versions[v];

  if (self->type == NULL)
    lose("Unknown IP version number");

  if (s != NULL) {
    if (inet_pton(self->type->af, s, self->address) <= 0)
      lose("Couldn't parse IP address");
    return (PyObject *) self;
  }

  if ((pylong = PyNumber_Long(init)) != NULL) {
    if (_PyLong_AsByteArray((PyLongObject *) pylong, self->address, self->type->length, 0, 0) < 0)
      goto error;
    Py_XDECREF(pylong);
    return (PyObject *) self;
  }

  lose_type_error("Couldn't convert initializer to IPAddress");

 error:
  Py_XDECREF(self);
  Py_XDECREF(pylong);
  return NULL;
}

static PyObject *
ipaddress_object_str(ipaddress_object *self)
{
  char addrstr[sizeof("aaaa:bbbb:cccc:dddd:eeee:ffff:255.255.255.255") + 1];

  ENTERING(ipaddress_object_str);

  if (!inet_ntop(self->type->af, self->address, addrstr, sizeof(addrstr)))
    lose("Couldn't convert IP address");

  return PyString_FromString(addrstr);

 error:
  return NULL;
}

static PyObject *
ipaddress_object_repr(ipaddress_object *self)
{
  char addrstr[sizeof("aaaa:bbbb:cccc:dddd:eeee:ffff:255.255.255.255") + 1];

  ENTERING(ipaddress_object_repr);

  if (!inet_ntop(self->type->af, self->address, addrstr, sizeof(addrstr)))
    lose("Couldn't convert IP address");

  return PyString_FromFormat("<%s object %s at %p>",
                             self->ob_type->tp_name, addrstr, self);

 error:
  return NULL;
}

static int
ipaddress_object_compare(PyObject *arg1, PyObject *arg2)
{
  PyObject *obj1 = PyNumber_Long(arg1);
  PyObject *obj2 = PyNumber_Long(arg2);
  int cmp = -1;

  ENTERING(ipaddress_object_compare);

  if (obj1 != NULL && obj2 != NULL)
    cmp = PyObject_Compare(obj1, obj2);

  Py_XDECREF(obj1);
  Py_XDECREF(obj2);
  return cmp;
}

static PyObject *
ipaddress_object_richcompare(PyObject *arg1, PyObject *arg2, int op)
{
  PyObject *obj1 = PyNumber_Long(arg1);
  PyObject *obj2 = PyNumber_Long(arg2);
  PyObject *result = NULL;

  ENTERING(ipaddress_object_richcompare);

  if (obj1 != NULL && obj2 != NULL)
    result = PyObject_RichCompare(obj1, obj2, op);

  Py_XDECREF(obj1);
  Py_XDECREF(obj2);
  return result;
}

static long
ipaddress_object_hash(ipaddress_object *self)
{
  unsigned long h = 0;
  int i;

  ENTERING(ipaddress_object_hash);

  for (i = 0; (unsigned) i < self->type->length; i++)
    h ^= self->address[i] << ((i & 3) << 3);

  return (long) h == -1 ? 0 : (long) h;
}

static char ipaddress_object_from_bytes__doc__[] =
  "Construct an IPAddress object from a sequence of bytes.\n"
  "\n"
  "Argument must be a Python string of exactly 4 or 16 bytes.\n"
  ;

static PyObject *
ipaddress_object_from_bytes(PyTypeObject *type, PyObject *args)
{
  ipaddress_object *result = NULL;
  char *bytes = NULL;
  Py_ssize_t len;
  int v;

  ENTERING(ipaddress_object_from_bytes);

  if (!PyArg_ParseTuple(args, "s#", &bytes, &len))
    goto error;

  if ((result = (ipaddress_object *) type->tp_alloc(type, 0)) == NULL)
    goto error;

  result->type = NULL;

  for (v = 0; v < (int) (sizeof(ipaddress_versions)/sizeof(*ipaddress_versions)); v++)
    if (len == ipaddress_versions[v]->length)
      result->type = ipaddress_versions[v];

  if (result->type == NULL)
    lose("Unknown IP version number");

  memcpy(result->address, bytes, len);
  return (PyObject *) result;

 error:
  Py_XDECREF(result);
  return NULL;
}

static char ipaddress_object_to_bytes__doc__[] =
  "Return the binary value of this IPAddress as a Python string\n"
  "of exactly 4 or 16 bytes.\n"
  ;

static PyObject *
ipaddress_object_to_bytes(ipaddress_object *self)
{
  ENTERING(ipaddress_object_from_bytes);
  return PyString_FromStringAndSize((char *) self->address, self->type->length);
}

static PyObject *
ipaddress_object_get_bits(ipaddress_object *self, GCC_UNUSED void *closure)
{
  ENTERING(ipaddress_object_get_bits);
  return PyInt_FromLong(self->type->length * 8);
}

static PyObject *
ipaddress_object_get_version(ipaddress_object *self, GCC_UNUSED void *closure)
{
  ENTERING(ipaddress_object_get_version);
  return PyInt_FromLong(self->type->version);
}

static PyObject *
ipaddress_object_number_binary_helper(binaryfunc function, PyObject *arg1, PyObject *arg2)
{
  ipaddress_object *addr = NULL;
  ipaddress_object *addr1 = NULL;
  ipaddress_object *addr2 = NULL;
  ipaddress_object *result = NULL;
  PyObject *obj1 = NULL;
  PyObject *obj2 = NULL;
  PyObject *obj3 = NULL;
  PyObject *obj4 = NULL;

  if (POW_IPAddress_Check(arg1))
    addr1 = (ipaddress_object *) arg1;

  if (POW_IPAddress_Check(arg2))
    addr2 = (ipaddress_object *) arg2;

  if ((addr1 == NULL && addr2 == NULL) ||
      (addr1 != NULL && addr2 != NULL && addr1->type != addr2->type) ||
      (obj1 = PyNumber_Long(arg1)) == NULL ||
      (obj2 = PyNumber_Long(arg2)) == NULL) {
    result = (ipaddress_object *) Py_NotImplemented;
    Py_INCREF(result);
    goto error;
  }

  if ((obj3 = function(obj1, obj2)) == NULL)
    goto error;

  if ((obj4 = PyNumber_Long(obj3)) == NULL)
    lose("Couldn't convert result");

  addr = addr1 != NULL ? addr1 : addr2;

  if ((result = (ipaddress_object *) addr->ob_type->tp_alloc(addr->ob_type, 0)) == NULL)
    goto error;

  result->type = addr->type;

  if (_PyLong_AsByteArray((PyLongObject *) obj4, result->address, result->type->length, 0, 0) < 0) {
    Py_XDECREF(result);
    result = NULL;
  }

 error:                         /* Fall through */
  Py_XDECREF(obj1);
  Py_XDECREF(obj2);
  Py_XDECREF(obj3);
  Py_XDECREF(obj4);

  return (PyObject *) result;
}

static PyObject *
ipaddress_object_number_long(PyObject *arg)
{
  ipaddress_object *addr = (ipaddress_object *) arg;

  ENTERING(ipaddress_object_number_long);

  if (!POW_IPAddress_Check(arg))
    return Py_INCREF(Py_NotImplemented), Py_NotImplemented;

  return _PyLong_FromByteArray(addr->address, addr->type->length, 0, 0);
}

static PyObject *
ipaddress_object_number_int(PyObject *arg)
{
  ENTERING(ipaddress_object_number_int);
  return ipaddress_object_number_long(arg);
}

static PyObject *
ipaddress_object_number_add(PyObject *arg1, PyObject *arg2)
{
  ENTERING(ipaddress_object_number_add);
  return ipaddress_object_number_binary_helper(PyNumber_Add, arg1, arg2);
}

static PyObject *
ipaddress_object_number_subtract(PyObject *arg1, PyObject *arg2)
{
  ENTERING(ipaddress_object_number_subtract);
  return ipaddress_object_number_binary_helper(PyNumber_Subtract, arg1, arg2);
}

static PyObject *
ipaddress_object_number_lshift(PyObject *arg1, PyObject *arg2)
{
  ENTERING(ipaddress_object_number_lshift);
  return ipaddress_object_number_binary_helper(PyNumber_Lshift, arg1, arg2);
}

static PyObject *
ipaddress_object_number_rshift(PyObject *arg1, PyObject *arg2)
{
  ENTERING(ipaddress_object_number_rshift);
  return ipaddress_object_number_binary_helper(PyNumber_Rshift, arg1, arg2);
}

static PyObject *
ipaddress_object_number_and(PyObject *arg1, PyObject *arg2)
{
  ENTERING(ipaddress_object_number_and);
  return ipaddress_object_number_binary_helper(PyNumber_And, arg1, arg2);
}

static PyObject *
ipaddress_object_number_xor(PyObject *arg1, PyObject *arg2)
{
  ENTERING(ipaddress_object_number_xor);
  return ipaddress_object_number_binary_helper(PyNumber_Xor, arg1, arg2);
}

static PyObject *
ipaddress_object_number_or(PyObject *arg1, PyObject *arg2)
{
  ENTERING(ipaddress_object_number_or);
  return ipaddress_object_number_binary_helper(PyNumber_Or, arg1, arg2);
}

static int
ipaddress_object_number_nonzero(ipaddress_object *self)
{
  int i;

  ENTERING(ipaddress_object_number_nonzero);

  for (i = 0; (unsigned) i < self->type->length; i++)
    if (self->address[i] != 0)
      return 1;
  return 0;
}

static PyObject *
ipaddress_object_number_invert(ipaddress_object *self)
{
  ipaddress_object *result = NULL;
  int i;

  ENTERING(ipaddress_object_number_invert);

  if ((result = (ipaddress_object *) self->ob_type->tp_alloc(self->ob_type, 0)) == NULL)
    goto error;

  result->type = self->type;

  for (i = 0; (unsigned) i < self->type->length; i++)
    result->address[i] = ~self->address[i];

 error:                         /* Fall through */
  return (PyObject *) result;
}

static char ipaddress_object_copy__doc__[] =
  "Copy an IPAddress object.\n"
  ;

static PyObject *
ipaddress_object_copy(ipaddress_object *self, GCC_UNUSED PyObject *args)
{
  ipaddress_object *result = NULL;

  ENTERING(ipaddress_object_copy);

  if ((result = (ipaddress_object *) self->ob_type->tp_alloc(self->ob_type, 0)) == NULL)
    goto error;

  memcpy(result->address, self->address, sizeof(result->address));
  result->type = self->type;

 error:
  return (PyObject *) result;
}

static struct PyMethodDef ipaddress_object_methods[] = {
  Define_Method(__copy__,		ipaddress_object_copy,		METH_VARARGS),
  Define_Method(__deepcopy__,		ipaddress_object_copy,		METH_VARARGS),
  Define_Method(toBytes,                ipaddress_object_to_bytes,      METH_NOARGS),
  Define_Class_Method(fromBytes,        ipaddress_object_from_bytes,    METH_VARARGS),
  {NULL}
};

static PyGetSetDef ipaddress_object_getsetters[] = {
  {"bits", 	(getter) ipaddress_object_get_bits},
  {"version", 	(getter) ipaddress_object_get_version},
  {NULL}
};

static PyNumberMethods ipaddress_NumberMethods = {
  ipaddress_object_number_add,                  /* nb_add */
  ipaddress_object_number_subtract,             /* nb_subtract */
  0,                                            /* nb_multiply */
  0,                                            /* nb_divide */
  0,                                            /* nb_remainder */
  0,                                            /* nb_divmod */
  0,                                            /* nb_power */
  0,                                            /* nb_negative */
  0,                                            /* nb_positive */
  0,                                            /* nb_absolute */
  (inquiry) ipaddress_object_number_nonzero,    /* nb_nonzero */
  (unaryfunc) ipaddress_object_number_invert,   /* nb_invert */
  ipaddress_object_number_lshift,               /* nb_lshift */
  ipaddress_object_number_rshift,               /* nb_rshift */
  ipaddress_object_number_and,                  /* nb_and */
  ipaddress_object_number_xor,                  /* nb_xor */
  ipaddress_object_number_or,                   /* nb_or */
  0,                                            /* nb_coerce */
  ipaddress_object_number_int,                  /* nb_int */
  ipaddress_object_number_long,                 /* nb_long */
  0,                                            /* nb_float */
  0,                                            /* nb_oct */
  0,                                            /* nb_hex */
  0,                                            /* nb_inplace_add */
  0,                                            /* nb_inplace_subtract */
  0,                                            /* nb_inplace_multiply */
  0,                                            /* nb_inplace_divide */
  0,                                            /* nb_inplace_remainder */
  0,                                            /* nb_inplace_power */
  0,                                            /* nb_inplace_lshift */
  0,                                            /* nb_inplace_rshift */
  0,                                            /* nb_inplace_and */
  0,                                            /* nb_inplace_xor */
  0,                                            /* nb_inplace_or */
  0,                                            /* nb_floor_divide */
  0,                                            /* nb_true_divide */
  0,                                            /* nb_inplace_floor_divide */
  0,                                            /* nb_inplace_true_divide */
  0,                                            /* nb_index */
};

static PyTypeObject POW_IPAddress_Type = {
  PyObject_HEAD_INIT(NULL)
  0,                                        /* ob_size */
  "rpki.POW.IPAddress",                     /* tp_name */
  sizeof(ipaddress_object),                 /* tp_basicsize */
  0,                                        /* tp_itemsize */
  0,                                        /* tp_dealloc */
  0,                                        /* tp_print */
  0,                                        /* tp_getattr */
  0,                                        /* tp_setattr */
  ipaddress_object_compare,                 /* tp_compare */
  (reprfunc) ipaddress_object_repr,         /* tp_repr */
  &ipaddress_NumberMethods,                 /* tp_as_number */
  0,                                        /* tp_as_sequence */
  0,                                        /* tp_as_mapping */
  (hashfunc) ipaddress_object_hash,         /* tp_hash */
  0,                                        /* tp_call */
  (reprfunc) ipaddress_object_str,          /* tp_str */
  0,                                        /* tp_getattro */
  0,                                        /* tp_setattro */
  0,                                        /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_CHECKTYPES, /* tp_flags */
  0,                                        /* tp_doc */
  0,                                        /* tp_traverse */
  0,                                        /* tp_clear */
  ipaddress_object_richcompare,             /* tp_richcompare */
  0,                                        /* tp_weaklistoffset */
  0,                                        /* tp_iter */
  0,                                        /* tp_iternext */
  ipaddress_object_methods,                 /* tp_methods */
  0,                                        /* tp_members */
  ipaddress_object_getsetters,              /* tp_getset */
  0,                                        /* tp_base */
  0,                                        /* tp_dict */
  0,                                        /* tp_descr_get */
  0,                                        /* tp_descr_set */
  0,                                        /* tp_dictoffset */
  0,                                        /* tp_init */
  0,                                        /* tp_alloc */
  ipaddress_object_new,                     /* tp_new */
};



/*
 * X509 object.
 */

static x509_object *
x509_object_new_helper(PyTypeObject *type, X509 *x)
{
  x509_object *self;

  if (type == NULL)
    type = &POW_X509_Type;

  if ((self = (x509_object *) type->tp_alloc(type, 0)) == NULL)
    return NULL;

  self->x509 = x;
  return self;
}

static PyObject *
x509_object_new(PyTypeObject *type, GCC_UNUSED PyObject *args, GCC_UNUSED PyObject *kwds)
{
  x509_object *self = NULL;
  X509 *x = NULL;

  ENTERING(x509_object_new);

  if ((x = X509_new()) == NULL)
    lose_no_memory();

  if ((self = x509_object_new_helper(type, x)) == NULL)
    goto error;

  return (PyObject *) self;

 error:
  X509_free(x);
  return NULL;
}

static void
x509_object_dealloc(x509_object *self)
{
  ENTERING(x509_object_dealloc);
  X509_free(self->x509);
  self->ob_type->tp_free((PyObject*) self);
}

static PyObject *
x509_object_pem_read_helper(PyTypeObject *type, BIO *bio)
{
  x509_object *self = NULL;

  ENTERING(x509_object_pem_read_helper);

  if ((self = (x509_object *) x509_object_new(type, NULL, NULL)) == NULL)
    goto error;

  if (!PEM_read_bio_X509(bio, &self->x509, NULL, NULL))
    lose_openssl_error("Couldn't load PEM encoded certificate");

  return (PyObject *) self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static PyObject *
x509_object_der_read_helper(PyTypeObject *type, BIO *bio)
{
  x509_object *self;

  ENTERING(x509_object_der_read_helper);

  if ((self = (x509_object *) x509_object_new(type, NULL, NULL)) == NULL)
    goto error;

  if (!d2i_X509_bio(bio, &self->x509))
    lose_openssl_error("Couldn't load DER encoded certificate");

  return (PyObject *) self;

 error:
  Py_XDECREF(self);
  return NULL;
}

static char x509_object_pem_read__doc__[] =
  "Read a PEM-encoded X.509 object from a string.\n"
  ;

static PyObject *
x509_object_pem_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(x509_object_pem_read);
  return read_from_string_helper(x509_object_pem_read_helper, type, args);
}

static char x509_object_pem_read_file__doc__[] =
  "Read a PEM-encoded X.509 object from a file.\n"
  ;

static PyObject *
x509_object_pem_read_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(x509_object_pem_read_file);
  return read_from_file_helper(x509_object_pem_read_helper, type, args);
}

static char x509_object_der_read__doc__[] =
  "Read a DER-encoded X.509 object from a string.\n"
  ;

static PyObject *
x509_object_der_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(x509_object_der_read);
  return read_from_string_helper(x509_object_der_read_helper, type, args);
}

static char x509_object_der_read_file__doc__[] =
  "Read a DER-encoded X.509 object from a file.\n"
  ;

static PyObject *
x509_object_der_read_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(x509_object_der_read_file);
  return read_from_file_helper(x509_object_der_read_helper, type, args);
}

static char x509_object_pem_write__doc__[] =
  "Return the PEM encoding of this certificate, as a string.\n"
  ;

static PyObject *
x509_object_pem_write(x509_object *self)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  ENTERING(x509_object_pem_write);

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  if (!PEM_write_bio_X509(bio, self->x509))
    lose_openssl_error("Unable to write certificate");

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static char x509_object_der_write__doc__[] =
  "Return the DER encoding of this certificate, as a string.\n"
  ;

static PyObject *
x509_object_der_write(x509_object *self)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  ENTERING(x509_object_der_write);

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  if (!i2d_X509_bio(bio, self->x509))
    lose_openssl_error("Unable to write certificate");

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static X509_EXTENSION *
x509_object_extension_get_helper(x509_object *self, int nid)
{
  if (self != NULL && self->x509 != NULL)
    return X509_get_ext(self->x509, X509_get_ext_by_NID(self->x509, nid, -1));
  else
    return NULL;
}

static PyObject *
x509_object_extension_set_helper(x509_object *self, extension_wrapper ext)
{
  int ok = 0;

  if (ext.value == NULL)
    goto error;

  if (!X509_add1_ext_i2d(self->x509, ext.nid, ext.value, ext.critical, X509V3_ADD_REPLACE))
    lose_openssl_error("Couldn't add extension to certificate");

  ok = 1;

 error:
  ext.destructor(ext.value);
  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char x509_object_get_public_key__doc__[] =
  "Return the public key from this certificate object,\n"
  "as an Asymmetric object.\n"
  ;

static PyObject *
x509_object_get_public_key(x509_object *self)
{
  PyTypeObject *type = &POW_Asymmetric_Type;
  asymmetric_object *asym = NULL;

  ENTERING(x509_object_get_public_key);

  if ((asym = (asymmetric_object *) type->tp_alloc(type, 0)) == NULL)
    goto error;

  if ((asym->pkey = X509_get_pubkey(self->x509)) == NULL)
    lose_openssl_error("Couldn't extract public key from certificate");

  whack_ec_key_to_namedCurve(asym->pkey);

  return (PyObject *) asym;

 error:
  Py_XDECREF(asym);
  return NULL;
}

static char x509_object_set_public_key__doc__[] =
  "Set the public key of this certificate object.\n"
  "\n"
  "The \"key\" parameter should be an instance of the Asymmetric class,\n"
  "containing a public key.\n"
  ;

static PyObject *
x509_object_set_public_key(x509_object *self, PyObject *args)
{
  asymmetric_object *asym;

  ENTERING(x509_object_set_public_key);

  if (!PyArg_ParseTuple(args, "O!", &POW_Asymmetric_Type, &asym))
    goto error;

  if (!X509_set_pubkey(self->x509, asym->pkey))
    lose_openssl_error("Couldn't set certificate's public key");

  Py_RETURN_NONE;

 error:
  return NULL;
}

static char x509_object_sign__doc__[] =
  "Sign a certificate with a private key.\n"
  "\n"
  "The \"key\" parameter should be an instance of the Asymmetric class,\n"
  "containing a private key.\n"
  "\n"
  "The optional \"digest\" parameter indicates which digest to compute and\n"
  "sign, and should be one of the following:\n"
  "\n"
  "* SHA1_DIGEST\n"
  "* SHA256_DIGEST\n"
  "* SHA384_DIGEST\n"
  "* SHA512_DIGEST\n"
  "\n"
  "The default digest algorithm is SHA-256.\n"
  ;

static PyObject *
x509_object_sign(x509_object *self, PyObject *args)
{
  asymmetric_object *asym;
  int digest_type = SHA256_DIGEST;
  const EVP_MD *digest_method = NULL;

  ENTERING(x509_object_sign);

  if (!PyArg_ParseTuple(args, "O!|i", &POW_Asymmetric_Type, &asym, &digest_type))
    goto error;

  if ((digest_method = evp_digest_factory(digest_type)) == NULL)
    lose("Unsupported digest algorithm");

  if (!X509_sign(self->x509, asym->pkey, digest_method))
    lose_openssl_error("Couldn't sign certificate");

  Py_RETURN_NONE;

 error:
  return NULL;
}

static int x509_store_ctx_object_verify_cb(int ok, X509_STORE_CTX *ctx);

static char x509_object_verify__doc__[] =
  "Verify a certificate.\n"
  ;

#warning Write real x509_object_verify__doc__[] once API is stable.

static PyObject *
x509_object_verify(x509_object *self, PyObject *args, PyObject *kwds)
{
  static char *kwlist[] = {"trusted", "untrusted", "crl", "policy", "context_class", NULL};
  PyObject *ctxclass = (PyObject *) &POW_X509StoreCTX_Type;
  STACK_OF(X509)   *trusted_stack = NULL;
  STACK_OF(X509) *untrusted_stack = NULL;
  STACK_OF(X509_CRL)   *crl_stack = NULL;
  x509_store_ctx_object *ctx = NULL;
  PyObject *trusted   = Py_None;
  PyObject *untrusted = Py_None;
  PyObject *crl       = Py_None;
  PyObject *policy    = Py_None;
  int ok = 0;

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "|OOOOO", kwlist, &trusted, &untrusted, &crl, &policy, &ctxclass))
    goto error;

  if ((trusted_stack = x509_helper_iterable_to_stack(trusted)) == NULL)
    goto error;

  if ((untrusted_stack = x509_helper_iterable_to_stack(untrusted)) == NULL)
    goto error;

  if (crl != Py_None && !POW_CRL_Check(crl))
    lose_type_error("Not a CRL");

  if (crl != Py_None && ((crl_stack = sk_X509_CRL_new_null()) == NULL ||
                         !sk_X509_CRL_push(crl_stack, ((crl_object *) crl)->crl)))
    lose_no_memory();

  if (!PyCallable_Check(ctxclass))
    lose_type_error("Context class must be callable");

  if ((ctx = (x509_store_ctx_object *) PyObject_CallFunctionObjArgs(ctxclass, NULL)) == NULL)
    goto error;

  if (!POW_X509StoreCTX_Check(ctx))
    lose_type_error("Returned context is not a X509StoreCTX");

  if (ctx->ctx == NULL)
    lose("Uninitialized X509StoreCTX");

  if (crl != Py_None)
    X509_VERIFY_PARAM_set_flags(ctx->ctx->param, X509_V_FLAG_CRL_CHECK);

  if (policy != Py_None) {
    const char  *oid_txt = NULL;
    ASN1_OBJECT *oid_obj = NULL;

    if ((oid_txt = PyString_AsString(policy)) == NULL)
      goto error;

    if ((oid_obj = OBJ_txt2obj(oid_txt, 1)) == NULL)
      lose("Couldn't parse policy OID");

    X509_VERIFY_PARAM_set_flags(ctx->ctx->param, X509_V_FLAG_POLICY_CHECK | X509_V_FLAG_EXPLICIT_POLICY);
    X509_VERIFY_PARAM_add0_policy(ctx->ctx->param, oid_obj);
  }

  Py_XINCREF(trusted);
  Py_XINCREF(untrusted);
  Py_XINCREF(crl);
  X509_STORE_CTX_set_cert(ctx->ctx, self->x509);
  X509_STORE_CTX_trusted_stack(ctx->ctx, trusted_stack);
  X509_STORE_CTX_set_chain(ctx->ctx, untrusted_stack);
  X509_STORE_CTX_set0_crls(ctx->ctx, crl_stack);

  X509_STORE_CTX_set_verify_cb(ctx->ctx, x509_store_ctx_object_verify_cb);
  X509_VERIFY_PARAM_set_flags(ctx->ctx->param, X509_V_FLAG_X509_STRICT);

  ok = X509_verify_cert(ctx->ctx) >= 0;

  X509_STORE_CTX_set0_crls(ctx->ctx, NULL);
  X509_STORE_CTX_set_chain(ctx->ctx, NULL);
  X509_STORE_CTX_trusted_stack(ctx->ctx, NULL);
  X509_STORE_CTX_set_cert(ctx->ctx, NULL);
  Py_XDECREF(crl);
  Py_XDECREF(untrusted);
  Py_XDECREF(trusted);

  if (PyErr_Occurred())
    goto error;

  if (!ok)
    lose_validation_error("X509_verify_cert() raised an exception");

 error:
  sk_X509_free(trusted_stack);
  sk_X509_free(untrusted_stack);
  sk_X509_CRL_free(crl_stack);

  if (ok)
    return (PyObject *) ctx;

  Py_XDECREF(ctx);
  return NULL;
}


static char x509_object_check_rpki_conformance__doc__[] =
  "Check a certificate for conformance to the RPKI profile.\n"
  ;

#warning Write real x509_object_check_rpki_conformance__doc__[] once API is stable.

static PyObject *
x509_object_check_rpki_conformance(x509_object *self, PyObject *args, PyObject *kwds)
{
  static char *kwlist[] = {"status", "eku", NULL};
  PyObject *status = Py_None;
  PyObject *ekuarg = Py_None;
  EVP_PKEY *issuer_pkey = NULL, *subject_pkey = NULL;
  AUTHORITY_INFO_ACCESS *sia = NULL, *aia = NULL;
  STACK_OF(POLICYINFO) *policies = NULL;
  ASN1_BIT_STRING *ski_pubkey = NULL;
  STACK_OF(DIST_POINT) *crldp = NULL;
  EXTENDED_KEY_USAGE *eku = NULL;
  BASIC_CONSTRAINTS *bc = NULL;
  ASN1_OCTET_STRING *ski = NULL;
  AUTHORITY_KEYID *aki = NULL;
  ASIdentifiers *asid = NULL;
  IPAddrBlocks *addr = NULL;
  unsigned char ski_hashbuf[EVP_MAX_MD_SIZE];
  unsigned ski_hashlen, afi;
  int i, ok, crit, ex_count, is_ca = 0, ekunid = NID_undef, ret = 0;

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O", kwlist, &PySet_Type, &status, &ekuarg))
    goto error;

  if (ekuarg != Py_None) {
    const char *ekutxt = PyString_AsString(ekuarg);
    if (ekutxt == NULL)
      goto error;
    ekunid = OBJ_txt2nid(ekutxt);
  }

  /*
   * We don't use X509_check_ca() to check whether the certificate is
   * a CA, because it's not paranoid enough to enforce the RPKI
   * certificate profile, but we still call it because we need it (or
   * something) to invoke x509v3_cache_extensions() for us.
   */

  (void) X509_check_ca(self->x509);

  if (!check_allowed_time_encoding(X509_get_notBefore(self->x509)) ||
      !check_allowed_time_encoding(X509_get_notAfter(self->x509)))
    record_validation_status(status, NONCONFORMANT_ASN1_TIME_VALUE);

  if (X509_get_signature_nid(self->x509) != NID_sha256WithRSAEncryption)
    record_validation_status(status, NONCONFORMANT_SIGNATURE_ALGORITHM);

  if (!check_allowed_dn(X509_get_subject_name(self->x509)))
    record_validation_status(status, NONCONFORMANT_SUBJECT_NAME);

  if (!check_allowed_dn(X509_get_issuer_name(self->x509)))
    record_validation_status(status, NONCONFORMANT_ISSUER_NAME);

  /*
   * Apparently nothing ever looks at these fields.  We wouldn't
   * bother either if they weren't forbidden by the RPKI certificate
   * profile.
   */

  if (!self->x509->cert_info || self->x509->cert_info->issuerUID || self->x509->cert_info->subjectUID)
    record_validation_status(status, NONCONFORMANT_CERTIFICATE_UID);

  /*
   * Public key checks postponed until we've checked extensions (in
   * particular, until we've checked Basic Constraints and know
   * whether to apply the CA or EE rules).
   */

  /*
   * Keep track of allowed extensions we've seen.  Once we've
   * processed all the ones we expect, anything left is an error.
   */

  ex_count = X509_get_ext_count(self->x509);

  /* Critical */
  if ((bc = X509_get_ext_d2i(self->x509, NID_basic_constraints, &crit, NULL)) != NULL) {
    ex_count--;
    if (!crit || bc->ca <= 0 || bc->pathlen != NULL)
      record_validation_status(status, MALFORMED_BASIC_CONSTRAINTS);
  }

  is_ca = bc != NULL;

  /*
   * Check for presence of AIA, SIA, and CRLDP, and make sure that
   * they're in the correct format, but leave checking of the URIs
   * themselves for Python code to handle.
   */

  /* Non-criticial */
  if ((aia = X509_get_ext_d2i(self->x509, NID_info_access, &crit, NULL)) != NULL) {
    ex_count--;
    if (crit)
      record_validation_status(status, GRATUITOUSLY_CRITICAL_EXTENSION);
    ok = sk_ACCESS_DESCRIPTION_num(aia) > 0;
    for (i = 0; ok && i < sk_ACCESS_DESCRIPTION_num(aia); i++) {
      ACCESS_DESCRIPTION *a = sk_ACCESS_DESCRIPTION_value(aia, i);
      ok = (a != NULL && a->location->type == GEN_URI &&
            OBJ_obj2nid(a->method) == NID_ad_ca_issuers);
    }
    if (!ok)
      record_validation_status(status, MALFORMED_AIA_EXTENSION);
  }

  /* Non-criticial */
  if ((sia = X509_get_ext_d2i(self->x509, NID_sinfo_access, &crit, NULL)) != NULL) {
    ex_count--;
    if (crit)
      record_validation_status(status, GRATUITOUSLY_CRITICAL_EXTENSION);
    ok = sk_ACCESS_DESCRIPTION_num(sia) > 0;
    for (i = 0; ok && i < sk_ACCESS_DESCRIPTION_num(sia); i++) {
      ACCESS_DESCRIPTION *a = sk_ACCESS_DESCRIPTION_value(sia, i);
      int nid = a == NULL ? NID_undef : OBJ_obj2nid(a->method);
      ok = (a != NULL && a->location->type == GEN_URI &&
            (nid == NID_caRepository    || nid == NID_ad_rpkiManifest ||
             nid == NID_ad_signedObject || nid == NID_ad_rpkiNotify));
    }
    if (!ok)
      record_validation_status(status, MALFORMED_SIA_EXTENSION);
  }

  /* Non-critical */
  if ((crldp = X509_get_ext_d2i(self->x509, NID_crl_distribution_points, &crit, NULL)) != NULL) {
    DIST_POINT *dp = sk_DIST_POINT_value(crldp, 0);
    ex_count--;
    if (crit)
      record_validation_status(status, GRATUITOUSLY_CRITICAL_EXTENSION);
    ok = (sk_DIST_POINT_num(crldp) == 1 &&
          dp->reasons == NULL   && dp->CRLissuer == NULL &&
          dp->distpoint != NULL && dp->distpoint->type == 0);
    for (i = 0; ok && i < sk_GENERAL_NAME_num(dp->distpoint->name.fullname); i++) {
      GENERAL_NAME *gn = sk_GENERAL_NAME_value(dp->distpoint->name.fullname, i);
      ok = gn != NULL && gn->type == GEN_URI;
    }
    if (!ok)
      record_validation_status(status, MALFORMED_CRLDP_EXTENSION);
  }

  /* Non-critical */
  if ((eku = X509_get_ext_d2i(self->x509, NID_ext_key_usage, &crit, NULL)) != NULL) {
    ex_count--;
    ok = 0;
    if (!crit && !is_ca && sk_ASN1_OBJECT_num(eku) > 0 && ekunid != NID_undef)
      for (i = 0; !ok && i < sk_ASN1_OBJECT_num(eku); i++)
        ok = OBJ_obj2nid(sk_ASN1_OBJECT_value(eku, i)) == ekunid;
    if (!ok)
      record_validation_status(status, INAPPROPRIATE_EKU_EXTENSION);
  }

  /* Critical */
  if ((policies = X509_get_ext_d2i(self->x509, NID_certificate_policies, &crit, NULL)) != NULL) {
    POLICYQUALINFO *qualifier = NULL;
    POLICYINFO *policy = NULL;
    ex_count--;
    if (!crit || sk_POLICYINFO_num(policies) != 1 ||
	(policy = sk_POLICYINFO_value(policies, 0)) == NULL ||
	OBJ_obj2nid(policy->policyid) != NID_cp_ipAddr_asNumber ||
	sk_POLICYQUALINFO_num(policy->qualifiers) > 1 ||
	(sk_POLICYQUALINFO_num(policy->qualifiers) == 1 &&
	 ((qualifier = sk_POLICYQUALINFO_value(policy->qualifiers, 0)) == NULL ||
	  OBJ_obj2nid(qualifier->pqualid) != NID_id_qt_cps)))
      record_validation_status(status, BAD_CERTIFICATE_POLICY);
    else if (qualifier != NULL)
      record_validation_status(status, POLICY_QUALIFIER_CPS);
  }

  /* Critical */
  if ((self->x509->ex_flags & EXFLAG_KUSAGE) == 0) 
    record_validation_status(status, KEY_USAGE_MISSING);
  else {
    ex_count--;    
    if (!X509_EXTENSION_get_critical(X509_get_ext(self->x509, X509_get_ext_by_NID(self->x509, NID_key_usage, -1))) ||
        self->x509->ex_kusage != (is_ca ? KU_KEY_CERT_SIGN | KU_CRL_SIGN : KU_DIGITAL_SIGNATURE))
      record_validation_status(status, BAD_KEY_USAGE);
  }

  /* Critical */
  if ((addr = X509_get_ext_d2i(self->x509, NID_sbgp_ipAddrBlock, &crit, NULL)) != NULL) {
    ex_count--;
    if (!crit || ekunid == NID_id_kp_bgpsec_router ||
	!v3_addr_is_canonical(addr) || sk_IPAddressFamily_num(addr) == 0)
      record_validation_status(status, BAD_IPADDRBLOCKS);
    else
      for (i = 0; i < sk_IPAddressFamily_num(addr); i++) {
        IPAddressFamily *f = sk_IPAddressFamily_value(addr, i);
        afi = v3_addr_get_afi(f);
        if (afi != IANA_AFI_IPV4 && afi != IANA_AFI_IPV6)
          record_validation_status(status, UNKNOWN_AFI);
        else if (f->addressFamily->length != 2)
          record_validation_status(status, SAFI_NOT_ALLOWED);
      }
  }

  /* Critical */
  if ((asid = X509_get_ext_d2i(self->x509, NID_sbgp_autonomousSysNum, &crit, NULL)) != NULL) {
    ex_count--;
    if (!crit || asid->asnum == NULL || asid->rdi != NULL || !v3_asid_is_canonical(asid) ||
	(ekunid == NID_id_kp_bgpsec_router && asid->asnum->type == ASIdentifierChoice_inherit))
      record_validation_status(status, BAD_ASIDENTIFIERS);
  }

  if (addr == NULL && asid == NULL)
    record_validation_status(status, MISSING_RESOURCES);

  /* Non-critical */
  if ((ski = X509_get_ext_d2i(self->x509, NID_subject_key_identifier, &crit, NULL)) == NULL)
    record_validation_status(status, SKI_EXTENSION_MISSING);
  else {
    ex_count--;
    if (crit)
      record_validation_status(status, GRATUITOUSLY_CRITICAL_EXTENSION);
    if ((ski_pubkey = X509_get0_pubkey_bitstr(self->x509)) == NULL ||
        !EVP_Digest(ski_pubkey->data, ski_pubkey->length,
                    ski_hashbuf, &ski_hashlen, EVP_sha1(), NULL) ||
        ski_hashlen != 20 ||
        ski_hashlen != ASN1_STRING_length(ski) ||
        memcmp(ski_hashbuf, ASN1_STRING_data(ski), ski_hashlen))
      record_validation_status(status, SKI_PUBLIC_KEY_MISMATCH);
  }

  /* Non-critical */
  if ((aki = X509_get_ext_d2i(self->x509, NID_authority_key_identifier, &crit, NULL)) != NULL) {
    ex_count--;
    if (crit)
      record_validation_status(status, GRATUITOUSLY_CRITICAL_EXTENSION);
    if (aki->keyid == NULL || aki->serial != NULL || aki->issuer != NULL)
      record_validation_status(status, AKI_EXTENSION_WRONG_FORMAT);
  }

  if (ex_count > 0)
    record_validation_status(status, DISALLOWED_X509V3_EXTENSION);

  /*
   * Public key checks.
   */

  subject_pkey = X509_get_pubkey(self->x509);
  ok = subject_pkey != NULL;
  if (ok) {
    ASN1_OBJECT *algorithm;

    (void) X509_PUBKEY_get0_param(&algorithm, NULL, NULL, NULL, X509_get_X509_PUBKEY(self->x509));

    switch (OBJ_obj2nid(algorithm)) {

    case NID_rsaEncryption:
      ok = (EVP_PKEY_base_id(subject_pkey) == EVP_PKEY_RSA &&
            EVP_PKEY_bits(subject_pkey) == 2048 &&
            BN_get_word(subject_pkey->pkey.rsa->e) == 65537);
      break;

    case NID_X9_62_id_ecPublicKey:
      ok = (EVP_PKEY_base_id(subject_pkey) == EVP_PKEY_EC &&
            ekunid == NID_id_kp_bgpsec_router &&
            EC_GROUP_get_curve_name(EC_KEY_get0_group(subject_pkey->pkey.ec)) == NID_X9_62_prime256v1);
      break;

    default:
      ok = 0;
    }
  }
  if (!ok)
    record_validation_status(status, BAD_PUBLIC_KEY);

  ret = 1;

 error:
  EVP_PKEY_free(issuer_pkey);
  EVP_PKEY_free(subject_pkey);
  BASIC_CONSTRAINTS_free(bc);
  sk_ACCESS_DESCRIPTION_pop_free(sia, ACCESS_DESCRIPTION_free);
  sk_ACCESS_DESCRIPTION_pop_free(aia, ACCESS_DESCRIPTION_free);
  sk_DIST_POINT_pop_free(crldp, DIST_POINT_free);
  sk_POLICYINFO_pop_free(policies, POLICYINFO_free);
  sk_ASN1_OBJECT_pop_free(eku, ASN1_OBJECT_free);
  ASN1_OCTET_STRING_free(ski);
  AUTHORITY_KEYID_free(aki);
  ASIdentifiers_free(asid);
  sk_IPAddressFamily_pop_free(addr, IPAddressFamily_free);

  if (ret)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char x509_object_get_version__doc__[] =
  "Return version number of this certificate.\n"
  ;

static PyObject *
x509_object_get_version(x509_object *self)
{
  ENTERING(x509_object_get_version);
  return Py_BuildValue("l", X509_get_version(self->x509));
}

static char x509_object_set_version__doc__[] =
  "Set version number of this certificate.\n"
  "\n"
  "The \"version\" parameter should be an integer.\n"
  ;

static PyObject *
x509_object_set_version(x509_object *self, PyObject *args)
{
  long version = 0;

  ENTERING(x509_object_set_version);

  if (!PyArg_ParseTuple(args, "l", &version))
    goto error;

  if (!X509_set_version(self->x509, version))
    lose("Couldn't set certificate version");

  Py_RETURN_NONE;

 error:

  return NULL;
}

static char x509_object_get_serial__doc__[] =
  "Return the serial number of this certificate.\n"
  ;

static PyObject *
x509_object_get_serial(x509_object *self)
{
  ENTERING(x509_object_get_serial);
  return Py_BuildValue("N", ASN1_INTEGER_to_PyLong(X509_get_serialNumber(self->x509)));
}

static char x509_object_set_serial__doc__[] =
  "Set the serial number of this certificate.\n"
  "\n"
  "The \"serial\" parameter should ba an integer.\n"
  ;

static PyObject *
x509_object_set_serial(x509_object *self, PyObject *args)
{
  ASN1_INTEGER *a_serial = NULL;
  PyObject *p_serial = NULL;
  int ok = 0;

  ENTERING(x509_object_set_serial);

  if (!PyArg_ParseTuple(args, "O", &p_serial) ||
      (a_serial = PyLong_to_ASN1_INTEGER(p_serial)) == NULL)
    goto error;

  if (!X509_set_serialNumber(self->x509, a_serial))
    lose_no_memory();

  ok = 1;

 error:
  ASN1_INTEGER_free(a_serial);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char x509_object_get_issuer__doc__[] =
  "Return this certificate's issuer name, represented as a tuple.\n"
  "\n"
  "Each element of this tuple is another tuple representing one\n"
  "\"Relative Distinguished Name\" (RDN), each element of which in turn\n"
  "is yet another tuple representing one AttributeTypeAndValue pair.\n"
  "\n"
  "In practice, RDNs containing multiple attributes are rare, thus the RDN\n"
  "tuples will usually be exactly one element long, but using the\n"
  "tuple-of-tuples-of-tuples format lets us represent the general case.\n"
  "\n"
  "The AttributeTypeANdValue pairs are two-element tuples, the first\n"
  "element of which is a string representing an Object Identifier (OID),\n"
  "the second of which contains the attribute value.\n"
  "\n"
  "This method takes an optional \"format\" parameter which controls\n"
  "the format in which OIDs are returned.  Allowed values are:\n"
  "\n"
  "  * SHORTNAME_FORMAT (the OpenSSL \"short name\" for this OID)\n"
  "  * LONGNAME_FORMAT  (the OpenSSL \"long name\" for this OID)\n"
  "  * OIDNAME_FORMAT   (the OID in dotted decimal numeric format)\n"
  "\n"
  "The default is OIDNAME_FORMAT.\n"
  "\n"
  "See RFC 5280 section 4.1.2.4 for details of the ASN.1 structure.\n"
  ;

static PyObject *
x509_object_get_issuer(x509_object *self, PyObject *args)
{
  PyObject *result = NULL;
  int format = OIDNAME_FORMAT;

  ENTERING(x509_object_get_issuer);

  if (!PyArg_ParseTuple(args, "|i", &format))
    goto error;

  result = x509_object_helper_get_name(X509_get_issuer_name(self->x509),
                                       format);

 error:                         /* Fall through */
  return result;
}

static char x509_object_get_subject__doc__[] =
  "Return this certificate's subject name, as a tuple.\n"
  "\n"
  "See the documentation for the \"getIssuer\" method for details on the\n"
  "structure of the return value and use of the optional \"format\"\n"
  "parameter.\n"
  ;

static PyObject *
x509_object_get_subject(x509_object *self, PyObject *args)
{
  PyObject *result = NULL;
  int format = OIDNAME_FORMAT;

  ENTERING(x509_object_get_subject);

  if (!PyArg_ParseTuple(args, "|i", &format))
    goto error;

  result = x509_object_helper_get_name(X509_get_subject_name(self->x509),
                                       format);

 error:                         /* Fall through */
  return result;
}

static char x509_object_set_subject__doc__[] =
  "Set this certificate's subject name.\n"
  "\n"
  "The \"name\" parameter should be in the same format as the return\n"
  "value from the \"getIssuer\" method.\n"
  ;

static PyObject *
x509_object_set_subject(x509_object *self, PyObject *args)
{
  PyObject *name_sequence = NULL;
  X509_NAME *name = NULL;

  ENTERING(x509_object_set_subject);

  if (!PyArg_ParseTuple(args, "O", &name_sequence))
    goto error;

  if (!PySequence_Check(name_sequence))
    lose_type_error("Expected a sequence object");

  if ((name = x509_object_helper_set_name(name_sequence)) == NULL)
    goto error;

  if (!X509_set_subject_name(self->x509, name))
    lose("Unable to set subject name");

  X509_NAME_free(name);

  Py_RETURN_NONE;

 error:
  X509_NAME_free(name);
  return NULL;
}

static char x509_object_set_issuer__doc__[] =
  "Set this certificate's issuer name.\n"
  "\n"
  "The \"name\" parameter should be in the same format as the return\n"
  "value from the \"getIssuer\" method.\n"
  ;

static PyObject *
x509_object_set_issuer(x509_object *self, PyObject *args)
{
  PyObject *name_sequence = NULL;
  X509_NAME *name = NULL;

  ENTERING(x509_object_set_issuer);

  if (!PyArg_ParseTuple(args, "O", &name_sequence))
    goto error;

  if (!PySequence_Check(name_sequence))
    lose_type_error("Expected a sequence object");

  if ((name = x509_object_helper_set_name(name_sequence)) == NULL)
    goto error;

  if (!X509_set_issuer_name(self->x509, name))
    lose("Unable to set issuer name");

  X509_NAME_free(name);

  Py_RETURN_NONE;

 error:
  X509_NAME_free(name);
  return  NULL;
}

static char x509_object_get_issuer_hash__doc__[] =
  "Return the OpenSSL \"name hash\" for this certificate's issuer name.\n"
  ;

static PyObject *
x509_object_get_issuer_hash(x509_object *self)
{
  ENTERING(x509_object_get_issuer_hash);
  return Py_BuildValue("k", X509_NAME_hash(X509_get_issuer_name(self->x509)));
}

static char x509_object_get_subject_hash__doc__[] =
  "Return the OpenSSL \"name hash\" for this certificate's subject name.\n"
  ;

static PyObject *
x509_object_get_subject_hash(x509_object *self)
{
  ENTERING(x509_object_get_subject_hash);
  return Py_BuildValue("k", X509_NAME_hash(X509_get_subject_name(self->x509)));
}

static char x509_object_get_not_before__doc__[] =
  "Return this certificate's \"notBefore\" value as a datetime.\n"
  ;

static PyObject *
x509_object_get_not_before (x509_object *self)
{
  ENTERING(x509_object_get_not_before);
  return ASN1_TIME_to_Python(X509_get_notBefore(self->x509));
}

static char x509_object_get_not_after__doc__[] =
  "Return this certificate's \"notAfter\" value as a datetime.\n"
  ;

static PyObject *
x509_object_get_not_after (x509_object *self)
{
  ENTERING(x509_object_get_not_after);
  return ASN1_TIME_to_Python(X509_get_notAfter(self->x509));
}

static char x509_object_set_not_after__doc__[] =
  "Set this certificate's \"notAfter\" value.\n"
  "\n"
  "The \"time\" parameter should be a datetime object.\n"
  ;

static PyObject *
x509_object_set_not_after (x509_object *self, PyObject *args)
{
  PyObject *o = NULL;
  ASN1_TIME *t = NULL;

  ENTERING(x509_object_set_not_after);

  if (!PyArg_ParseTuple(args, "O", &o))
    goto error;

  if ((t = Python_to_ASN1_TIME(o, 1)) == NULL)
    lose("Couldn't convert notAfter string");

  if (!X509_set_notAfter(self->x509, t))
    lose("Couldn't set notAfter");

  ASN1_TIME_free(t);
  Py_RETURN_NONE;

 error:
  ASN1_TIME_free(t);
  return NULL;
}

static char x509_object_set_not_before__doc__[] =
  "Set this certificate's \"notBefore\" value.\n"
  "\n"
  "The \"time\" parameter should be a datetime object.\n"
  ;

static PyObject *
x509_object_set_not_before (x509_object *self, PyObject *args)
{
  PyObject *o = NULL;
  ASN1_TIME *t = NULL;

  ENTERING(x509_object_set_not_before);

  if (!PyArg_ParseTuple(args, "O", &o))
    goto error;

  if ((t = Python_to_ASN1_TIME(o, 1)) == NULL)
    lose("Couldn't convert notBefore string");

  if (!X509_set_notBefore(self->x509, t))
    lose("Couldn't set notBefore");

  ASN1_TIME_free(t);
  Py_RETURN_NONE;

 error:
  ASN1_TIME_free(t);
  return NULL;
}

static char x509_object_clear_extensions__doc__[] =
  "Clear all extensions attached to this certificate.\n"
  ;

static PyObject *
x509_object_clear_extensions(x509_object *self)
{
  X509_EXTENSION *ext;

  ENTERING(x509_object_clear_extensions);

  while ((ext = X509_delete_ext(self->x509, 0)) != NULL)
    X509_EXTENSION_free(ext);

  Py_RETURN_NONE;
}

static char x509_object_get_ski__doc__[] =
  EXTENSION_GET_SKI__DOC__
  ;

static PyObject *
x509_object_get_ski(x509_object *self)
{
  return extension_get_ski(x509_object_extension_get_helper(self, NID_subject_key_identifier));
}

static char x509_object_set_ski__doc__[] =
  EXTENSION_SET_SKI__DOC__
  ;

static PyObject *
x509_object_set_ski(x509_object *self, PyObject *args)
{
  return x509_object_extension_set_helper(self, extension_set_ski(args));
}

static char x509_object_get_aki__doc__[] =
  EXTENSION_GET_AKI__DOC__
  ;

static PyObject *
x509_object_get_aki(x509_object *self)
{
  return extension_get_aki(x509_object_extension_get_helper(self, NID_authority_key_identifier));
}

static char x509_object_set_aki__doc__[] =
  EXTENSION_SET_AKI__DOC__
  ;

static PyObject *
x509_object_set_aki(x509_object *self, PyObject *args)
{
  return x509_object_extension_set_helper(self, extension_set_aki(args));
}

static char x509_object_get_key_usage__doc__[] =
  EXTENSION_GET_KEY_USAGE__DOC__
  ;

static PyObject *
x509_object_get_key_usage(x509_object *self)
{
  return extension_get_key_usage(x509_object_extension_get_helper(self, NID_key_usage));
}

static char x509_object_set_key_usage__doc__[] =
  "Set the KeyUsage extension for this certificate.\n"
  "\n"
  EXTENSION_SET_KEY_USAGE__DOC__
  ;

static PyObject *
x509_object_set_key_usage(x509_object *self, PyObject *args)
{
  return x509_object_extension_set_helper(self, extension_set_key_usage(args));
}

static char x509_object_get_eku__doc__[] =
  EXTENSION_GET_EKU__DOC__
  ;

static PyObject *
x509_object_get_eku(x509_object *self)
{
  return extension_get_eku(x509_object_extension_get_helper(self, NID_ext_key_usage));
}

static char x509_object_set_eku__doc__[] =
  "Set the ExtendedKeyUsage extension for this certificate.\n"
  "\n"
  EXTENSION_SET_EKU__DOC__
  ;

static PyObject *
x509_object_set_eku(x509_object *self, PyObject *args)
{
  return x509_object_extension_set_helper(self, extension_set_eku(args));
}

static char x509_object_get_rfc3779__doc__[] =
  "Return this certificate's RFC 3779 resources.\n"
  "\n"
  "Return value is a three-element tuple: the first element is the ASN\n"
  "resources, the second is the IPv4 resources, the third is the IPv6\n"
  "resources.  Each of these elements in turn can be:\n"
  "\n"
  "* None, if this certificate contains no resources of this kind;\n"
  "\n"
  "* the string \"inherit\", if this certificate inherits this kind\n"
  "  of resources from its  issuer; or\n"
  "\n"
  "* a tuple representing a set of ranges of ASNs or IP addresses.\n"
  "\n"
  "Each range is a two-element tuple, respectively representing the low\n"
  "and high ends of the range, inclusive.  ASN ranges are represented by\n"
  "pairs of integers, IP address ranges are represented by pairs of\n"
  "IPAddress objects.\n"
  ;

static PyObject *
x509_object_get_rfc3779(x509_object *self)
{
  PyObject *result = NULL;
  PyObject *asn_result = NULL;
  PyObject *ipv4_result = NULL;
  PyObject *ipv6_result = NULL;
  PyObject *range = NULL;
  PyObject *range_b = NULL;
  PyObject *range_e = NULL;
  ASIdentifiers *asid = NULL;
  IPAddrBlocks *addr = NULL;
  int i, j;

  ENTERING(x509_object_get_rfc3779);

  if ((asid = X509_get_ext_d2i(self->x509, NID_sbgp_autonomousSysNum, NULL, NULL)) != NULL &&
      asid->asnum != NULL) {
    switch (asid->asnum->type) {

    case ASIdentifierChoice_inherit:
      if ((asn_result = PyString_FromString("inherit")) == NULL)
        goto error;
      break;

    case ASIdentifierChoice_asIdsOrRanges:

      if ((asn_result = PyTuple_New(sk_ASIdOrRange_num(asid->asnum->u.asIdsOrRanges))) == NULL)
        goto error;

      for (i = 0; i < sk_ASIdOrRange_num(asid->asnum->u.asIdsOrRanges); i++) {
        ASIdOrRange *aor = sk_ASIdOrRange_value(asid->asnum->u.asIdsOrRanges, i);
        ASN1_INTEGER *b = NULL;
        ASN1_INTEGER *e = NULL;

        switch (aor->type) {

        case ASIdOrRange_id:
          b = e = aor->u.id;
          break;

        case ASIdOrRange_range:
          b = aor->u.range->min;
          e = aor->u.range->max;
          break;

        default:
          lose_value_error("Unexpected asIdsOrRanges type");
        }

        if (ASN1_STRING_type(b) == V_ASN1_NEG_INTEGER ||
            ASN1_STRING_type(e) == V_ASN1_NEG_INTEGER)
          lose_value_error("I don't believe in negative ASNs");

        if ((range_b = ASN1_INTEGER_to_PyLong(b)) == NULL ||
            (range_e = ASN1_INTEGER_to_PyLong(e)) == NULL ||
            (range = Py_BuildValue("(NN)", range_b, range_e)) == NULL)
          goto error;

        PyTuple_SET_ITEM(asn_result, i, range);
        range = range_b = range_e = NULL;
      }

      break;

    default:
      lose_value_error("Unexpected ASIdentifierChoice type");
    }
  }

  if ((addr = X509_get_ext_d2i(self->x509, NID_sbgp_ipAddrBlock, NULL, NULL)) != NULL) {
    for (i = 0; i < sk_IPAddressFamily_num(addr); i++) {
      IPAddressFamily *f = sk_IPAddressFamily_value(addr, i);
      const struct ipaddress_version *ip_type = NULL;
      const unsigned int afi = v3_addr_get_afi(f);
      PyObject **result_obj = NULL;
      int addr_len = 0;

      switch (afi) {
      case IANA_AFI_IPV4: result_obj = &ipv4_result; ip_type = &ipaddress_version_4; break;
      case IANA_AFI_IPV6: result_obj = &ipv6_result; ip_type = &ipaddress_version_6; break;
      default:            lose_value_error("Unknown AFI");
      }

      if (*result_obj != NULL)
        lose_value_error("Duplicate IPAddressFamily");

      if (f->addressFamily->length > 2)
        lose_value_error("Unsupported SAFI");

      switch (f->ipAddressChoice->type) {

      case IPAddressChoice_inherit:
        if ((*result_obj = PyString_FromString("inherit")) == NULL)
          goto error;
        continue;

      case IPAddressChoice_addressesOrRanges:
        break;

      default:
        lose_value_error("Unexpected IPAddressChoice type");
      }

      if ((*result_obj = PyTuple_New(sk_IPAddressOrRange_num(f->ipAddressChoice->u.addressesOrRanges))) == NULL)
        goto error;

      for (j = 0; j < sk_IPAddressOrRange_num(f->ipAddressChoice->u.addressesOrRanges); j++) {
        IPAddressOrRange *aor = sk_IPAddressOrRange_value(f->ipAddressChoice->u.addressesOrRanges, j);
        ipaddress_object *addr_b = NULL;
        ipaddress_object *addr_e = NULL;

        if ((range_b = POW_IPAddress_Type.tp_alloc(&POW_IPAddress_Type, 0)) == NULL ||
            (range_e = POW_IPAddress_Type.tp_alloc(&POW_IPAddress_Type, 0)) == NULL)
          goto error;

        addr_b = (ipaddress_object *) range_b;
        addr_e = (ipaddress_object *) range_e;

        if ((addr_len = v3_addr_get_range(aor, afi, addr_b->address, addr_e->address,
                                          sizeof(addr_b->address))) == 0)
          lose_value_error("Couldn't unpack IP addresses from BIT STRINGs");

        addr_b->type = addr_e->type = ip_type;

        if ((range = Py_BuildValue("(NN)", range_b, range_e)) == NULL)
          goto error;

        PyTuple_SET_ITEM(*result_obj, j, range);
        range = range_b = range_e = NULL;
      }
    }
  }

  result = Py_BuildValue("(OOO)",
                         (asn_result  == NULL ? Py_None : asn_result),
                         (ipv4_result == NULL ? Py_None : ipv4_result),
                         (ipv6_result == NULL ? Py_None : ipv6_result));

 error:                         /* Fall through */
  ASIdentifiers_free(asid);
  sk_IPAddressFamily_pop_free(addr, IPAddressFamily_free);
  Py_XDECREF(range_b);
  Py_XDECREF(range_e);
  Py_XDECREF(range);
  Py_XDECREF(asn_result);
  Py_XDECREF(ipv4_result);
  Py_XDECREF(ipv6_result);

  return result;
}

static char x509_object_set_rfc3779__doc__[] =
  "Set this certificate's RFC 3779 resources.\n"
  "\n"
  "This method takes three arguments: \"asn\", \"ipv4\", and \"ipv6\".\n"
  "\n"
  "Each of these arguments can be:\n"
  "\n"
  "* None, to omit this kind of resource;\n"
  "\n"
  "* The string \"inherit\", to specify RFC 3779 resource inheritance; or\n"
  "\n"
  "* An iterable object which returns range pairs of the appropriate type.\n"
  "\n"
  "Range pairs are as returned by the .getRFC3779() method.\n"
  ;

static PyObject *
x509_object_set_rfc3779(x509_object *self, PyObject *args, PyObject *kwds)
{
  static char *kwlist[] = {"asn", "ipv4", "ipv6", NULL};
  PyObject *asn_arg  = Py_None;
  PyObject *ipv4_arg = Py_None;
  PyObject *ipv6_arg = Py_None;
  PyObject *iterator = NULL;
  PyObject *item = NULL;
  PyObject *fast = NULL;
  ASIdentifiers *asid = NULL;
  IPAddrBlocks *addr = NULL;
  ASN1_INTEGER *asid_b = NULL;
  ASN1_INTEGER *asid_e = NULL;
  ipaddress_object *addr_b = NULL;
  ipaddress_object *addr_e = NULL;
  int empty = 0;

  ENTERING(x509_object_set_rfc3779);

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "|OOO", kwlist, &asn_arg, &ipv4_arg, &ipv6_arg))
    goto error;

  if (asn_arg != Py_None) {

    empty = 1;

    if ((asid = ASIdentifiers_new()) == NULL)
      lose_no_memory();

    if (PyString_Check(asn_arg)) {

      if (strcmp(PyString_AsString(asn_arg), "inherit"))
        lose_type_error("ASID must be an iterable that returns range pairs, or the string \"inherit\"");

      if (!v3_asid_add_inherit(asid, V3_ASID_ASNUM))
        lose_no_memory();

      empty = 0;

    } else {

      if ((iterator = PyObject_GetIter(asn_arg)) == NULL)
        goto error;

      while ((item = PyIter_Next(iterator)) != NULL) {

        if ((fast = PySequence_Fast(item, "ASN range must be a sequence")) == NULL)
          goto error;

        if (PySequence_Fast_GET_SIZE(fast) != 2)
          lose_type_error("ASN range must be two-element sequence");

        if ((asid_b = PyLong_to_ASN1_INTEGER(PySequence_Fast_GET_ITEM(fast, 0))) == NULL)
          goto error;

        switch (PyObject_RichCompareBool(PySequence_Fast_GET_ITEM(fast, 0),
                                         PySequence_Fast_GET_ITEM(fast, 1), Py_EQ)) {
        case 0:
          if ((asid_e = PyLong_to_ASN1_INTEGER(PySequence_Fast_GET_ITEM(fast, 1))) == NULL)
            goto error;
          break;
        case 1:
          break;
        default:
          goto error;
        }

        if (!v3_asid_add_id_or_range(asid, V3_ASID_ASNUM, asid_b, asid_e))
          lose_openssl_error("Couldn't add range to ASID");

        asid_b = asid_e = NULL;
        Py_XDECREF(item);
        Py_XDECREF(fast);
        item = fast = NULL;
        empty = 0;
      }

      Py_XDECREF(iterator);
      iterator = NULL;
    }

    if (!empty && (!v3_asid_canonize(asid) ||
                   !X509_add1_ext_i2d(self->x509, NID_sbgp_autonomousSysNum,
                                      asid, 1, X509V3_ADD_REPLACE)))
      lose_openssl_error("Couldn't add ASID extension to certificate");
  }

  if (ipv4_arg != Py_None || ipv6_arg != Py_None) {
    int v;
 
    empty = 1;

    if ((addr = sk_IPAddressFamily_new_null()) == NULL)
      lose_no_memory();

    /*
     * Cheap trick to let us inline all of this instead of being
     * forced to use a separate function.  Refactor, some day.
     */

    for (v = 0; v < (int) (sizeof(ipaddress_versions)/sizeof(*ipaddress_versions)); v++) {
      const struct ipaddress_version *ip_type = ipaddress_versions[v];
      PyObject **argp;

      switch (ip_type->version) {
      case 4: argp = &ipv4_arg; break;
      case 6: argp = &ipv6_arg; break;
      default: continue;        /* Never happens */
      }

      if (PyString_Check(*argp)) {

        if (strcmp(PyString_AsString(*argp), "inherit"))
          lose_type_error("Argument must be an iterable that returns range pairs, or the string \"inherit\"");

        if (!v3_addr_add_inherit(addr, ip_type->afi, NULL))
          lose_no_memory();

        empty = 0;

      } else {

        if ((iterator = PyObject_GetIter(*argp)) == NULL)
          goto error;

        while ((item = PyIter_Next(iterator)) != NULL) {

          if ((fast = PySequence_Fast(item, "Address range must be a sequence")) == NULL)
            goto error;

          if (PySequence_Fast_GET_SIZE(fast) != 2 ||
              !POW_IPAddress_Check(PySequence_Fast_GET_ITEM(fast, 0)) ||
              !POW_IPAddress_Check(PySequence_Fast_GET_ITEM(fast, 1)))
            lose_type_error("Address range must be two-element sequence of IPAddress objects");

          addr_b = (ipaddress_object *) PySequence_Fast_GET_ITEM(fast, 0);
          addr_e = (ipaddress_object *) PySequence_Fast_GET_ITEM(fast, 1);

          if (addr_b->type != ip_type ||
              addr_e->type != ip_type ||
              memcmp(addr_b->address, addr_e->address, ip_type->length) > 0)
            lose("Address range must be two-element sequence of IPAddress objects in ascending order");

          if (!v3_addr_add_range(addr, ip_type->afi, NULL, addr_b->address, addr_e->address))
            lose_openssl_error("Couldn't add range to IPAddrBlock");

          Py_XDECREF(item);
          Py_XDECREF(fast);
          item = fast = NULL;
          addr_b = addr_e = NULL;
          empty = 0;
        }

        Py_XDECREF(iterator);
        iterator = NULL;
      }
    }

    if (!empty && (!v3_addr_canonize(addr) ||
                   !X509_add1_ext_i2d(self->x509, NID_sbgp_ipAddrBlock,
                                      addr, 1, X509V3_ADD_REPLACE)))
      lose_openssl_error("Couldn't add IPAddrBlock extension to certificate");
  }

  Py_RETURN_NONE;

 error:
  ASN1_INTEGER_free(asid_b);
  ASN1_INTEGER_free(asid_e);
  ASIdentifiers_free(asid);
  sk_IPAddressFamily_pop_free(addr, IPAddressFamily_free);
  Py_XDECREF(iterator);
  Py_XDECREF(item);
  Py_XDECREF(fast);
  return NULL;
}

static char x509_object_get_basic_constraints__doc__[] =
  "Return BasicConstraints for this certificate.\n"
  "\n"
  EXTENSION_GET_BASIC_CONSTRAINTS__DOC__
  ;

static PyObject *
x509_object_get_basic_constraints(x509_object *self)
{
  return extension_get_basic_constraints(x509_object_extension_get_helper(self, NID_basic_constraints));
}

static char x509_object_set_basic_constraints__doc__[] =
  "Set BasicConstraints for this certificate.\n"
  "\n"
  EXTENSION_SET_BASIC_CONSTRAINTS__DOC__
  ;

static PyObject *
x509_object_set_basic_constraints(x509_object *self, PyObject *args)
{
  return x509_object_extension_set_helper(self, extension_set_basic_constraints(args));
}

static char x509_object_get_sia__doc__[] =
  "Get SIA values for this certificate.\n"
  "\n"
  EXTENSION_GET_SIA__DOC__
  ;

static PyObject *
x509_object_get_sia(x509_object *self)
{
  return extension_get_sia(x509_object_extension_get_helper(self, NID_sinfo_access));
}

static char x509_object_set_sia__doc__[] =
  "Set SIA values for this certificate.\n"
  "\n"
  EXTENSION_SET_SIA__DOC__
  ;

static PyObject *
x509_object_set_sia(x509_object *self, PyObject *args, PyObject *kwds)
{
  return x509_object_extension_set_helper(self, extension_set_sia(args, kwds));
}

static char x509_object_get_aia__doc__[] =
  "Get this certificate's AIA values.\n"
  "\n"
  "If the certificate has no AIA extension, this method returns None.\n"
  "\n"  
  "Otherwise, this returns a sequence of caIssuers URIs.\n"
  "\n"
  "Any other accessMethods are ignored, as are any non-URI accessLocations.\n"
  ;

static PyObject *
x509_object_get_aia(x509_object *self)
{
  AUTHORITY_INFO_ACCESS *ext = NULL;
  PyObject *result = NULL;
  const char *uri;
  PyObject *obj;
  int i, n = 0;

  ENTERING(x509_object_get_aia);

  if ((ext = X509_get_ext_d2i(self->x509, NID_info_access, NULL, NULL)) == NULL)
    Py_RETURN_NONE;

  for (i = 0; i < sk_ACCESS_DESCRIPTION_num(ext); i++) {
    ACCESS_DESCRIPTION *a = sk_ACCESS_DESCRIPTION_value(ext, i);
    if (a->location->type == GEN_URI &&
        OBJ_obj2nid(a->method) == NID_ad_ca_issuers)
      n++;
  }

  if (((result = PyTuple_New(n)) == NULL))
    goto error;

  n = 0;

  for (i = 0; i < sk_ACCESS_DESCRIPTION_num(ext); i++) {
    ACCESS_DESCRIPTION *a = sk_ACCESS_DESCRIPTION_value(ext, i);
    if (a->location->type == GEN_URI && OBJ_obj2nid(a->method) == NID_ad_ca_issuers) {
      uri = (char *) ASN1_STRING_data(a->location->d.uniformResourceIdentifier);
      if ((obj = PyString_FromString(uri)) == NULL)
        goto error;
      PyTuple_SET_ITEM(result, n++, obj);
    }
  }

  AUTHORITY_INFO_ACCESS_free(ext);
  return result;

 error:
  AUTHORITY_INFO_ACCESS_free(ext);
  Py_XDECREF(result);
  return NULL;
}

static char x509_object_set_aia__doc__[] =
  "Set AIA URIs for this certificate.\n"
  "\n"
  "Argument is a iterable which returns caIssuers URIs.\n"
  ;

static PyObject *
x509_object_set_aia(x509_object *self, PyObject *args)
{
  AUTHORITY_INFO_ACCESS *ext = NULL;
  PyObject *caIssuers = NULL;
  PyObject *iterator = NULL;
  ASN1_OBJECT *oid = NULL;
  PyObject *item = NULL;
  ACCESS_DESCRIPTION *a = NULL;
  int ok = 0;
  Py_ssize_t urilen;
  char *uri;

  ENTERING(x509_object_set_aia);

  if (!PyArg_ParseTuple(args, "O", &caIssuers))
    goto error;

  if ((ext = AUTHORITY_INFO_ACCESS_new()) == NULL)
    lose_no_memory();

  if ((oid = OBJ_nid2obj(NID_ad_ca_issuers)) == NULL)
    lose_openssl_error("Couldn't find AIA accessMethod OID");

  if ((iterator = PyObject_GetIter(caIssuers)) == NULL)
    goto error;

  while ((item = PyIter_Next(iterator)) != NULL) {

    if (PyString_AsStringAndSize(item, &uri, &urilen) < 0)
      goto error;

    if ((a = ACCESS_DESCRIPTION_new()) == NULL ||
        (a->method = OBJ_dup(oid)) == NULL ||
        (a->location->d.uniformResourceIdentifier = ASN1_IA5STRING_new()) == NULL ||
        !ASN1_OCTET_STRING_set(a->location->d.uniformResourceIdentifier, (unsigned char *) uri, urilen))
      lose_no_memory();

    a->location->type = GEN_URI;

    if (!sk_ACCESS_DESCRIPTION_push(ext, a))
      lose_no_memory();

    a = NULL;
    Py_XDECREF(item);
    item = NULL;
  }

  Py_XDECREF(iterator);
  iterator = NULL;

  if (!X509_add1_ext_i2d(self->x509, NID_info_access, ext, 0, X509V3_ADD_REPLACE))
    lose_openssl_error("Couldn't add AIA extension to certificate");

  ok = 1;

 error:
  AUTHORITY_INFO_ACCESS_free(ext);
  ACCESS_DESCRIPTION_free(a);
  Py_XDECREF(item);
  Py_XDECREF(iterator);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char x509_object_get_crldp__doc__[] =
  "Get CRL Distribution Point (CRLDP) values for this certificate.\n"
  "\n"
  "If the certificate has no CRLDP extension, this method returns None.\n"
  "\n"
  "Otherwise, it returns a sequence of URIs representing distributionPoint\n"
  "fullName values found in the first Distribution Point.  Other CRLDP\n"
  "fields are ignored, as are subsequent Distribution Points and any non-URI\n"
  "fullName values.\n"
  ;

static PyObject *
x509_object_get_crldp(x509_object *self)
{
  CRL_DIST_POINTS *ext = NULL;
  DIST_POINT *dp = NULL;
  PyObject *result = NULL;
  const char *uri;
  PyObject *obj;
  int i, n = 0;

  ENTERING(x509_object_get_crldp);

  if ((ext = X509_get_ext_d2i(self->x509, NID_crl_distribution_points, NULL, NULL)) == NULL ||
      (dp = sk_DIST_POINT_value(ext, 0)) == NULL ||
      dp->distpoint == NULL ||
      dp->distpoint->type != 0)
    Py_RETURN_NONE;

  for (i = 0; i < sk_GENERAL_NAME_num(dp->distpoint->name.fullname); i++) {
    GENERAL_NAME *gn = sk_GENERAL_NAME_value(dp->distpoint->name.fullname, i);
    if (gn->type == GEN_URI)
      n++;
  }

  if (((result = PyTuple_New(n)) == NULL))
    goto error;

  n = 0;

  for (i = 0; i < sk_GENERAL_NAME_num(dp->distpoint->name.fullname); i++) {
    GENERAL_NAME *gn = sk_GENERAL_NAME_value(dp->distpoint->name.fullname, i);
    if (gn->type == GEN_URI) {
      uri = (char *) ASN1_STRING_data(gn->d.uniformResourceIdentifier);
      if ((obj = PyString_FromString(uri)) == NULL)
        goto error;
      PyTuple_SET_ITEM(result, n++, obj);
    }
  }

  sk_DIST_POINT_pop_free(ext, DIST_POINT_free);
  return result;

 error:
  sk_DIST_POINT_pop_free(ext, DIST_POINT_free);
  Py_XDECREF(result);
  return NULL;
}

static char x509_object_set_crldp__doc__[] =
  "Set CRLDP values for this certificate.\n"
  "\n"
  "Argument is a iterable which returns distributionPoint fullName URIs.\n"
  ;

static PyObject *
x509_object_set_crldp(x509_object *self, PyObject *args)
{
  CRL_DIST_POINTS *ext = NULL;
  PyObject *fullNames = NULL;
  PyObject *iterator = NULL;
  PyObject *item = NULL;
  DIST_POINT *dp = NULL;
  GENERAL_NAME *gn = NULL;
  Py_ssize_t urilen;
  char *uri;
  int ok = 0;

  ENTERING(x509_object_set_crldp);

  if (!PyArg_ParseTuple(args, "O", &fullNames))
    goto error;

  if ((ext = sk_DIST_POINT_new_null()) == NULL ||
      (dp = DIST_POINT_new()) == NULL ||
      (dp->distpoint = DIST_POINT_NAME_new()) == NULL ||
      (dp->distpoint->name.fullname = sk_GENERAL_NAME_new_null()) == NULL)
    lose_no_memory();

  dp->distpoint->type = 0;

  if ((iterator = PyObject_GetIter(fullNames)) == NULL)
    goto error;

  while ((item = PyIter_Next(iterator)) != NULL) {

    if (PyString_AsStringAndSize(item, &uri, &urilen) < 0)
      goto error;

    if ((gn = GENERAL_NAME_new()) == NULL ||
        (gn->d.uniformResourceIdentifier = ASN1_IA5STRING_new()) == NULL ||
        !ASN1_OCTET_STRING_set(gn->d.uniformResourceIdentifier, (unsigned char *) uri, urilen))
      lose_no_memory();

    gn->type = GEN_URI;

    if (!sk_GENERAL_NAME_push(dp->distpoint->name.fullname, gn))
      lose_no_memory();

    gn = NULL;
    Py_XDECREF(item);
    item = NULL;
  }

  Py_XDECREF(iterator);
  iterator = NULL;

  if (!sk_DIST_POINT_push(ext, dp))
    lose_no_memory();

  dp = NULL;

  if (!X509_add1_ext_i2d(self->x509, NID_crl_distribution_points, ext, 0, X509V3_ADD_REPLACE))
    lose_openssl_error("Couldn't add CRLDP extension to certificate");

  ok = 1;

 error:
  sk_DIST_POINT_pop_free(ext, DIST_POINT_free);
  DIST_POINT_free(dp);
  GENERAL_NAME_free(gn);
  Py_XDECREF(item);
  Py_XDECREF(iterator);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char x509_object_get_certificate_policies__doc__[] =
  "Get Certificate Policies values for this certificate.\n"
  "\n"
  "If this certificate has no Certificate Policies extension, this method\n"
  "returns None.\n"
  "\n"
  "Otherwise, this method returns a sequence of Object Identifiers.\n"
  "\n"
  "Policy qualifiers, if any, are ignored.\n"
  ;

static PyObject *
x509_object_get_certificate_policies(x509_object *self)
{
  CERTIFICATEPOLICIES *ext = NULL;
  PyObject *result = NULL;
  PyObject *obj;
  int i;

  ENTERING(x509_object_get_certificate_policies);

  if ((ext = X509_get_ext_d2i(self->x509, NID_certificate_policies, NULL, NULL)) == NULL)
    Py_RETURN_NONE;

  if (((result = PyTuple_New(sk_POLICYINFO_num(ext))) == NULL))
    goto error;

  for (i = 0; i < sk_POLICYINFO_num(ext); i++) {
    POLICYINFO *p = sk_POLICYINFO_value(ext, i);

    if ((obj = ASN1_OBJECT_to_PyString(p->policyid)) == NULL)
      goto error;

    PyTuple_SET_ITEM(result, i, obj);
  }

  sk_POLICYINFO_pop_free(ext, POLICYINFO_free);
  return result;

 error:
  sk_POLICYINFO_pop_free(ext, POLICYINFO_free);
  Py_XDECREF(result);
  return NULL;
}

static char x509_object_set_certificate_policies__doc__[] =
  "Set Certificate Policies for this certificate.\n"
  "\n"
  "Argument is a iterable which returns policy OIDs.\n"
  "\n"  
  "Policy qualifier are not supported.\n"
  "\n"
  "The extension will be marked as critical, since there's not much point\n"
  "in using this extension without making it critical.\n"
  ;

static PyObject *
x509_object_set_certificate_policies(x509_object *self, PyObject *args)
{
  CERTIFICATEPOLICIES *ext = NULL;
  PyObject *policies = NULL;
  PyObject *iterator = NULL;
  POLICYINFO *pol = NULL;
  PyObject *item = NULL;
  const char *oid;
  int ok = 0;

  ENTERING(x509_object_set_certificate_policies);

  if (!PyArg_ParseTuple(args, "O", &policies))
    goto error;

  if ((ext = sk_POLICYINFO_new_null()) == NULL)
    lose_no_memory();

  if ((iterator = PyObject_GetIter(policies)) == NULL)
    goto error;

  while ((item = PyIter_Next(iterator)) != NULL) {

    if ((oid = PyString_AsString(item)) == NULL)
      goto error;

    if ((pol = POLICYINFO_new()) == NULL)
      lose_no_memory();

    if ((pol->policyid = OBJ_txt2obj(oid, 1)) == NULL)
      lose("Couldn't parse OID");

    if (!sk_POLICYINFO_push(ext, pol))
      lose_no_memory();

    pol = NULL;
    Py_XDECREF(item);
    item = NULL;
  }

  Py_XDECREF(iterator);
  iterator = NULL;

  if (!X509_add1_ext_i2d(self->x509, NID_certificate_policies, ext, 1, X509V3_ADD_REPLACE))
    lose_openssl_error("Couldn't add CERTIFICATE_POLICIES extension to certificate");

  ok = 1;

 error:
  POLICYINFO_free(pol);
  sk_POLICYINFO_pop_free(ext, POLICYINFO_free);
  Py_XDECREF(item);
  Py_XDECREF(iterator);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char x509_object_pprint__doc__[] =
  "Return a pretty-printed rendition of this certificate.\n"
  ;

static PyObject *
x509_object_pprint(x509_object *self)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  ENTERING(x509_object_pprint);

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  if (!X509_print(bio, self->x509))
    lose_openssl_error("Unable to pretty-print certificate");

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static struct PyMethodDef x509_object_methods[] = {
  Define_Method(pemWrite,               x509_object_pem_write,                  METH_NOARGS),
  Define_Method(derWrite,               x509_object_der_write,                  METH_NOARGS),
  Define_Method(sign,                   x509_object_sign,                       METH_VARARGS),
  Define_Method(verify,                 x509_object_verify,                     METH_KEYWORDS),
  Define_Method(checkRPKIConformance,   x509_object_check_rpki_conformance,     METH_KEYWORDS),
  Define_Method(getPublicKey,           x509_object_get_public_key,             METH_NOARGS),
  Define_Method(setPublicKey,           x509_object_set_public_key,             METH_VARARGS),
  Define_Method(getVersion,             x509_object_get_version,                METH_NOARGS),
  Define_Method(setVersion,             x509_object_set_version,                METH_VARARGS),
  Define_Method(getSerial,              x509_object_get_serial,                 METH_NOARGS),
  Define_Method(setSerial,              x509_object_set_serial,                 METH_VARARGS),
  Define_Method(getIssuer,              x509_object_get_issuer,                 METH_VARARGS),
  Define_Method(setIssuer,              x509_object_set_issuer,                 METH_VARARGS),
  Define_Method(getSubject,             x509_object_get_subject,                METH_VARARGS),
  Define_Method(setSubject,             x509_object_set_subject,                METH_VARARGS),
  Define_Method(getNotBefore,           x509_object_get_not_before,             METH_NOARGS),
  Define_Method(getNotAfter,            x509_object_get_not_after,              METH_NOARGS),
  Define_Method(setNotAfter,            x509_object_set_not_after,              METH_VARARGS),
  Define_Method(setNotBefore,           x509_object_set_not_before,             METH_VARARGS),
  Define_Method(clearExtensions,        x509_object_clear_extensions,           METH_NOARGS),
  Define_Method(pprint,                 x509_object_pprint,                     METH_NOARGS),
  Define_Method(getSKI,                 x509_object_get_ski,                    METH_NOARGS),
  Define_Method(setSKI,                 x509_object_set_ski,                    METH_VARARGS),
  Define_Method(getAKI,                 x509_object_get_aki,                    METH_NOARGS),
  Define_Method(setAKI,                 x509_object_set_aki,                    METH_VARARGS),
  Define_Method(getKeyUsage,            x509_object_get_key_usage,              METH_NOARGS),
  Define_Method(setKeyUsage,            x509_object_set_key_usage,              METH_VARARGS),
  Define_Method(getEKU,                 x509_object_get_eku,                    METH_NOARGS),
  Define_Method(setEKU,                 x509_object_set_eku,                    METH_VARARGS),
  Define_Method(getRFC3779,             x509_object_get_rfc3779,                METH_NOARGS),
  Define_Method(setRFC3779,             x509_object_set_rfc3779,                METH_KEYWORDS),
  Define_Method(getBasicConstraints,    x509_object_get_basic_constraints,      METH_NOARGS),
  Define_Method(setBasicConstraints,    x509_object_set_basic_constraints,      METH_VARARGS),
  Define_Method(getSIA,                 x509_object_get_sia,                    METH_NOARGS),
  Define_Method(setSIA,                 x509_object_set_sia,                    METH_KEYWORDS),
  Define_Method(getAIA,                 x509_object_get_aia,                    METH_NOARGS),
  Define_Method(setAIA,                 x509_object_set_aia,                    METH_VARARGS),
  Define_Method(getCRLDP,               x509_object_get_crldp,                  METH_NOARGS),
  Define_Method(setCRLDP,               x509_object_set_crldp,                  METH_VARARGS),
  Define_Method(getCertificatePolicies, x509_object_get_certificate_policies,   METH_NOARGS),
  Define_Method(setCertificatePolicies, x509_object_set_certificate_policies,   METH_VARARGS),
  Define_Method(getIssuerHash,          x509_object_get_issuer_hash,            METH_NOARGS),
  Define_Method(getSubjectHash,         x509_object_get_subject_hash,           METH_NOARGS),
  Define_Class_Method(pemRead,          x509_object_pem_read,                   METH_VARARGS),
  Define_Class_Method(pemReadFile,      x509_object_pem_read_file,              METH_VARARGS),
  Define_Class_Method(derRead,          x509_object_der_read,                   METH_VARARGS),
  Define_Class_Method(derReadFile,      x509_object_der_read_file,              METH_VARARGS),
  {NULL}
};

static char POW_X509_Type__doc__[] =
  "This class represents an X.509v3 certificate.\n"
  ;

static PyTypeObject POW_X509_Type = {
  PyObject_HEAD_INIT(0)
  0,                                        /* ob_size */
  "rpki.POW.X509",                          /* tp_name */
  sizeof(x509_object),                      /* tp_basicsize */
  0,                                        /* tp_itemsize */
  (destructor)x509_object_dealloc,          /* tp_dealloc */
  0,                                        /* tp_print */
  0,                                        /* tp_getattr */
  0,                                        /* tp_setattr */
  0,                                        /* tp_compare */
  0,                                        /* tp_repr */
  0,                                        /* tp_as_number */
  0,                                        /* tp_as_sequence */
  0,                                        /* tp_as_mapping */
  0,                                        /* tp_hash */
  0,                                        /* tp_call */
  0,                                        /* tp_str */
  0,                                        /* tp_getattro */
  0,                                        /* tp_setattro */
  0,                                        /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
  POW_X509_Type__doc__,                     /* tp_doc */
  0,                                        /* tp_traverse */
  0,                                        /* tp_clear */
  0,                                        /* tp_richcompare */
  0,                                        /* tp_weaklistoffset */
  0,                                        /* tp_iter */
  0,                                        /* tp_iternext */
  x509_object_methods,                      /* tp_methods */
  0,                                        /* tp_members */
  0,                                        /* tp_getset */
  0,                                        /* tp_base */
  0,                                        /* tp_dict */
  0,                                        /* tp_descr_get */
  0,                                        /* tp_descr_set */
  0,                                        /* tp_dictoffset */
  0,                                        /* tp_init */
  0,                                        /* tp_alloc */
  x509_object_new,                          /* tp_new */
};



/*
 * X509StoreCTX object.
 */

static int 
x509_store_ctx_object_verify_cb(int ok, X509_STORE_CTX *ctx)
{
  static char method_name[] = "verify_callback";
  x509_store_ctx_object *self = (x509_store_ctx_object *) X509_STORE_CTX_get_ex_data(ctx, x509_store_ctx_ex_data_idx);
  PyObject *result = NULL;

  if (self == NULL)
    return ok;

  if (!PyObject_HasAttrString((PyObject *) self, method_name))
    return ok;

  if ((result = PyObject_CallMethod((PyObject *) self, method_name, "i", ok)) == NULL)
    return -1;

  ok = PyObject_IsTrue(result);
  Py_XDECREF(result);
  return ok;
}

static PyObject *
x509_store_ctx_object_new(PyTypeObject *type, GCC_UNUSED PyObject *args, GCC_UNUSED PyObject *kwds)
{
  x509_store_ctx_object *self = NULL;

  ENTERING(x509_store_ctx_object_new);

  if ((self = (x509_store_ctx_object *) type->tp_alloc(type, 0)) == NULL)
    goto error;

  self->ctx = NULL;
  self->store = NULL;
  return (PyObject *) self;    

 error:
  Py_XDECREF(self);
  return NULL;
}

static int
x509_store_ctx_object_init(x509_store_ctx_object *self, PyObject *args, GCC_UNUSED PyObject *kwds)
{
  ENTERING(x509_store_ctx_object_init);

  if ((self->store = X509_STORE_new()) == NULL ||
      (self->ctx = X509_STORE_CTX_new()) == NULL)
    lose_no_memory();

  if (!X509_STORE_CTX_init(self->ctx, self->store, NULL, NULL))
    lose_openssl_error("Couldn't initialize X509_STORE_CTX");

  if (!X509_STORE_CTX_set_ex_data(self->ctx, x509_store_ctx_ex_data_idx, self))
    lose_openssl_error("Couldn't set X509_STORE_CTX ex_data");

  X509_VERIFY_PARAM_set_flags(self->ctx->param, X509_V_FLAG_X509_STRICT);
  return 0;

 error:
  return -1;
}

static void
x509_store_ctx_object_dealloc(x509_store_ctx_object *self)
{
  ENTERING(x509_store_ctx_object_dealloc);
  X509_STORE_CTX_free(self->ctx);
  X509_STORE_free(self->store);
  self->ob_type->tp_free((PyObject*) self);
}

static char x509_store_ctx_object_get_error__doc__[] =
  "Extract verification error code from this X509StoreCTX.\n"
  ;

static PyObject*
x509_store_ctx_object_get_error (x509_store_ctx_object *self)
{
  return Py_BuildValue("i", X509_STORE_CTX_get_error(self->ctx));
}

static char x509_store_ctx_object_get_error_string__doc__[] =
  "Extract verification error string from this X509StoreCTX.\n"
  ;

static PyObject*
x509_store_ctx_object_get_error_string (x509_store_ctx_object *self)
{
  return Py_BuildValue("s", X509_verify_cert_error_string(X509_STORE_CTX_get_error(self->ctx)));
}

static char x509_store_ctx_object_get_error_depth__doc__[] =
  "Extract verification error depth from this X509StoreCTX.\n"
  ;

static PyObject*
x509_store_ctx_object_get_error_depth (x509_store_ctx_object *self)
{
  return Py_BuildValue("i", X509_STORE_CTX_get_error_depth(self->ctx));
}

static char x509_store_ctx_object_get_current_certificate__doc__[] =
  "Extract the certificate which caused the current validation error,\n"
  "or None if no certificate is relevant.\n"
  ;

static PyObject *
x509_store_ctx_object_get_current_certificate (x509_store_ctx_object *self)
{
  X509 *x = X509_STORE_CTX_get_current_cert(self->ctx);
  x509_object *obj = NULL;

  if (x == NULL)
    Py_RETURN_NONE;

  if ((x = X509_dup(x)) == NULL)
    lose_no_memory();

  if ((obj = x509_object_new_helper(NULL, x)) == NULL)
    goto error;

  return (PyObject *) obj;

 error:
  Py_XDECREF(obj);
  X509_free(x);
  return NULL;
}

static char x509_store_ctx_object_get_chain__doc__[] =
  "Extract certificate chain from X509StoreCTX.  If validation\n"
  "completed succesfully, this is the complete validation chain;\n"
  "otherwise, the returned chain may be invalid or incomplete.\n"
  ;

static PyObject *
x509_store_ctx_object_get_chain (x509_store_ctx_object *self)
{
  STACK_OF(X509) *chain = NULL;
  PyObject *result = NULL;

  if ((chain = X509_STORE_CTX_get1_chain(self->ctx)) == NULL)
    lose_openssl_error("X509_STORE_CTX_get1_chain() failed");
  
  result = stack_to_tuple_helper(CHECKED_PTR_OF(STACK_OF(X509), chain),
                                 stack_to_tuple_helper_get_x509);

 error:                         /* fall through */
  sk_X509_pop_free(chain, X509_free);
  return result;
}

/*
 * See (omnibus) man page for X509_STORE_CTX_get_error() for other
 * query methods we might want to expose.  Someday we might want to
 * support X509_V_FLAG_USE_CHECK_TIME too.
 */

static struct PyMethodDef x509_store_ctx_object_methods[] = {
  Define_Method(getError,               x509_store_ctx_object_get_error,                METH_NOARGS),
  Define_Method(getErrorString,         x509_store_ctx_object_get_error_string,         METH_NOARGS),
  Define_Method(getErrorDepth,          x509_store_ctx_object_get_error_depth,          METH_NOARGS),
  Define_Method(getCurrentCertificate,  x509_store_ctx_object_get_current_certificate,  METH_NOARGS),
  Define_Method(getChain,               x509_store_ctx_object_get_chain,                METH_NOARGS),
 {NULL}
};

static char POW_X509StoreCTX_Type__doc__[] =
  "This class holds the state of an OpenSSL certificate verification\n"
  "operation.  Ordinarily, the user will never have cause to instantiate\n"
  "this class directly, instead, an object of this class will be returned\n"
  "by X509.verify().\n"
  "\n"
  "If you need to see OpenSSL's verification callbacks, you can do so\n"
  "by subclassing X509StoreCTX and passing your subclass as an argument\n"
  "to X509.verify.  Your subclass should provide a .verify_callback()\n"
  "method, which should expect to receive one argument: the integer \"ok\"\n"
  "value passed by OpenSSL's verification callbacks.\n"
  "\n"
  "The return value from your .verify_callback() method will be is interpreted\n"
  "as a boolean value: anything which evaluates to True will be result in a\n"
  "return value of 1 to OpenSSL, while anything which evaluates to False will\n"
  "result in a return value of 0 to OpenSSL.\n"
  ;

static PyTypeObject POW_X509StoreCTX_Type = {
  PyObject_HEAD_INIT(0)
  0,                                        /* ob_size */
  "rpki.POW.X509StoreCTX",                  /* tp_name */
  sizeof(x509_store_ctx_object),            /* tp_basicsize */
  0,                                        /* tp_itemsize */
  (destructor)x509_store_ctx_object_dealloc,/* tp_dealloc */
  0,                                        /* tp_print */
  0,                                        /* tp_getattr */
  0,                                        /* tp_setattr */
  0,                                        /* tp_compare */
  0,                                        /* tp_repr */
  0,                                        /* tp_as_number */
  0,                                        /* tp_as_sequence */
  0,                                        /* tp_as_mapping */
  0,                                        /* tp_hash */
  0,                                        /* tp_call */
  0,                                        /* tp_str */
  0,                                        /* tp_getattro */
  0,                                        /* tp_setattro */
  0,                                        /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
  POW_X509StoreCTX_Type__doc__,             /* tp_doc */
  0,                                        /* tp_traverse */
  0,                                        /* tp_clear */
  0,                                        /* tp_richcompare */
  0,                                        /* tp_weaklistoffset */
  0,                                        /* tp_iter */
  0,                                        /* tp_iternext */
  x509_store_ctx_object_methods,            /* tp_methods */
  0,                                        /* tp_members */
  0,                                        /* tp_getset */
  0,                                        /* tp_base */
  0,                                        /* tp_dict */
  0,                                        /* tp_descr_get */
  0,                                        /* tp_descr_set */
  0,                                        /* tp_dictoffset */
  (initproc) x509_store_ctx_object_init,    /* tp_init */
  0,                                        /* tp_alloc */
  x509_store_ctx_object_new,                /* tp_new */
};



/*
 * CRL object.
 */

static crl_object *
crl_object_new_helper(PyTypeObject *type, X509_CRL *crl)
{
  crl_object *self = NULL;

  if (type == NULL)
    type = &POW_CRL_Type;

  if ((self = (crl_object *) type->tp_alloc(type, 0)) == NULL)
    return NULL;

  self->crl = crl;
  return self;
}

static PyObject *
crl_object_new(PyTypeObject *type, GCC_UNUSED PyObject *args, GCC_UNUSED PyObject *kwds)
{
  crl_object *self = NULL;
  X509_CRL *crl = NULL;

  ENTERING(crl_object_new);

  if ((crl = X509_CRL_new()) == NULL)
    lose_no_memory();

  if ((self = crl_object_new_helper(type, crl)) == NULL)
    goto error;

  return (PyObject *) self;

 error:
  X509_CRL_free(crl);
  return NULL;
}

static void
crl_object_dealloc(crl_object *self)
{
  ENTERING(crl_object_dealloc);
  X509_CRL_free(self->crl);
  self->ob_type->tp_free((PyObject*) self);
}

static PyObject *
crl_object_pem_read_helper(PyTypeObject *type, BIO *bio)
{
  crl_object *self;

  ENTERING(crl_object_pem_read_helper);

  if ((self = (crl_object *) crl_object_new(type, NULL, NULL)) == NULL)
    goto error;

  if (!PEM_read_bio_X509_CRL(bio, &self->crl, NULL, NULL))
    lose_openssl_error("Couldn't PEM encoded load CRL");

  return (PyObject *) self;

 error:
  Py_XDECREF(self);
  return NULL;
}

static PyObject *
crl_object_der_read_helper(PyTypeObject *type, BIO *bio)
{
  crl_object *self;

  ENTERING(crl_object_der_read_helper);

  if ((self = (crl_object *) crl_object_new(type, NULL, NULL)) == NULL)
    goto error;

  if (!d2i_X509_CRL_bio(bio, &self->crl))
    lose_openssl_error("Couldn't load DER encoded CRL");

  return (PyObject *) self;

 error:
  Py_XDECREF(self);
  return NULL;
}

static char crl_object_pem_read__doc__[] =
  "Read a PEM-encoded CRL object from a string.\n"
  ;

static PyObject *
crl_object_pem_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(crl_object_pem_read);
  return read_from_string_helper(crl_object_pem_read_helper, type, args);
}

static char crl_object_pem_read_file__doc__[] =
  "Read a PEM-encoded CRL object from a file.\n"
  ;

static PyObject *
crl_object_pem_read_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(crl_object_pem_read_file);
  return read_from_file_helper(crl_object_pem_read_helper, type, args);
}

static char crl_object_der_read__doc__[] =
  "Read a DER-encoded CRL object from a string.\n"
  ;

static PyObject *
crl_object_der_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(crl_object_der_read);
  return read_from_string_helper(crl_object_der_read_helper, type, args);
}

static char crl_object_der_read_file__doc__[] =
  "Read a DER-encoded CRL object from a file.\n"
  ;

static PyObject *
crl_object_der_read_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(crl_object_der_read_file);
  return read_from_file_helper(crl_object_der_read_helper, type, args);
}

static X509_EXTENSION *
crl_object_extension_get_helper(crl_object *self, int nid)
{
  if (self != NULL && self->crl != NULL)
    return X509_CRL_get_ext(self->crl, X509_CRL_get_ext_by_NID(self->crl, nid, -1));
  else
    return NULL;
}

static PyObject *
crl_object_extension_set_helper(crl_object *self, extension_wrapper ext)
{
  int ok = 0;

  if (ext.value == NULL)
    goto error;

  if (!X509_CRL_add1_ext_i2d(self->crl, ext.nid, ext.value, ext.critical, X509V3_ADD_REPLACE))
    lose_openssl_error("Couldn't add extension to CRL");

  ok = 1;

 error:
  ext.destructor(ext.value);
  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}



static char crl_object_get_version__doc__[] =
  "Return the version number of this CRL.\n"
  ;

static PyObject *
crl_object_get_version(crl_object *self)
{
  ENTERING(crl_object_get_version);
  return Py_BuildValue("l", X509_CRL_get_version(self->crl));
}

static char crl_object_set_version__doc__[] =
  "Set the version number of this CRL.\n"
  "\n"
  "The \"version\" parameter should be a positive integer.\n"
  ;

static PyObject *
crl_object_set_version(crl_object *self, PyObject *args)
{
  long version = 0;

  ENTERING(crl_object_set_version);

  if (!PyArg_ParseTuple(args, "i", &version))
    goto error;

  if (!X509_CRL_set_version(self->crl, version))
    lose_no_memory();

  Py_RETURN_NONE;

 error:
  return NULL;
}

static char crl_object_get_issuer__doc__[] =
  "Return issuer name of this CRL.\n"
  "\n"
  "See the \"getIssuer()\" method of the X509 class for more details.\n"
  ;

static PyObject *
crl_object_get_issuer(crl_object *self, PyObject *args)
{
  PyObject *result = NULL;
  int format = OIDNAME_FORMAT;

  ENTERING(crl_object_get_issuer);

  if (!PyArg_ParseTuple(args, "|i", &format))
    goto error;

  result = x509_object_helper_get_name(X509_CRL_get_issuer(self->crl), format);

 error:                         /* Fall through */
  return result;
}

static char crl_object_set_issuer__doc__[] =
  "Set this CRL's issuer name.\n"
  "\n"
  "See the \"setIssuer()\" method of the X509 class for details.\n"
  ;

static PyObject *
crl_object_set_issuer(crl_object *self, PyObject *args)
{
  PyObject *name_sequence = NULL;
  X509_NAME *name = NULL;

  ENTERING(crl_object_set_issuer);

  if (!PyArg_ParseTuple(args, "O", &name_sequence))
    goto error;

  if (!PySequence_Check(name_sequence))
    lose_type_error("Expected a sequence object");

  if ((name = x509_object_helper_set_name(name_sequence)) == NULL)
    goto error;

  if (!X509_CRL_set_issuer_name(self->crl, name))
    lose_openssl_error("Unable to set issuer name");

  X509_NAME_free(name);

  Py_RETURN_NONE;

 error:
  X509_NAME_free(name);
  return NULL;
}

static char crl_object_get_issuer_hash__doc__[] =
  "Return the OpenSSL \"name hash\" for this CRL's issuer name.\n"
  ;

static PyObject *
crl_object_get_issuer_hash(crl_object *self)
{
  ENTERING(crl_object_get_issuer_hash);
  return Py_BuildValue("k", X509_NAME_hash(X509_CRL_get_issuer(self->crl)));
}

/*
 * NB: OpenSSL is confused about the name of this field, probably for
 * backwards compatability with some ancient mistake.  What RFC 5280
 * calls "thisUpdate", OpenSSL calls "lastUpdate".
 */

static char crl_object_set_this_update__doc__[] =
  "Set this CRL's \"thisUpdate\" value.\n"
  "\n"
  "The \"time\" parameter should be a datetime object.\n"
  ;

static PyObject *
crl_object_set_this_update (crl_object *self, PyObject *args)
{
  PyObject *o = NULL;
  ASN1_TIME *t = NULL;

  ENTERING(crl_object_set_this_update);

  if (!PyArg_ParseTuple(args, "O", &o))
    goto error;

  if ((t = Python_to_ASN1_TIME(o, 1)) == NULL)
    lose("Couldn't convert thisUpdate string");

  if (!X509_CRL_set_lastUpdate(self->crl, t)) /* sic */
    lose("Couldn't set thisUpdate");

  ASN1_TIME_free(t);
  Py_RETURN_NONE;

 error:
  ASN1_TIME_free(t);
  return NULL;
}

static char crl_object_get_this_update__doc__[] =
  "Return this CRL's \"thisUpdate\" value as a datetime.\n"
  ;

static PyObject *
crl_object_get_this_update (crl_object *self)
{
  ENTERING(crl_object_get_this_update);
  return ASN1_TIME_to_Python(X509_CRL_get_lastUpdate(self->crl)); /* sic */
}

static char crl_object_set_next_update__doc__[] =
  "Set this CRL's \"nextUpdate\" value.\n"
  "\n"
  "The \"time\" parameter should be a datetime object.\n"
  ;

static PyObject *
crl_object_set_next_update (crl_object *self, PyObject *args)
{
  PyObject *o = NULL;
  ASN1_TIME *t = NULL;

  ENTERING(crl_object_set_next_update);

  if (!PyArg_ParseTuple(args, "O", &o))
    goto error;

  if ((t = Python_to_ASN1_TIME(o, 1)) == NULL)
    lose("Couldn't parse nextUpdate string");

  if (!X509_CRL_set_nextUpdate(self->crl, t))
    lose("Couldn't set nextUpdate");

  ASN1_TIME_free(t);
  Py_RETURN_NONE;

 error:
  ASN1_TIME_free(t);
  return NULL;
}

static char crl_object_get_next_update__doc__[] =
  "Returns this CRL's \"nextUpdate\" value as a datetime.\n"
  ;

static PyObject *
crl_object_get_next_update (crl_object *self)
{
  ENTERING(crl_object_get_next_update);
  return ASN1_TIME_to_Python(X509_CRL_get_nextUpdate(self->crl));
}

static char crl_object_add_revocations__doc__[] =
  "This method adds a collection of revocations to this CRL.\n"
  "\n"
  "The \"iterable\" parameter should be an iterable object which returns\n"
  "two-element sequences.  The first element of each pair should be the\n"
  "revoked serial number (an integer), the second element should be the\n"
  "revocation date (a datetime object).\n"
  ;

static PyObject *
crl_object_add_revocations(crl_object *self, PyObject *args)
{
  PyObject *iterable = NULL;
  PyObject *iterator = NULL;
  PyObject *item = NULL;
  PyObject *fast = NULL;
  X509_REVOKED *revoked = NULL;
  ASN1_INTEGER *serial = NULL;
  ASN1_TIME *date = NULL;
  int ok = 0;

  ENTERING(crl_object_add_revocations);

  if (!PyArg_ParseTuple(args, "O", &iterable) ||
      (iterator = PyObject_GetIter(iterable)) == NULL)
    goto error;

  while ((item = PyIter_Next(iterator)) != NULL) {

    if ((fast = PySequence_Fast(item, "Revocation entry must be a sequence")) == NULL)
      goto error;

    if (PySequence_Fast_GET_SIZE(fast) != 2)
      lose_type_error("Revocation entry must be two-element sequence");

    if ((serial = PyLong_to_ASN1_INTEGER(PySequence_Fast_GET_ITEM(fast, 0))) == NULL ||
        (date = Python_to_ASN1_TIME(PySequence_Fast_GET_ITEM(fast, 1), 1)) == NULL)
      goto error;

    if ((revoked = X509_REVOKED_new()) == NULL ||
        !X509_REVOKED_set_serialNumber(revoked, serial) ||
        !X509_REVOKED_set_revocationDate(revoked, date))
      lose_no_memory();

    ASN1_INTEGER_free(serial);
    serial = NULL;

    ASN1_TIME_free(date);
    date = NULL;

    if (!X509_CRL_add0_revoked(self->crl, revoked))
      lose_no_memory();

    revoked = NULL;
    Py_XDECREF(item);
    Py_XDECREF(fast);
    item = fast = NULL;
  }

  if (!X509_CRL_sort(self->crl))
    lose_openssl_error("Couldn't sort CRL");

  ok = 1;

 error:
  Py_XDECREF(iterator);
  Py_XDECREF(item);
  Py_XDECREF(fast);
  X509_REVOKED_free(revoked);
  ASN1_INTEGER_free(serial);
  ASN1_TIME_free(date);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char crl_object_get_revoked__doc__[] =
  "Return a sequence of two-element tuples representing the sequence of\n"
  "revoked certificates listed in this CRL.\n"
  "\n"
  "The first element of each pair is the serialNumber of the revoked\n"
  "certificate, the second element is the revocationDate.\n"
  ;

static PyObject *
crl_object_get_revoked(crl_object *self)
{
  STACK_OF(X509_REVOKED) *revoked = NULL;
  X509_REVOKED *r = NULL;
  PyObject *result = NULL;
  PyObject *item = NULL;
  PyObject *serial = NULL;
  PyObject *date = NULL;
  int i;

  ENTERING(crl_object_get_revoked);

  if ((revoked = X509_CRL_get_REVOKED(self->crl)) == NULL)
    lose("Inexplicable NULL revocation list pointer");

  if ((result = PyTuple_New(sk_X509_REVOKED_num(revoked))) == NULL)
    goto error;

  for (i = 0; i < sk_X509_REVOKED_num(revoked); i++) {
    r = sk_X509_REVOKED_value(revoked, i);

    if ((serial = ASN1_INTEGER_to_PyLong(r->serialNumber)) == NULL ||
        (date = ASN1_TIME_to_Python(r->revocationDate)) == NULL ||
        (item = Py_BuildValue("(NN)", serial, date)) == NULL)
      goto error;

    PyTuple_SET_ITEM(result, i, item);
    item = serial = date = NULL;
  }

  return result;

 error:
  Py_XDECREF(result);
  Py_XDECREF(item);
  Py_XDECREF(serial);
  Py_XDECREF(date);
  return NULL;
}

static char crl_object_is_revoked__doc__[] =
  "Check whether a particular certificate has been revoked.\n"
  ;

static PyObject *
crl_object_is_revoked(crl_object *self, PyObject *args)
{
  x509_object *x = NULL;

  if (!PyArg_ParseTuple(args, "O!", &POW_X509_Type, &x))
    return NULL;

  return PyBool_FromLong(X509_CRL_get0_by_cert(self->crl, NULL, x->x509));
}

static char crl_object_clear_extensions__doc__[] =
  "Clear all extensions attached to this CRL.\n"
  ;

static PyObject *
crl_object_clear_extensions(crl_object *self)
{
  X509_EXTENSION *ext;

  ENTERING(crl_object_clear_extensions);

  while ((ext = X509_CRL_delete_ext(self->crl, 0)) != NULL)
    X509_EXTENSION_free(ext);

  Py_RETURN_NONE;
}

static char crl_object_sign__doc__[] =
  "Sign this CRL with a private key.\n"
  "\n"
  "The \"key\" parameter should be an instance of the Asymmetric class,\n"
  "containing a private key.\n"
  "\n"
  "The optional \"digest\" parameter indicates which digest to compute and\n"
  "sign, and should be one of the following:\n"
  "\n"
  "* SHA1_DIGEST\n"
  "* SHA256_DIGEST\n"
  "* SHA384_DIGEST\n"
  "* SHA512_DIGEST\n"
  "\n"
  "The default digest algorithm is SHA-256.\n"
  ;

static PyObject *
crl_object_sign(crl_object *self, PyObject *args)
{
  asymmetric_object *asym;
  int digest_type = SHA256_DIGEST;
  const EVP_MD *digest_method = NULL;

  ENTERING(crl_object_sign);

  if (!PyArg_ParseTuple(args, "O!|i", &POW_Asymmetric_Type, &asym, &digest_type))
    goto error;

  if ((digest_method = evp_digest_factory(digest_type)) == NULL)
    lose("Unsupported digest algorithm");

  if (!X509_CRL_sign(self->crl, asym->pkey, digest_method))
    lose_openssl_error("Couldn't sign CRL");

  Py_RETURN_NONE;

 error:
  return NULL;
}

static char crl_object_verify__doc__[] =
  "Verify this CRL's signature against its issuer.\n"
  ;

static PyObject *
crl_object_verify(crl_object *self, PyObject *args)
{
  x509_object *issuer;

  ENTERING(crl_object_verify);

  if (!PyArg_ParseTuple(args, "O!", &POW_X509_Type, &issuer))
    goto error;

  if (!X509_CRL_verify(self->crl, X509_get_pubkey(issuer->x509)))
    lose_validation_error("X509_CRL_verify() raised an exception");

  Py_RETURN_NONE;

 error:
  return NULL;
}

static char crl_object_check_rpki_conformance__doc__[] =
  "Check this CRL for conformance to the RPKI profile.\n"
  ;

static PyObject *
crl_object_check_rpki_conformance(crl_object *self, PyObject *args, PyObject *kwds)
{
  static char *kwlist[] = {"issuer", "status", NULL};
  x509_object *issuer = NULL;
  PyObject *status = Py_None;

  ENTERING(crl_object_check_rpki_conformance);

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!O!", kwlist, &POW_X509_Type, &issuer, &PySet_Type, &status))
    goto error;

  if (!check_crl(self->crl, issuer->x509, status))
    goto error;

  Py_RETURN_NONE;

 error:
  return NULL;
}

static char crl_object_pem_write__doc__[] =
  "Return the PEM encoding of this CRL, as a string.\n"
  ;

static PyObject *
crl_object_pem_write(crl_object *self)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  ENTERING(crl_object_pem_write);

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  if (!PEM_write_bio_X509_CRL(bio, self->crl))
    lose_openssl_error("Unable to write CRL");

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static char crl_object_der_write__doc__[] =
  "Return the DER encoding of this CRL, as a string.\n"
  ;

static PyObject *
crl_object_der_write(crl_object *self)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  ENTERING(crl_object_der_write);

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  if (!i2d_X509_CRL_bio(bio, self->crl))
    lose_openssl_error("Unable to write CRL");

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static char crl_object_get_aki__doc__[] =
  EXTENSION_GET_AKI__DOC__
  ;

static PyObject *
crl_object_get_aki(crl_object *self)
{
  return extension_get_aki(crl_object_extension_get_helper(self, NID_authority_key_identifier));
}

static char crl_object_set_aki__doc__[] =
  EXTENSION_SET_AKI__DOC__
  ;

static PyObject *
crl_object_set_aki(crl_object *self, PyObject *args)
{
  return crl_object_extension_set_helper(self, extension_set_aki(args));
}

static char crl_object_get_crl_number__doc__[] =
  "Return the CRL Number extension value from this CRL, an integer.\n"
  ;

static PyObject *
crl_object_get_crl_number(crl_object *self)
{
  ASN1_INTEGER *ext = X509_CRL_get_ext_d2i(self->crl, NID_crl_number, NULL, NULL);
  PyObject *result = NULL;

  ENTERING(crl_object_get_crl_number);

  if (ext == NULL)
    Py_RETURN_NONE;

  result = Py_BuildValue("N", ASN1_INTEGER_to_PyLong(ext));
  ASN1_INTEGER_free(ext);
  return result;
}

static char crl_object_set_crl_number__doc__[] =
  "Set the CRL Number extension value in this CRL.\n"
  "\n"
  "The \"number\" parameter should be an integer.\n"
  ;

static PyObject *
crl_object_set_crl_number(crl_object *self, PyObject *args)
{
  ASN1_INTEGER *ext = NULL;
  PyObject *crl_number = NULL;

  ENTERING(crl_object_set_crl_number);

  if (!PyArg_ParseTuple(args, "O", &crl_number) ||
      (ext = PyLong_to_ASN1_INTEGER(crl_number)) == NULL)
    goto error;

  if (!X509_CRL_add1_ext_i2d(self->crl, NID_crl_number, ext, 0, X509V3_ADD_REPLACE))
    lose_openssl_error("Couldn't add CRL Number extension to CRL");

  ASN1_INTEGER_free(ext);
  Py_RETURN_NONE;

 error:
  ASN1_INTEGER_free(ext);
  return NULL;
}

static char crl_object_pprint__doc__[] =
  "Return a pretty-printed rendition of this CRL.\n"
  ;

static PyObject *
crl_object_pprint(crl_object *self)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  ENTERING(crl_object_pprint);

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  if (!X509_CRL_print(bio, self->crl))
    lose_openssl_error("Unable to pretty-print CRL");

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static struct PyMethodDef crl_object_methods[] = {
  Define_Method(sign,                   crl_object_sign,                        METH_VARARGS),
  Define_Method(verify,                 crl_object_verify,                      METH_VARARGS),
  Define_Method(checkRPKIConformance,   crl_object_check_rpki_conformance,      METH_KEYWORDS),
  Define_Method(getVersion,             crl_object_get_version,                 METH_NOARGS),
  Define_Method(setVersion,             crl_object_set_version,                 METH_VARARGS),
  Define_Method(getIssuer,              crl_object_get_issuer,                  METH_VARARGS),
  Define_Method(setIssuer,              crl_object_set_issuer,                  METH_VARARGS),
  Define_Method(getThisUpdate,          crl_object_get_this_update,     	METH_NOARGS),
  Define_Method(setThisUpdate,          crl_object_set_this_update,             METH_VARARGS),
  Define_Method(getNextUpdate,          crl_object_get_next_update,             METH_NOARGS),
  Define_Method(setNextUpdate,          crl_object_set_next_update,             METH_VARARGS),
  Define_Method(getRevoked,             crl_object_get_revoked,                 METH_NOARGS),
  Define_Method(isRevoked,              crl_object_is_revoked,                  METH_VARARGS),
  Define_Method(addRevocations,         crl_object_add_revocations,             METH_VARARGS),
  Define_Method(clearExtensions,        crl_object_clear_extensions,            METH_NOARGS),
  Define_Method(pemWrite,               crl_object_pem_write,                   METH_NOARGS),
  Define_Method(derWrite,               crl_object_der_write,                   METH_NOARGS),
  Define_Method(pprint,                 crl_object_pprint,                      METH_NOARGS),
  Define_Method(getAKI,                 crl_object_get_aki,                     METH_NOARGS),
  Define_Method(setAKI,                 crl_object_set_aki,                     METH_VARARGS),
  Define_Method(getCRLNumber,           crl_object_get_crl_number,              METH_NOARGS),
  Define_Method(setCRLNumber,           crl_object_set_crl_number,              METH_VARARGS),
  Define_Method(getIssuerHash,          crl_object_get_issuer_hash,             METH_NOARGS),
  Define_Class_Method(pemRead,          crl_object_pem_read,                    METH_VARARGS),
  Define_Class_Method(pemReadFile,      crl_object_pem_read_file,               METH_VARARGS),
  Define_Class_Method(derRead,          crl_object_der_read,                    METH_VARARGS),
  Define_Class_Method(derReadFile,      crl_object_der_read_file,               METH_VARARGS),
  {NULL}
};

static char POW_CRL_Type__doc__[] =
  "Container for OpenSSL's X509 CRL management facilities.\n"
  ;

static PyTypeObject POW_CRL_Type = {
  PyObject_HEAD_INIT(0)
  0,                                     /* ob_size */
  "rpki.POW.CRL",                        /* tp_name */
  sizeof(crl_object),                    /* tp_basicsize */
  0,                                     /* tp_itemsize */
  (destructor)crl_object_dealloc,        /* tp_dealloc */
  0,                                     /* tp_print */
  0,                                     /* tp_getattr */
  0,                                     /* tp_setattr */
  0,                                     /* tp_compare */
  0,                                     /* tp_repr */
  0,                                     /* tp_as_number */
  0,                                     /* tp_as_sequence */
  0,                                     /* tp_as_mapping */
  0,                                     /* tp_hash */
  0,                                     /* tp_call */
  0,                                     /* tp_str */
  0,                                     /* tp_getattro */
  0,                                     /* tp_setattro */
  0,                                     /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
  POW_CRL_Type__doc__,                   /* tp_doc */
  0,                                     /* tp_traverse */
  0,                                     /* tp_clear */
  0,                                     /* tp_richcompare */
  0,                                     /* tp_weaklistoffset */
  0,                                     /* tp_iter */
  0,                                     /* tp_iternext */
  crl_object_methods,                    /* tp_methods */
  0,                                     /* tp_members */
  0,                                     /* tp_getset */
  0,                                     /* tp_base */
  0,                                     /* tp_dict */
  0,                                     /* tp_descr_get */
  0,                                     /* tp_descr_set */
  0,                                     /* tp_dictoffset */
  0,                                     /* tp_init */
  0,                                     /* tp_alloc */
  crl_object_new,                        /* tp_new */
};



/*
 * Asymmetric object.
 */

static PyObject *
asymmetric_object_new(PyTypeObject *type, GCC_UNUSED PyObject *args, GCC_UNUSED PyObject *kwds)
{
  asymmetric_object *self = NULL;

  ENTERING(asymmetric_object_new);

  if ((self = (asymmetric_object *) type->tp_alloc(type, 0)) == NULL)
    goto error;

  self->pkey = NULL;

  return (PyObject *) self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static int
asymmetric_object_init(asymmetric_object *self, PyObject *args, PyObject *kwds)
{
  static char *kwlist[] = {NULL};

  ENTERING(asymmetric_object_init);

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "", kwlist))
    goto error;

  /*
   * We used to take arguments to generate an RSA key, but that's
   * now in the .generateRSA() class method.
   */

  return 0;

 error:
  return -1;
}

static void
asymmetric_object_dealloc(asymmetric_object *self)
{
  ENTERING(asymmetric_object_dealloc);
  EVP_PKEY_free(self->pkey);
  self->ob_type->tp_free((PyObject*) self);
}

static PyObject *
asymmetric_object_pem_read_private_helper(PyTypeObject *type, BIO *bio, char *pass)
{
  asymmetric_object *self = NULL;

  ENTERING(asymmetric_object_pem_read_private_helper);

  if ((self = (asymmetric_object *) asymmetric_object_new(type, NULL, NULL)) == NULL)
    goto error;

  if (!PEM_read_bio_PrivateKey(bio, &self->pkey, NULL, pass))
    lose_openssl_error("Couldn't load private key");

  whack_ec_key_to_namedCurve(self->pkey);

  return (PyObject *) self;

 error:
  Py_XDECREF(self);
  return NULL;
}

/*
 * We can't use the generic read_from_*_helper() functions here
 * because of optional the PEM password, so we just code the two PEM
 * read cases for private keys directly.  Other than the passphrase,
 * code is pretty much the same as the generic functions.
 *
 * It turns out that OpenSSL is moving away from its old raw PKCS #1.5
 * private key format in favor of PKCS #8.  This makes sense, but it
 * leaves us with a minor mess to track.  Many OpenSSL functions that
 * originally expected PKCS #1.5 now also accept PKCS #8, so there's
 * no tearing hurry about this, but at some point we might want to
 * switch to writing PKCS #8.  It looks like this would be relatively
 * straightforward: see functions i2d_PKCS8PrivateKey_bio() and
 * PEM_write_bio_PKCS8PrivateKey(), and note that PKCS #8 supports
 * encrypted private keys in DER format, so the DER methods should
 * take a passphrase argument as the PEM methods do.
 */

static char asymmetric_object_pem_read_private__doc__[] =
  "Read a PEM-encoded private key from a string.\n"
  "\n"
  "Optional second argument is a passphrase for the key.\n"
  ;

static PyObject *
asymmetric_object_pem_read_private(PyTypeObject *type, PyObject *args)
{
  PyObject *result = NULL;
  char *pass = NULL;
  char *src = NULL;
  BIO *bio = NULL;
  Py_ssize_t len = 0;

  ENTERING(asymmetric_object_pem_read_private);

  if (!PyArg_ParseTuple(args, "s#|s", &src, &len, &pass))
    goto error;

  if ((bio = BIO_new_mem_buf(src, len)) == NULL)
    lose_no_memory();

  result = asymmetric_object_pem_read_private_helper(type, bio, pass);

 error:
  BIO_free(bio);
  return result;
}

static char asymmetric_object_pem_read_private_file__doc__[] =
  "Read a PEM-encoded private key from a file.\n"
  "\n"
  "Optional second argument is a passphrase for the key.\n"
  ;

static PyObject *
asymmetric_object_pem_read_private_file(PyTypeObject *type, PyObject *args)
{
  const char *filename = NULL;
  PyObject *result = NULL;
  char *pass = NULL;
  BIO *bio = NULL;

  ENTERING(asymmetric_object_pem_read_private_file);

  if (!PyArg_ParseTuple(args, "s|s", &filename, &pass))
    goto error;

  if ((bio = BIO_new_file(filename, "rb")) == NULL)
    lose_openssl_error("Could not open file");

  result = asymmetric_object_pem_read_private_helper(type, bio, pass);

 error:
  BIO_free(bio);
  return result;
}

/*
 * Used to be only PEM format private keys had passphrases, but with PKCS #8
 * that's not really true anymore.  We may need to extend the API here to allow
 * passphrases for DER private keys as well.
 */

static PyObject *
asymmetric_object_der_read_private_helper(PyTypeObject *type, BIO *bio)
{
  asymmetric_object *self = NULL;

  ENTERING(asymmetric_object_der_read_private_helper);

  if ((self = (asymmetric_object *) asymmetric_object_new(type, NULL, NULL)) == NULL)
    goto error;

  if (!d2i_PrivateKey_bio(bio, &self->pkey))
    lose_openssl_error("Couldn't load private key");

  whack_ec_key_to_namedCurve(self->pkey);

  return (PyObject *) self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static char asymmetric_object_der_read_private__doc__[] =
  "Read a DER-encoded private key from a string.\n"
  ;

static PyObject *
asymmetric_object_der_read_private(PyTypeObject *type, PyObject *args)
{
  ENTERING(asymmetric_object_der_read_private);
  return read_from_string_helper(asymmetric_object_der_read_private_helper, type, args);
}

static char asymmetric_object_der_read_private_file__doc__[] =
  "Read a DER-encoded private key from a file.\n"
  ;

static PyObject *
asymmetric_object_der_read_private_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(asymmetric_object_der_read_private_file);
  return read_from_file_helper(asymmetric_object_der_read_private_helper, type, args);
}

static PyObject *
asymmetric_object_pem_read_public_helper(PyTypeObject *type, BIO *bio)
{
  asymmetric_object *self = NULL;

  ENTERING(asymmetric_object_pem_read_public_helper);

  if ((self = (asymmetric_object *) asymmetric_object_new(type, NULL, NULL)) == NULL)
    goto error;

  if (!PEM_read_bio_PUBKEY(bio, &self->pkey, NULL, NULL))
    lose_openssl_error("Couldn't load public key");

  whack_ec_key_to_namedCurve(self->pkey);

  return (PyObject *) self;

 error:
  Py_XDECREF(self);
  return NULL;
}

static PyObject *
asymmetric_object_der_read_public_helper(PyTypeObject *type, BIO *bio)
{
  asymmetric_object *self = NULL;

  ENTERING(asymmetric_object_der_read_public_helper);

  if ((self = (asymmetric_object *) asymmetric_object_new(type, NULL, NULL)) == NULL)
    goto error;

  if (!d2i_PUBKEY_bio(bio, &self->pkey))
    lose_openssl_error("Couldn't load public key");

  whack_ec_key_to_namedCurve(self->pkey);

  return (PyObject *) self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static char asymmetric_object_pem_read_public__doc__[] =
  "Read a PEM-encoded public key from a string.\n"
  ;

static PyObject *
asymmetric_object_pem_read_public(PyTypeObject *type, PyObject *args)
{
  ENTERING(asymmetric_object_pem_read_public);
  return read_from_string_helper(asymmetric_object_pem_read_public_helper, type, args);
}

static char asymmetric_object_pem_read_public_file__doc__[] =
  "Read a PEM-encoded public key from a file.\n"
  ;

static PyObject *
asymmetric_object_pem_read_public_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(asymmetric_object_pem_read_public_file);
  return read_from_file_helper(asymmetric_object_pem_read_public_helper, type, args);
}

static char asymmetric_object_der_read_public__doc__[] =
  "Read a DER-encoded public key from a string.\n"
  ;

static PyObject *
asymmetric_object_der_read_public(PyTypeObject *type, PyObject *args)
{
  ENTERING(asymmetric_object_der_read_public);
  return read_from_string_helper(asymmetric_object_der_read_public_helper, type, args);
}

static char asymmetric_object_der_read_public_file__doc__[] =
  "Read a DER-encoded public key from a file.\n"
  ;

static PyObject *
asymmetric_object_der_read_public_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(asymmetric_object_der_read_public_file);
  return read_from_file_helper(asymmetric_object_der_read_public_helper, type, args);
}

static char asymmetric_object_pem_write_private__doc__[] =
  "Return the PEM encoding of an \"Asymmetric\" private key.\n"
  "\n"
  "This method takes an optional parameter \"passphrase\" which, if\n"
  "specified, will be used to encrypt the private key with AES-256-CBC.\n"
  "\n"
  "If you don't specify a passphrase, the key will not be encrypted.\n"
  ;

static PyObject *
asymmetric_object_pem_write_private(asymmetric_object *self, PyObject *args)
{
  PyObject *result = NULL;
  char *passphrase = NULL;
  const EVP_CIPHER *evp_method = NULL;
  BIO *bio = NULL;

  ENTERING(asymmetric_object_pem_write_private);

  if (!PyArg_ParseTuple(args, "|s", &passphrase))
    goto error;

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  if (passphrase)
    evp_method = EVP_aes_256_cbc();

  if (!PEM_write_bio_PrivateKey(bio, self->pkey, evp_method, NULL, 0, NULL, passphrase))
    lose_openssl_error("Unable to write key");

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static char asymmetric_object_pem_write_public__doc__[] =
  "Return the PEM encoding of an \"Asymmetric\" public key.\n"
  ;

static PyObject *
asymmetric_object_pem_write_public(asymmetric_object *self)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  ENTERING(asymmetric_object_pem_write_public);

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  if (!PEM_write_bio_PUBKEY(bio, self->pkey))
    lose_openssl_error("Unable to write key");

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static char asymmetric_object_der_write_private__doc__[] =
  "Return the DER encoding of an \"Asymmetric\" private key.\n"
  ;

static PyObject *
asymmetric_object_der_write_private(asymmetric_object *self)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  ENTERING(asymmetric_object_der_write_private);

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  if (!i2d_PrivateKey_bio(bio, self->pkey))
    lose_openssl_error("Unable to write private key");

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static char asymmetric_object_der_write_public__doc__[] =
  "Return the DER encoding of an \"Asymmetric\" public key.\n"
  ;

static PyObject *
asymmetric_object_der_write_public(asymmetric_object *self)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  ENTERING(asymmetric_object_der_write_public);

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  if (!i2d_PUBKEY_bio(bio, self->pkey))
    lose_openssl_error("Unable to write public key");

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static char asymmetric_object_generate_rsa__doc__[] =
  "Generate a new RSA keypair.\n"
  "\n"
  "Optional argument key_size is the desired key size, in bits;\n"
  "if not specified, the default is 2048."
  ;

static PyObject *
asymmetric_object_generate_rsa(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  static char *kwlist[] = {"key_size", NULL};
  asymmetric_object *self = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  int key_size = 2048;
  int ok = 0;

  ENTERING(asymmetric_object_generate_rsa);

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i", kwlist, &key_size))
    goto error;

  if ((self = (asymmetric_object *) asymmetric_object_new(type, NULL, NULL)) == NULL)
    goto error;

  /*
   * Explictly setting RSA_F4 would be tedious, as it requires messing
   * about with bignums, and F4 is the default, so we leave it alone.
   * In case this ever changes, the required sequence would be:
   * BN_new(), BN_set_word(), EVP_PKEY_CTX_set_rsa_keygen_pubexp(),
   * BN_free().
   */

  if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)) == NULL ||
      EVP_PKEY_keygen_init(ctx) <= 0 ||
      EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_size) <= 0 ||
      EVP_PKEY_keygen(ctx, &self->pkey) <= 0)
    lose_openssl_error("Couldn't generate new RSA key");

  ok = 1;

 error:
  EVP_PKEY_CTX_free(ctx);

  if (ok)
    return (PyObject *) self;

  Py_XDECREF(self);
  return NULL;
}

static char asymmetric_object_generate_from_params__doc__[] =
  "Generate a new keypair using an AsymmetricParams object.\n"
  ;

static PyObject *
asymmetric_object_generate_from_params(PyTypeObject *type, PyObject *args)
{
  asymmetric_params_object *params = NULL;
  asymmetric_object *self = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  int ok = 0;

  ENTERING(asymmetric_object_generate_from_params);

  if (!PyArg_ParseTuple(args, "O!", &POW_AsymmetricParams_Type, &params))
    goto error;

  if ((self = (asymmetric_object *) asymmetric_object_new(type, NULL, NULL)) == NULL)
    goto error;

  if ((ctx = EVP_PKEY_CTX_new(params->pkey, NULL)) == NULL ||
      EVP_PKEY_keygen_init(ctx) <= 0 ||
      EVP_PKEY_keygen(ctx, &self->pkey) <= 0)
    lose_openssl_error("Couldn't generate new key");

  whack_ec_key_to_namedCurve(self->pkey);

  ok = 1;

 error:
  EVP_PKEY_CTX_free(ctx);

  if (ok)
    return (PyObject *) self;

  Py_XDECREF(self);
  return NULL;
}

static char asymmetric_object_calculate_ski__doc__[] =
  "Calculate SKI value for this key.\n"
  "\n"
  "The SKI is the SHA-1 hash of key's SubjectPublicKey value.\n"
  ;

static PyObject *
asymmetric_object_calculate_ski(asymmetric_object *self)
{
  PyObject *result = NULL;
  X509_PUBKEY *pubkey = NULL;
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned digest_length;
  const unsigned char *key_data = NULL;
  int key_length;

  ENTERING(asymmetric_object_calculate_ski);

  if (!X509_PUBKEY_set(&pubkey, self->pkey) ||
      !X509_PUBKEY_get0_param(NULL, &key_data, &key_length, NULL, pubkey))
    lose_openssl_error("Couldn't extract public key");

  if (!EVP_Digest(key_data, key_length, digest, &digest_length, EVP_sha1(), NULL))
    lose_openssl_error("Couldn't calculate SHA-1 digest of public key");

  result = PyString_FromStringAndSize((char *) digest, digest_length);

 error:
  X509_PUBKEY_free(pubkey);
  return result;
}

static struct PyMethodDef asymmetric_object_methods[] = {
  Define_Method(pemWritePrivate,          asymmetric_object_pem_write_private,          METH_VARARGS),
  Define_Method(pemWritePublic,           asymmetric_object_pem_write_public,           METH_NOARGS),
  Define_Method(derWritePrivate,          asymmetric_object_der_write_private,          METH_NOARGS),
  Define_Method(derWritePublic,           asymmetric_object_der_write_public,           METH_NOARGS),
  Define_Method(calculateSKI,             asymmetric_object_calculate_ski,              METH_NOARGS),
  Define_Class_Method(pemReadPublic,      asymmetric_object_pem_read_public,            METH_VARARGS),
  Define_Class_Method(pemReadPublicFile,  asymmetric_object_pem_read_public_file,       METH_VARARGS),
  Define_Class_Method(derReadPublic,      asymmetric_object_der_read_public,            METH_VARARGS),
  Define_Class_Method(derReadPublicFile,  asymmetric_object_der_read_public_file,       METH_VARARGS),
  Define_Class_Method(pemReadPrivate,     asymmetric_object_pem_read_private,           METH_VARARGS),
  Define_Class_Method(pemReadPrivateFile, asymmetric_object_pem_read_private_file,      METH_VARARGS),
  Define_Class_Method(derReadPrivate,     asymmetric_object_der_read_private,           METH_VARARGS),
  Define_Class_Method(derReadPrivateFile, asymmetric_object_der_read_private_file,      METH_VARARGS),
  Define_Class_Method(generateRSA,        asymmetric_object_generate_rsa,               METH_KEYWORDS),
  Define_Class_Method(generateFromParams, asymmetric_object_generate_from_params,       METH_VARARGS),
  {NULL}
};

static char POW_Asymmetric_Type__doc__[] =
  "Container for OpenSSL's EVP_PKEY asymmetric key classes.\n"
  ;

static PyTypeObject POW_Asymmetric_Type = {
  PyObject_HEAD_INIT(0)
  0,                                     /* ob_size */
  "rpki.POW.Asymmetric",                 /* tp_name */
  sizeof(asymmetric_object),             /* tp_basicsize */
  0,                                     /* tp_itemsize */
  (destructor)asymmetric_object_dealloc, /* tp_dealloc */
  0,                                     /* tp_print */
  0,                                     /* tp_getattr */
  0,                                     /* tp_setattr */
  0,                                     /* tp_compare */
  0,                                     /* tp_repr */
  0,                                     /* tp_as_number */
  0,                                     /* tp_as_sequence */
  0,                                     /* tp_as_mapping */
  0,                                     /* tp_hash */
  0,                                     /* tp_call */
  0,                                     /* tp_str */
  0,                                     /* tp_getattro */
  0,                                     /* tp_setattro */
  0,                                     /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
  POW_Asymmetric_Type__doc__,            /* tp_doc */
  0,                                     /* tp_traverse */
  0,                                     /* tp_clear */
  0,                                     /* tp_richcompare */
  0,                                     /* tp_weaklistoffset */
  0,                                     /* tp_iter */
  0,                                     /* tp_iternext */
  asymmetric_object_methods,             /* tp_methods */
  0,                                     /* tp_members */
  0,                                     /* tp_getset */
  0,                                     /* tp_base */
  0,                                     /* tp_dict */
  0,                                     /* tp_descr_get */
  0,                                     /* tp_descr_set */
  0,                                     /* tp_dictoffset */
  (initproc) asymmetric_object_init,     /* tp_init */
  0,                                     /* tp_alloc */
  asymmetric_object_new,                 /* tp_new */
};



/*
 * AsymmetricParams object.
 */

static PyObject *
asymmetric_params_object_new(PyTypeObject *type, GCC_UNUSED PyObject *args, GCC_UNUSED PyObject *kwds)
{
  asymmetric_params_object *self = NULL;

  ENTERING(asymmetric_params_object_new);

  if ((self = (asymmetric_params_object *) type->tp_alloc(type, 0)) == NULL)
    goto error;

  self->pkey = NULL;

  return (PyObject *) self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static int
asymmetric_params_object_init(asymmetric_params_object *self, PyObject *args, PyObject *kwds)
{
  static char *kwlist[] = {NULL};

  ENTERING(asymmetric_params_object_init);

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "", kwlist))
    goto error;

  return 0;

 error:
  return -1;
}

static void
asymmetric_params_object_dealloc(asymmetric_params_object *self)
{
  ENTERING(asymmetric_params_object_dealloc);
  EVP_PKEY_free(self->pkey);
  self->ob_type->tp_free((PyObject*) self);
}

static PyObject *
asymmetric_params_object_pem_read_helper(PyTypeObject *type, BIO *bio)
{
  asymmetric_params_object *self = NULL;

  ENTERING(asymmetric_params_object_pem_read_helper);

  if ((self = (asymmetric_params_object *) asymmetric_params_object_new(type, NULL, NULL)) == NULL)
    goto error;

  if (!PEM_read_bio_Parameters(bio, &self->pkey))
    lose_openssl_error("Couldn't load PEM encoded key parameters");

  return (PyObject *) self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static char asymmetric_params_object_pem_read__doc__[] =
  "Read PEM-encoded key parameters from a string.\n"
  ;

static PyObject *
asymmetric_params_object_pem_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(asymmetric_params_object_pem_read);
  return read_from_string_helper(asymmetric_params_object_pem_read_helper, type, args);
}

static char asymmetric_params_object_pem_read_file__doc__[] =
  "Read PEM-encoded key parameters from a file.\n"
  ;

static PyObject *
asymmetric_params_object_pem_read_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(asymmetric_params_object_pem_read_file);
  return read_from_file_helper(asymmetric_params_object_pem_read_helper, type, args);
}

static char asymmetric_params_object_pem_write__doc__[] =
  "Return the PEM encoding of this set of key parameters, as a string.\n"
  ;

static PyObject *
asymmetric_params_object_pem_write(asymmetric_params_object *self)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  ENTERING(asymmetric_params_object_pem_write);

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  if (PEM_write_bio_Parameters(bio, self->pkey) <= 0)
    lose_openssl_error("Unable to write key parameters");

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static char asymmetric_params_object_generate_ec__doc__[] =
  "Generate a new set of EC parameters.\n"
  "\n"
  "Optional argument curve is a numeric code representing the curve to use;\n"
  "if not specified, the default is P-256."
  ;

static PyObject *
asymmetric_params_object_generate_ec(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  static char *kwlist[] = {"curve", NULL};
  asymmetric_params_object *self = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  int curve = NID_X9_62_prime256v1;
  int ok = 0;

  ENTERING(asymmetric_params_object_generate_ec);

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i", kwlist, &curve))
    goto error;

  if ((self = (asymmetric_params_object *) asymmetric_params_object_new(type, NULL, NULL)) == NULL)
    goto error;

  if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) == NULL ||
      EVP_PKEY_paramgen_init(ctx) <= 0 ||
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, curve) <= 0 ||
      EVP_PKEY_paramgen(ctx, &self->pkey) <= 0)
    lose_openssl_error("Couldn't generate key parameters");

  ok = 1;

 error:
  EVP_PKEY_CTX_free(ctx);

  if (ok)
    return (PyObject *) self;

  Py_XDECREF(self);
  return NULL;
}

static char asymmetric_params_object_generate_dh__doc__[] =
  "Generate a new set of DH parameters.\n"
  "\n"
  "Optional argument prime_length is length of the DH prime parameter\n"
  "to use, in bits; if not specified, the default is 2048 bits.\n"
  "\n"
  "Be warned that generating DH parameters with a 2048-bit prime may\n"
  "take a ridiculously long time.\n"
  ;

static PyObject *
asymmetric_params_object_generate_dh(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  static char *kwlist[] = {"prime_length", NULL};
  asymmetric_params_object *self = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  int prime_length = 2048;
  int ok = 0;

  ENTERING(asymmetric_params_object_generate_dh);

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i", kwlist, &prime_length))
    goto error;

  if ((self = (asymmetric_params_object *) asymmetric_params_object_new(type, NULL, NULL)) == NULL)
    goto error;

  if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL)) == NULL ||
      EVP_PKEY_paramgen_init(ctx) <= 0 ||
      EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, prime_length) <= 0 ||
      EVP_PKEY_paramgen(ctx, &self->pkey) <= 0)
    lose_openssl_error("Couldn't generate key parameters");

  ok = 1;

 error:
  EVP_PKEY_CTX_free(ctx);

  if (ok)
    return (PyObject *) self;

  Py_XDECREF(self);
  return NULL;
}

static char asymmetric_params_object_generate_dsa__doc__[] =
  "Generate a new set of DSA parameters.\n"
  "\n"
  "Optional argument key_length is the length of the key to generate, in bits;\n"
  "if not specified, the default is 2048 bits."
  ;

static PyObject *
asymmetric_params_object_generate_dsa(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  static char *kwlist[] = {"key_length", NULL};
  asymmetric_params_object *self = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  int key_length = 2048;
  int ok = 0;

  ENTERING(asymmetric_params_object_generate_dsa);

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "|i", kwlist, &key_length))
    goto error;

  if ((self = (asymmetric_params_object *) asymmetric_params_object_new(type, NULL, NULL)) == NULL)
    goto error;

  if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL)) == NULL ||
      EVP_PKEY_paramgen_init(ctx) <= 0 ||
      EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, key_length) <= 0 ||
      EVP_PKEY_paramgen(ctx, &self->pkey) <= 0)
    lose_openssl_error("Couldn't generate key parameters");

  ok = 1;

 error:
  EVP_PKEY_CTX_free(ctx);

  if (ok)
    return (PyObject *) self;

  Py_XDECREF(self);
  return NULL;
}

static struct PyMethodDef asymmetric_params_object_methods[] = {
  Define_Method(pemWrite,               asymmetric_params_object_pem_write,             METH_NOARGS),
  Define_Class_Method(pemRead,          asymmetric_params_object_pem_read,              METH_VARARGS),
  Define_Class_Method(pemReadFile,      asymmetric_params_object_pem_read_file,         METH_VARARGS),
  Define_Class_Method(generateEC,       asymmetric_params_object_generate_ec,		METH_KEYWORDS),
  Define_Class_Method(generateDH,	asymmetric_params_object_generate_dh,           METH_KEYWORDS),
  Define_Class_Method(generateDSA,	asymmetric_params_object_generate_dsa,          METH_KEYWORDS),
  {NULL}
};

static char POW_AsymmetricParams_Type__doc__[] =
  "Container for OpenSSL's EVP_PKEY asymmetric key parameter classes.\n"
  ;

static PyTypeObject POW_AsymmetricParams_Type = {
  PyObject_HEAD_INIT(0)
  0,                                     /* ob_size */
  "rpki.POW.AsymmetricParams",           /* tp_name */
  sizeof(asymmetric_params_object),      /* tp_basicsize */
  0,                                     /* tp_itemsize */
  (destructor)asymmetric_params_object_dealloc, /* tp_dealloc */
  0,                                     /* tp_print */
  0,                                     /* tp_getattr */
  0,                                     /* tp_setattr */
  0,                                     /* tp_compare */
  0,                                     /* tp_repr */
  0,                                     /* tp_as_number */
  0,                                     /* tp_as_sequence */
  0,                                     /* tp_as_mapping */
  0,                                     /* tp_hash */
  0,                                     /* tp_call */
  0,                                     /* tp_str */
  0,                                     /* tp_getattro */
  0,                                     /* tp_setattro */
  0,                                     /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
  POW_AsymmetricParams_Type__doc__,      /* tp_doc */
  0,                                     /* tp_traverse */
  0,                                     /* tp_clear */
  0,                                     /* tp_richcompare */
  0,                                     /* tp_weaklistoffset */
  0,                                     /* tp_iter */
  0,                                     /* tp_iternext */
  asymmetric_params_object_methods,      /* tp_methods */
  0,                                     /* tp_members */
  0,                                     /* tp_getset */
  0,                                     /* tp_base */
  0,                                     /* tp_dict */
  0,                                     /* tp_descr_get */
  0,                                     /* tp_descr_set */
  0,                                     /* tp_dictoffset */
  (initproc) asymmetric_params_object_init, /* tp_init */
  0,                                     /* tp_alloc */
  asymmetric_params_object_new,          /* tp_new */
};



/*
 * Digest object.
 */

static PyObject *
digest_object_new(PyTypeObject *type, GCC_UNUSED PyObject *args, GCC_UNUSED PyObject *kwds)
{
  digest_object *self = NULL;

  ENTERING(digest_object_new);

  if ((self = (digest_object *) type->tp_alloc(type, 0)) == NULL)
    goto error;

  self->digest_type = 0;

  return (PyObject *) self;

 error:
  return NULL;
}

static int
digest_object_init(digest_object *self, PyObject *args, PyObject *kwds)
{
  static char *kwlist[] = {"digest_type", NULL};
  const EVP_MD *digest_method = NULL;
  int digest_type = 0;

  ENTERING(digest_object_init);

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "i", kwlist, &digest_type))
    goto error;

  if ((digest_method = evp_digest_factory(digest_type)) == NULL)
    lose("Unsupported digest algorithm");

  self->digest_type = digest_type;
  if (!EVP_DigestInit(&self->digest_ctx, digest_method))
    lose_openssl_error("Couldn't initialize digest");

  return 0;

 error:
  return -1;
}

static void
digest_object_dealloc(digest_object *self)
{
  ENTERING(digest_object_dealloc);
  EVP_MD_CTX_cleanup(&self->digest_ctx);
  self->ob_type->tp_free((PyObject*) self);
}

static char digest_object_update__doc__[] =
  "Add data to this digest.\n"
  "\n"
  "the \"data\" parameter should be a string containing the data to be added.\n"
  ;

static PyObject *
digest_object_update(digest_object *self, PyObject *args)
{
  char *data = NULL;
  Py_ssize_t len = 0;

  ENTERING(digest_object_update);

  if (!PyArg_ParseTuple(args, "s#", &data, &len))
    goto error;

  if (!EVP_DigestUpdate(&self->digest_ctx, data, len))
    lose_openssl_error("EVP_DigestUpdate() failed");

  Py_RETURN_NONE;

 error:
  return NULL;
}

static char digest_object_copy__doc__[] =
  "Return a copy of this Digest object.\n"
  ;

static PyObject *
digest_object_copy(digest_object *self)
{
  digest_object *new = NULL;

  ENTERING(digest_object_copy);

  if ((new = (digest_object *) digest_object_new(&POW_Digest_Type, NULL, NULL)) == NULL)
    goto error;

  new->digest_type = self->digest_type;
  if (!EVP_MD_CTX_copy(&new->digest_ctx, &self->digest_ctx))
    lose_openssl_error("Couldn't copy digest");

  return (PyObject*) new;

 error:

  Py_XDECREF(new);
  return NULL;
}

static char digest_object_digest__doc__[] =
  "Return the digest of all the data which this Digest object has processed.\n"
  "\n"
  "This method can be called at any time and will not effect the internal\n"
  "state of the Digest object.\n"
  ;

/*
 * Do we really need to do this copy?  Nice general operation, but does
 * anything we're doing for RPKI care?
 */

static PyObject *
digest_object_digest(digest_object *self)
{
  unsigned char digest_text[EVP_MAX_MD_SIZE];
  unsigned digest_len = 0;
  PyObject *result = NULL;
  EVP_MD_CTX ctx;

  ENTERING(digest_object_digest);

  if (!EVP_MD_CTX_copy(&ctx, &self->digest_ctx))
    lose_openssl_error("Couldn't copy digest");

  EVP_DigestFinal(&ctx, digest_text, &digest_len);

  result = Py_BuildValue("s#", digest_text, (Py_ssize_t) digest_len);

 error:
  EVP_MD_CTX_cleanup(&ctx);
  return result;
}

static struct PyMethodDef digest_object_methods[] = {
  Define_Method(update,         digest_object_update,   METH_VARARGS),
  Define_Method(digest,         digest_object_digest,   METH_NOARGS),
  Define_Method(copy,           digest_object_copy,     METH_NOARGS),
  {NULL}
};

static char POW_Digest_Type__doc__[] =
  "This class provides access to the digest functionality of OpenSSL.\n"
  "It emulates the digest modules in the Python Standard Library, but\n"
  "does not currently support the \"hexdigest\" method.\n"
  "\n"
  "The constructor takes one parameter, the kind of Digest object to create.\n"
  "This should be one of the following:\n"
  "\n"
  "  * SHA1_DIGEST\n"
  "  * SHA256_DIGEST\n"
  "  * SHA384_DIGEST\n"
  "  * SHA512_DIGEST\n"
  ;

static PyTypeObject POW_Digest_Type = {
  PyObject_HEAD_INIT(0)
  0,                                  /* ob_size */
  "rpki.POW.Digest",                  /* tp_name */
  sizeof(digest_object),              /* tp_basicsize */
  0,                                  /* tp_itemsize */
  (destructor)digest_object_dealloc,  /* tp_dealloc */
  0,                                  /* tp_print */
  0,                                  /* tp_getattr */
  0,                                  /* tp_setattr */
  0,                                  /* tp_compare */
  0,                                  /* tp_repr */
  0,                                  /* tp_as_number */
  0,                                  /* tp_as_sequence */
  0,                                  /* tp_as_mapping */
  0,                                  /* tp_hash */
  0,                                  /* tp_call */
  0,                                  /* tp_str */
  0,                                  /* tp_getattro */
  0,                                  /* tp_setattro */
  0,                                  /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
  POW_Digest_Type__doc__,             /* tp_doc */
  0,                                  /* tp_traverse */
  0,                                  /* tp_clear */
  0,                                  /* tp_richcompare */
  0,                                  /* tp_weaklistoffset */
  0,                                  /* tp_iter */
  0,                                  /* tp_iternext */
  digest_object_methods,              /* tp_methods */
  0,                                  /* tp_members */
  0,                                  /* tp_getset */
  0,                                  /* tp_base */
  0,                                  /* tp_dict */
  0,                                  /* tp_descr_get */
  0,                                  /* tp_descr_set */
  0,                                  /* tp_dictoffset */
  (initproc) digest_object_init,      /* tp_init */
  0,                                  /* tp_alloc */
  digest_object_new,                  /* tp_new */
};



/*
 * CMS object.
 */

static PyObject *
cms_object_new(PyTypeObject *type, GCC_UNUSED PyObject *args, GCC_UNUSED PyObject *kwds)
{
  cms_object *self;

  ENTERING(cms_object_new);

  if ((self = (cms_object *) type->tp_alloc(type, 0)) != NULL)
    return (PyObject *) self;

  Py_XDECREF(self);
  return NULL;
}

static void
cms_object_dealloc(cms_object *self)
{
  ENTERING(cms_object_dealloc);
  CMS_ContentInfo_free(self->cms);
  self->ob_type->tp_free((PyObject*) self);
}

static PyObject *
cms_object_pem_read_helper(PyTypeObject *type, BIO *bio)
{
  cms_object *self;

  ENTERING(cms_object_pem_read_helper);

  if ((self = (cms_object *) type->tp_new(type, NULL, NULL)) == NULL)
    goto error;

  if (!PEM_read_bio_CMS(bio, &self->cms, NULL, NULL))
    lose_openssl_error("Couldn't load PEM encoded CMS message");

  return (PyObject *) self;

 error:
  Py_XDECREF(self);
  return NULL;
}

static PyObject *
cms_object_der_read_helper(PyTypeObject *type, BIO *bio)
{
  cms_object *self;

  ENTERING(cms_object_der_read_helper);

  if ((self = (cms_object *) type->tp_new(type, NULL, NULL)) == NULL)
    goto error;

  if (!d2i_CMS_bio(bio, &self->cms))
    lose_openssl_error("Couldn't load DER encoded CMS message");

  return (PyObject *) self;

 error:
  Py_XDECREF(self);
  return NULL;
}

static char cms_object_pem_read__doc__[] =
  "Read a PEM-encoded CMS object from a string.\n"
  ;

static PyObject *
cms_object_pem_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(cms_object_pem_read);
  return read_from_string_helper(cms_object_pem_read_helper, type, args);
}

static char cms_object_pem_read_file__doc__[] =
  "Read a PEM-encoded CMS object from a file.\n"
  ;

static PyObject *
cms_object_pem_read_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(cms_object_pem_read_file);
  return read_from_file_helper(cms_object_pem_read_helper, type, args);
}

static char cms_object_der_read__doc__[] =
  "Read a DER-encoded CMS object from a string.\n"
  ;

static PyObject *
cms_object_der_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(cms_object_der_read);
  return read_from_string_helper(cms_object_der_read_helper, type, args);
}

static char cms_object_der_read_file__doc__[] =
  "Read a DER-encoded CMS object from a file.\n"
  ;

static PyObject *
cms_object_der_read_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(cms_object_der_read_file);
  return read_from_file_helper(cms_object_der_read_helper, type, args);
}

static char cms_object_pem_write__doc__[] =
  "Return the DER encoding of this CMS message.\n"
  ;

static PyObject *
cms_object_pem_write(cms_object *self)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  ENTERING(cms_object_pem_write);

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  if (!PEM_write_bio_CMS(bio, self->cms))
    lose_openssl_error("Unable to write CMS object");

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static char cms_object_der_write__doc__[] =
  "Return the DER encoding of this CMS message.\n"
  ;

static PyObject *
cms_object_der_write(cms_object *self)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  ENTERING(cms_object_der_write);

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  if (!i2d_CMS_bio(bio, self->cms))
    lose_openssl_error("Unable to write CMS object");

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static int
cms_object_sign_helper(cms_object *self,
                       BIO *bio,
                       x509_object *signcert,
                       asymmetric_object *signkey,
                       PyObject *x509_iterable,
                       PyObject *crl_iterable,
                       char *oid,
                       unsigned flags)                       
{
  STACK_OF(X509) *x509_stack = NULL;
  ASN1_OBJECT *econtent_type = NULL;
  CMS_ContentInfo *cms = NULL;
  PyObject *iterator = NULL;
  PyObject *item = NULL;
  int ok = 0;

  ENTERING(cms_object_sign_helper);

  assert_no_unhandled_openssl_errors();

  flags &= CMS_NOCERTS | CMS_NOATTR;
  flags |= CMS_BINARY | CMS_NOSMIMECAP | CMS_PARTIAL | CMS_USE_KEYID;

  if ((x509_stack = x509_helper_iterable_to_stack(x509_iterable)) == NULL)
    goto error;

  assert_no_unhandled_openssl_errors();

  if (oid && (econtent_type = OBJ_txt2obj(oid, 1)) == NULL)
    lose_openssl_error("Couldn't parse OID");

  assert_no_unhandled_openssl_errors();

  if ((cms = CMS_sign(NULL, NULL, x509_stack, bio, flags)) == NULL)
    lose_openssl_error("Couldn't create CMS message");

  assert_no_unhandled_openssl_errors();

  if (econtent_type)
    CMS_set1_eContentType(cms, econtent_type);

  assert_no_unhandled_openssl_errors();

  if (!CMS_add1_signer(cms, signcert->x509, signkey->pkey, EVP_sha256(), flags))
    lose_openssl_error("Couldn't sign CMS message");

  assert_no_unhandled_openssl_errors();

  if (crl_iterable != Py_None) {

    if ((iterator = PyObject_GetIter(crl_iterable)) == NULL)
      goto error;

    while ((item = PyIter_Next(iterator)) != NULL) {

      if (!POW_CRL_Check(item))
        lose_type_error("Expected a CRL object");

      if (!CMS_add1_crl(cms, ((crl_object *) item)->crl))
        lose_openssl_error("Couldn't add CRL to CMS");

      assert_no_unhandled_openssl_errors();

      Py_XDECREF(item);
      item = NULL;
    }
  }

  if (!CMS_final(cms, bio, NULL, flags))
    lose_openssl_error("Couldn't finalize CMS signatures");

  assert_no_unhandled_openssl_errors();

  CMS_ContentInfo_free(self->cms);
  self->cms = cms;
  cms = NULL;

  ok = 1;

 error:                          /* fall through */
  CMS_ContentInfo_free(cms);
  sk_X509_free(x509_stack);
  ASN1_OBJECT_free(econtent_type);
  Py_XDECREF(iterator);
  Py_XDECREF(item);

  return ok;
}

static char cms_object_sign__doc__[] =
  "Sign this CMS message message with a private key.\n"
  "\n"
  "The \"signcert\" parameter should be the certificate against which the\n"
  "message will eventually be verified, an X509 object.\n"
  "\n"
  "The \"key\" parameter should be the private key with which to sign the\n"
  "message, an Asymmetric object.\n"
  "\n"
  "The \"data\" parameter should be the message to be signed, a string.\n"
  "\n"
  "The optional \"certs\" parameter should be an iterable supplying X509 objects\n"
  "to be included in the signed message.\n"
  "\n"
  "The optional \"crls\" parameter should be an iterable supplying CRL objects\n"
  "to be included in the signed message.\n"
  "\n"
  "The optional \"eContentType\" parameter should be an Object Identifier\n"
  "to use as the eContentType value in the signed message.\n"
  "\n"
  "The optional \"flags\" parameters should be an integer holding a bitmask,\n"
  "and can include the following flags:\n"
  "\n"
  "  * CMS_NOCERTS\n"
  "  * CMS_NOATTR\n"
  ;

static PyObject *
cms_object_sign(cms_object *self, PyObject *args)
{
  asymmetric_object *signkey = NULL;
  x509_object *signcert = NULL;
  PyObject *x509_iterable = Py_None;
  PyObject *crl_iterable = Py_None;
  char *buf = NULL, *oid = NULL;
  Py_ssize_t len;
  unsigned flags = 0;
  BIO *bio = NULL;
  int ok = 0;

  ENTERING(cms_object_sign);

  if (!PyArg_ParseTuple(args, "O!O!s#|OOsI",
                        &POW_X509_Type, &signcert,
                        &POW_Asymmetric_Type, &signkey,
                        &buf, &len,
                        &x509_iterable,
                        &crl_iterable,
                        &oid,
                        &flags))
    goto error;

  assert_no_unhandled_openssl_errors();

  if ((bio = BIO_new_mem_buf(buf, len)) == NULL)
    lose_no_memory();

  assert_no_unhandled_openssl_errors();

  if (!cms_object_sign_helper(self, bio, signcert, signkey,
                              x509_iterable, crl_iterable, oid, flags))
    lose_openssl_error("Couldn't sign CMS object");

  assert_no_unhandled_openssl_errors();

  ok = 1;

 error:
  BIO_free(bio);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static BIO *
cms_object_extract_without_verifying_helper(cms_object *self)
{
  const unsigned flags =
    CMS_NOCRL | CMS_NO_SIGNER_CERT_VERIFY | CMS_NO_ATTR_VERIFY | CMS_NO_CONTENT_VERIFY;

  BIO *bio = NULL;

  ENTERING(cms_object_extract_without_verifying_helper);

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  if (CMS_verify(self->cms, NULL, NULL, NULL, bio, flags) <= 0)
    lose_openssl_error("Couldn't parse CMS message");

  return bio;

 error:
  BIO_free(bio);
  return NULL;
}


#define CMS_OBJECT_VERIFY_HELPER__DOC__                                         \
  "\n"                                                                          \
  "The optional \"certs\" parameter is a set of certificates to search\n"       \
  "for the signer's certificate.\n"                                             \
  "\n"                                                                          \
  "The optional \"flags\" parameter is an integer of bit flags,\n"              \
  "containing zero or more of the following:\n"                                 \
  "\n"                                                                          \
  "  * CMS_NOINTERN\n"                                                          \
  "  * CMS_NOCRL\n"                                                             \
  "  * CMS_NO_SIGNER_CERT_VERIFY\n"                                             \
  "  * CMS_NO_ATTR_VERIFY\n"                                                    \
  "  * CMS_NO_CONTENT_VERIFY\n"                                                 \
  "\n"                                                                          \
  "Note that this method does NOT verify X.509 certificates, it just\n"         \
  "verifies the CMS signature.  Use certificate verification functions\n"       \
  "to verify certificates."

#warning Should we really allow the full range of flags here, or constrain to just the useful cases?

static BIO *
cms_object_verify_helper(cms_object *self, PyObject *args, PyObject *kwds)
{
  static char *kwlist[] = {"certs", "flags", NULL};
  PyObject *certs_iterable = Py_None;
  STACK_OF(X509) *certs_stack = NULL;
  unsigned flags = 0, ok = 0;
  BIO *bio = NULL;

  const unsigned flag_mask =
    CMS_NOINTERN | CMS_NOCRL | CMS_NO_SIGNER_CERT_VERIFY |
    CMS_NO_ATTR_VERIFY | CMS_NO_CONTENT_VERIFY;

  ENTERING(cms_object_verify_helper);

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "|OI", kwlist, &certs_iterable, &flags))
    goto error;

  if ((flags & ~flag_mask) != 0)
    lose_value_error("Bad CMS_verify() flags");

  flags |= CMS_NO_SIGNER_CERT_VERIFY;

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  assert_no_unhandled_openssl_errors();

  if (certs_iterable != Py_None &&
      (certs_stack = x509_helper_iterable_to_stack(certs_iterable)) == NULL)
    goto error;

  assert_no_unhandled_openssl_errors();

  if (CMS_verify(self->cms, certs_stack, NULL, NULL, bio, flags) <= 0)
    lose_openssl_error("Couldn't verify CMS message");

  assert_no_unhandled_openssl_errors();

  ok = 1;

 error:                          /* fall through */
  sk_X509_free(certs_stack);

  if (ok)
    return bio;

  BIO_free(bio);
  return NULL;
}

static char cms_object_verify__doc__[] =
  "Verify this CMS message against a trusted certificate store.\n"
  "\n"
  CMS_OBJECT_VERIFY_HELPER__DOC__
  "\n"
  "Return value is the decoded CMS content, as a Python string.\n"
  ;

static PyObject *
cms_object_verify(cms_object *self, PyObject *args, PyObject *kwds)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  ENTERING(cms_object_verify);

  if ((bio = cms_object_verify_helper(self, args, kwds)) != NULL)
    result = BIO_to_PyString_helper(bio);

  BIO_free(bio);
  return result;
}

static char cms_object_extract_without_verifying__doc__[] =
  "Extract content from a CMS object without attempting CMS verification.\n"
  "\n"
  "NEVER USE THIS METHOD ON AN UNVERIFIED CMS OBJECT!\n"
  ;

static PyObject *
cms_object_extract_without_verifying(cms_object *self)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  ENTERING(cms_object_extract_without_verifying);

  if ((bio = cms_object_extract_without_verifying_helper(self)) != NULL)
    result = BIO_to_PyString_helper(bio);

  BIO_free(bio);
  return result;
}

static char cms_object_check_rpki_conformance__doc__[] =
  "Check this CMS message for conformance to the RPKI profile.\n"
  ;

static PyObject *
cms_object_check_rpki_conformance(cms_object *self, PyObject *args, PyObject *kwds)
{
  static char *kwlist[] = {"status", NULL};
  PyObject *status = Py_None;

  ENTERING(cms_object_check_rpki_conformance);

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!", kwlist, &PySet_Type, &status))
    goto error;

  if (!check_cms(self->cms, status))
    goto error;

  Py_RETURN_NONE;

 error:
  return NULL;
}

static char cms_object_eContentType__doc__[] =
  "Return the eContentType OID of this CMS message.\n"
  ;

static PyObject *
cms_object_eContentType(cms_object *self)
{
  const ASN1_OBJECT *oid = NULL;
  PyObject *result = NULL;

  ENTERING(cms_object_eContentType);

  if ((oid = CMS_get0_eContentType(self->cms)) == NULL)
    lose_openssl_error("Couldn't extract eContentType from CMS message");

  assert_no_unhandled_openssl_errors();

  result = ASN1_OBJECT_to_PyString(oid);

 error:
  return result;
}

static char cms_object_signingTime__doc__[] =
  "Return the signingTime of this CMS message.\n"
  ;

static PyObject *
cms_object_signingTime(cms_object *self)
{
  PyObject *result = NULL;
  STACK_OF(CMS_SignerInfo) *sis = NULL;
  CMS_SignerInfo *si = NULL;
  X509_ATTRIBUTE *xa = NULL;
  ASN1_TYPE *so = NULL;
  int i;

  ENTERING(cms_object_signingTime);

  if ((sis = CMS_get0_SignerInfos(self->cms)) == NULL)
    lose_openssl_error("Couldn't extract signerInfos from CMS message[1]");

  if (sk_CMS_SignerInfo_num(sis) != 1)
    lose_openssl_error("Couldn't extract signerInfos from CMS message[2]");

  si = sk_CMS_SignerInfo_value(sis, 0);

  if ((i = CMS_signed_get_attr_by_NID(si, NID_pkcs9_signingTime, -1)) < 0)
    lose_openssl_error("Couldn't extract signerInfos from CMS message[3]");

  if ((xa = CMS_signed_get_attr(si, i)) == NULL)
    lose_openssl_error("Couldn't extract signerInfos from CMS message[4]");

  if (xa->single)
    lose("Couldn't extract signerInfos from CMS message[5]");

  if (X509_ATTRIBUTE_count(xa) != 1)
    lose("Couldn't extract signerInfos from CMS message[6]");

  if ((so = X509_ATTRIBUTE_get0_type(xa, 0)) == NULL)
    lose("Couldn't extract signerInfos from CMS message[7]");

  switch (so->type) {
  case V_ASN1_UTCTIME:
    result = ASN1_TIME_to_Python(so->value.utctime);
    break;
  case V_ASN1_GENERALIZEDTIME:
    result = ASN1_TIME_to_Python(so->value.generalizedtime);
    break;
  default:
    lose("Couldn't extract signerInfos from CMS message[8]");
  }

 error:
  return result;
}

static char cms_object_pprint__doc__[] =
  "Return a pretty-printed representation of this CMS message.\n"
  ;

static PyObject *
cms_object_pprint(cms_object *self)
{
  BIO *bio = NULL;
  PyObject *result = NULL;

  ENTERING(cms_object_pprint);

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  if (!CMS_ContentInfo_print_ctx(bio, self->cms, 0, NULL))
    lose_openssl_error("Unable to pretty-print CMS object");

  result = BIO_to_PyString_helper(bio);

 error:
  BIO_free(bio);
  return result;
}

static char cms_object_certs__doc__[] =
  "Return any certificates embedded in this CMS message, as a sequence\n"
  "of X509 objects.   This sequence will be empty if the message wrapper\n"
  "contains no certificates.\n"
  ;

/*
 * Might want to accept an optional subclass argument.
 */

static PyObject *
cms_object_certs(cms_object *self)
{
  STACK_OF(X509) *certs = NULL;
  PyObject *result = NULL;

  ENTERING(cms_object_certs);

  if ((certs = CMS_get1_certs(self->cms)) != NULL)
    result = stack_to_tuple_helper(CHECKED_PTR_OF(STACK_OF(X509), certs),
                                   stack_to_tuple_helper_get_x509);
  else if (!ERR_peek_error())
    result = Py_BuildValue("()");
  else
    lose_openssl_error("Couldn't extract certs from CMS message");

 error:                          /* fall through */
  sk_X509_pop_free(certs, X509_free);
  return result;
}

static char cms_object_crls__doc__[] =
  "Return any CRLs embedded in this CMS message, as a sequence of CRL objects.\n"
  "This sequence will be empty if the message contains no CRLs.\n"
  ;

/*
 * Might want to accept an optional subclass argument.
 */

static PyObject *
cms_object_crls(cms_object *self)
{
  STACK_OF(X509_CRL) *crls = NULL;
  PyObject *result = NULL;

  ENTERING(cms_object_crls);

  if ((crls = CMS_get1_crls(self->cms)) != NULL)
    result = stack_to_tuple_helper(CHECKED_PTR_OF(STACK_OF(X509_CRL), crls),
                                   stack_to_tuple_helper_get_crl);
  else if (!ERR_peek_error())
    result = Py_BuildValue("()");
  else
    lose_openssl_error("Couldn't extract CRLs from CMS message");

 error:                          /* fall through */
  sk_X509_CRL_pop_free(crls, X509_CRL_free);
  return result;
}

static struct PyMethodDef cms_object_methods[] = {
  Define_Method(pemWrite,                       cms_object_pem_write,                   METH_NOARGS),
  Define_Method(derWrite,                       cms_object_der_write,                   METH_NOARGS),
  Define_Method(sign,                           cms_object_sign,                        METH_VARARGS),
  Define_Method(verify,                         cms_object_verify,                      METH_KEYWORDS),
  Define_Method(extractWithoutVerifying,        cms_object_extract_without_verifying,   METH_NOARGS),
  Define_Method(checkRPKIConformance,           cms_object_check_rpki_conformance,      METH_KEYWORDS),
  Define_Method(eContentType,                   cms_object_eContentType,                METH_NOARGS),
  Define_Method(signingTime,                    cms_object_signingTime,                 METH_NOARGS),
  Define_Method(pprint,                         cms_object_pprint,                      METH_NOARGS),
  Define_Method(certs,                          cms_object_certs,                       METH_NOARGS),
  Define_Method(crls,                           cms_object_crls,                        METH_NOARGS),
  Define_Class_Method(pemRead,                  cms_object_pem_read,                    METH_VARARGS),
  Define_Class_Method(pemReadFile,              cms_object_pem_read_file,               METH_VARARGS),
  Define_Class_Method(derRead,                  cms_object_der_read,                    METH_VARARGS),
  Define_Class_Method(derReadFile,              cms_object_der_read_file,               METH_VARARGS),
  {NULL}
};

static char POW_CMS_Type__doc__[] =
  "Wrapper for OpenSSL's CMS class.  At present this only handes signed\n"
  "objects, as those are the only kind of CMS objects used in RPKI.\n"
  ;

static PyTypeObject POW_CMS_Type = {
  PyObject_HEAD_INIT(0)
  0,                                  /* ob_size */
  "rpki.POW.CMS",                     /* tp_name */
  sizeof(cms_object),                 /* tp_basicsize */
  0,                                  /* tp_itemsize */
  (destructor)cms_object_dealloc,     /* tp_dealloc */
  0,                                  /* tp_print */
  0,                                  /* tp_getattr */
  0,                                  /* tp_setattr */
  0,                                  /* tp_compare */
  0,                                  /* tp_repr */
  0,                                  /* tp_as_number */
  0,                                  /* tp_as_sequence */
  0,                                  /* tp_as_mapping */
  0,                                  /* tp_hash */
  0,                                  /* tp_call */
  0,                                  /* tp_str */
  0,                                  /* tp_getattro */
  0,                                  /* tp_setattro */
  0,                                  /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
  POW_CMS_Type__doc__,                /* tp_doc */
  0,                                  /* tp_traverse */
  0,                                  /* tp_clear */
  0,                                  /* tp_richcompare */
  0,                                  /* tp_weaklistoffset */
  0,                                  /* tp_iter */
  0,                                  /* tp_iternext */
  cms_object_methods,                 /* tp_methods */
  0,                                  /* tp_members */
  0,                                  /* tp_getset */
  0,                                  /* tp_base */
  0,                                  /* tp_dict */
  0,                                  /* tp_descr_get */
  0,                                  /* tp_descr_set */
  0,                                  /* tp_dictoffset */
  0,                                  /* tp_init */
  0,                                  /* tp_alloc */
  cms_object_new,                     /* tp_new */
};



/*
 * Manifest object.
 */

static PyObject *
manifest_object_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  manifest_object *self = NULL;

  ENTERING(manifest_object_new);

  if ((self = (manifest_object *) cms_object_new(type, args, kwds)) != NULL &&
      (self->manifest = Manifest_new()) != NULL)
    return (PyObject *) self;

  Py_XDECREF(self);
  return NULL;
}

static void
manifest_object_dealloc(manifest_object *self)
{
  ENTERING(manifest_object_dealloc);
  Manifest_free(self->manifest);
  cms_object_dealloc(&self->cms);
}

static char manifest_object_verify__doc__[] =
  "Verify this manifest against a trusted certificate store.\n"
  "\n"
  CMS_OBJECT_VERIFY_HELPER__DOC__
  ;

static PyObject *
manifest_object_verify(manifest_object *self, PyObject *args, PyObject *kwds)
{
  BIO *bio = NULL;
  int ok = 0;

  ENTERING(manifest_object_verify);

  if ((bio = cms_object_verify_helper(&self->cms, args, kwds)) == NULL)
    goto error;

  if (!ASN1_item_d2i_bio(ASN1_ITEM_rptr(Manifest), bio, &self->manifest))
    lose_openssl_error("Couldn't decode manifest");

  ok = 1;

 error:
  BIO_free(bio);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char manifest_object_extract_without_verifying__doc__[] =
  "Extract manifest payload from CMS wrapper without attempting CMS verification.\n"
  "\n"
  "NEVER USE THIS METHOD ON AN UNVERIFIED MANIFEST!\n"
  ;

static PyObject *
manifest_object_extract_without_verifying(manifest_object *self)
{
  BIO *bio = NULL;
  int ok = 0;

  ENTERING(manifest_object_extract_without_verifying);

  if ((bio = cms_object_extract_without_verifying_helper(&self->cms)) == NULL)
    goto error;

  if (!ASN1_item_d2i_bio(ASN1_ITEM_rptr(Manifest), bio, &self->manifest))
    lose_openssl_error("Couldn't decode manifest");

  ok = 1;

 error:
  BIO_free(bio);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char manifest_object_check_rpki_conformance__doc__[] =
  "Check this manifest for conformance to the RPKI profile.\n"
  ;

static PyObject *
manifest_object_check_rpki_conformance(manifest_object *self, PyObject *args, PyObject *kwds)
{
  static char *kwlist[] = {"status", NULL};
  PyObject *status = Py_None;

  ENTERING(manifest_object_check_rpki_conformance);

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!", kwlist, &PySet_Type, &status))
    goto error;

  if (!check_cms(self->cms.cms, status) || !check_manifest(self->cms.cms, self->manifest, status))
    goto error;

  Py_RETURN_NONE;

 error:
  return NULL;
}


static PyObject *
manifest_object_der_read_helper(PyTypeObject *type, BIO *bio)
{
  manifest_object *self;

  ENTERING(manifest_object_der_read_helper);

  if ((self = (manifest_object *) cms_object_der_read_helper(type, bio)) != NULL)
    self->manifest = NULL;

  return (PyObject *) self;
}

static char manifest_object_der_read__doc__[] =
  "Read a DER-encoded manifest object from a string.\n"
  ;

static PyObject *
manifest_object_der_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(manifest_object_der_read);
  return read_from_string_helper(manifest_object_der_read_helper, type, args);
}

static char manifest_object_der_read_file__doc__[] =
  "Read a DER-encoded manifest object from a file.\n"
  ;

static PyObject *
manifest_object_der_read_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(manifest_object_der_read_file);
  return read_from_file_helper(manifest_object_der_read_helper, type, args);
}

static PyObject *
manifest_object_pem_read_helper(PyTypeObject *type, BIO *bio)
{
  manifest_object *self;

  ENTERING(manifest_object_pem_read_helper);

  if ((self = (manifest_object *) cms_object_pem_read_helper(type, bio)) != NULL)
    self->manifest = NULL;

  return (PyObject *) self;
}

static char manifest_object_pem_read__doc__[] =
  "Read a PEM-encoded manifest object from a string.\n"
  ;

static PyObject *
manifest_object_pem_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(manifest_object_pem_read);
  return read_from_string_helper(manifest_object_pem_read_helper, type, args);
}

static char manifest_object_pem_read_file__doc__[] =
  "Read a PEM-encoded manifest object from a file.\n"
  ;

static PyObject *
manifest_object_pem_read_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(manifest_object_pem_read_file);
  return read_from_file_helper(manifest_object_pem_read_helper, type, args);
}

static char manifest_object_get_version__doc__[] =
  "Return the version number of this manifest.\n"
  ;

static PyObject *
manifest_object_get_version(manifest_object *self)
{
  ENTERING(manifest_object_get_version);

  if (self->manifest == NULL)
    lose_not_verified("Can't report version of unverified manifest");

  if (self->manifest->version)
    return Py_BuildValue("N", ASN1_INTEGER_to_PyLong(self->manifest->version));
  else
    return PyInt_FromLong(0);

 error:
  return NULL;
}

static char manifest_object_set_version__doc__[] =
  "Set the version number of this manifest.\n"
  "\n"
  "The \"version\" parameter should be a non-negative integer.\n"
  "\n"
  "As of this writing, zero is both the default and the only defined version.\n"
  "Attempting to set any version number other than zero will fail, as we\n"
  "don't understand how to write other versions, by definition.\n"
  ;

static PyObject *
manifest_object_set_version(manifest_object *self, PyObject *args)
{
  int version = 0;

  ENTERING(manifest_object_set_version);

  if (!PyArg_ParseTuple(args, "|i", &version))
    goto error;

  if (version != 0)
    lose("RFC 6486 only defines RPKI manifest version zero");

  if (self->manifest == NULL)
    lose_not_verified("Can't set version of unverified manifest");

  ASN1_INTEGER_free(self->manifest->version);
  self->manifest->version = NULL;

  Py_RETURN_NONE;

 error:
  return NULL;
}

static char manifest_object_get_manifest_number__doc__[] =
  "Return the manifestNumber of this manifest.\n"
  ;

static PyObject *
manifest_object_get_manifest_number(manifest_object *self)
{
  ENTERING(manifest_object_get_manifest_number);

  if (self->manifest == NULL)
    lose_not_verified("Can't get manifestNumber of unverified manifest");

  return Py_BuildValue("N", ASN1_INTEGER_to_PyLong(self->manifest->manifestNumber));

 error:
  return NULL;
}

static char manifest_object_set_manifest_number__doc__[] =
  "Set the manifestNumber of this manifest.\n"
  "\n"
  "The \"manifestNumber\" parameter should be a non-negative integer.\n"
  ;

static PyObject *
manifest_object_set_manifest_number(manifest_object *self, PyObject *args)
{
  PyObject *manifestNumber = NULL;
  PyObject *zero = NULL;
  int ok = 0;

  ENTERING(manifest_object_set_manifest_number);

  if (!PyArg_ParseTuple(args, "O", &manifestNumber))
    goto error;

  if ((zero = PyInt_FromLong(0)) == NULL)
    goto error;

  switch (PyObject_RichCompareBool(manifestNumber, zero, Py_GE)) {
  case -1:
    goto error;
  case 0:
    lose("Negative manifest number is not allowed");
  }

  if (self->manifest == NULL)
    lose_not_verified("Can't set manifestNumber of unverified manifest");

  ASN1_INTEGER_free(self->manifest->manifestNumber);

  if ((self->manifest->manifestNumber = PyLong_to_ASN1_INTEGER(manifestNumber)) == NULL)
    goto error;

  ok = 1;

 error:
  Py_XDECREF(zero);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char manifest_object_set_this_update__doc__[] =
  "Set this manifest's \"thisUpdate\" value.\n"
  "\n"
  "The \"time\" parameter should be a datetime object.\n"
  ;

static PyObject *
manifest_object_set_this_update (manifest_object *self, PyObject *args)
{
  ASN1_TIME *t = NULL;
  PyObject *o = NULL;

  ENTERING(manifest_object_set_this_update);

  if (!PyArg_ParseTuple(args, "O", &o))
    goto error;

  if (self->manifest == NULL)
    lose_not_verified("Can't set thisUpdate value of unverified manifest");

  if ((t = Python_to_ASN1_TIME(o, 0)) == NULL)
    lose("Couldn't convert thisUpdate string");

  ASN1_TIME_free(self->manifest->thisUpdate);
  self->manifest->thisUpdate = t;
  Py_RETURN_NONE;

 error:
  ASN1_TIME_free(t);
  return NULL;
}

static char manifest_object_get_this_update__doc__[] =
  "Return this manifest's \"thisUpdate\" value as a datetime.\n"
  ;

static PyObject *
manifest_object_get_this_update (manifest_object *self)
{
  ENTERING(manifest_object_get_this_update);

  if (self->manifest == NULL)
    lose_not_verified("Can't get thisUpdate value of unverified manifest");

  return ASN1_TIME_to_Python(self->manifest->thisUpdate);

 error:
  return NULL;
}

static char manifest_object_set_next_update__doc__[] =
  "Set this manifest's \"nextUpdate\" value.\n"
  "\n"
  "The \"time\" parameter should be a datetime object.\n"
  ;

static PyObject *
manifest_object_set_next_update (manifest_object *self, PyObject *args)
{
  ASN1_TIME *t = NULL;
  PyObject *o = NULL;

  ENTERING(manifest_object_set_next_update);

  if (!PyArg_ParseTuple(args, "O", &o))
    goto error;

  if (self->manifest == NULL)
    lose_not_verified("Can't set nextUpdate value of unverified manifest"); 

  if ((t = Python_to_ASN1_TIME(o, 0)) == NULL)
    lose("Couldn't parse nextUpdate string");

  ASN1_TIME_free(self->manifest->nextUpdate);
  self->manifest->nextUpdate = t;
  Py_RETURN_NONE;

 error:
  ASN1_TIME_free(t);
  return NULL;
}

static char manifest_object_get_next_update__doc__[] =
  "Return this manifest's \"nextUpdate\" value as a datetime.\n"
  ;

static PyObject *
manifest_object_get_next_update (manifest_object *self)
{
  ENTERING(manifest_object_get_next_update);

  if (self->manifest == NULL)
    lose_not_verified("Can't extract nextUpdate value of unverified manifest");

  return ASN1_TIME_to_Python(self->manifest->nextUpdate);

 error:
  return NULL;
}

static char manifest_object_get_algorithm__doc__[] =
  "Return this manifest's fileHashAlg OID.\n"
  ;

static PyObject *
manifest_object_get_algorithm(manifest_object *self)
{
  PyObject *result = NULL;

  ENTERING(manifest_object_get_algorithm);

  if (self->manifest == NULL)
    lose_not_verified("Can't extract algorithm OID of unverified manifest");

  result = ASN1_OBJECT_to_PyString(self->manifest->fileHashAlg);

 error:
  return result;
}

static char manifest_object_set_algorithm__doc__[] =
  "Set this manifest's fileHashAlg OID.\n"
  ;

static PyObject *
manifest_object_set_algorithm(manifest_object *self, PyObject *args)
{
  ASN1_OBJECT *oid = NULL;
  const char *s = NULL;

  ENTERING(manifest_object_set_algorithm);

  if (!PyArg_ParseTuple(args, "s", &s))
    goto error;

  if (self->manifest == NULL)
    lose_not_verified("Can't set algorithm OID for unverified manifest");

  if ((oid = OBJ_txt2obj(s, 1)) == NULL)
    lose_no_memory();

  ASN1_OBJECT_free(self->manifest->fileHashAlg);
  self->manifest->fileHashAlg = oid;
  Py_RETURN_NONE;

 error:
  ASN1_OBJECT_free(oid);
  return NULL;
}

static char manifest_object_add_files__doc__[] =
  "Add a collection of <filename, hash> pairs to this manifest.\n"
  "\n"
  "The \"iterable\" parameter should be an iterable object supplying\n"
  "returning two-element sequences; the first element of each sequence\n"
  "should be the filename (a text string), the second element should be the\n"
  "hash (a binary string).\n"
  ;

static PyObject *
manifest_object_add_files(manifest_object *self, PyObject *args)
{
  PyObject *iterable = NULL;
  PyObject *iterator = NULL;
  PyObject *item = NULL;
  PyObject *fast = NULL;
  FileAndHash *fah = NULL;
  char *file = NULL;
  char *hash = NULL;
  Py_ssize_t filelen, hashlen;
  int ok = 0;

  ENTERING(manifest_object_add_files);

  if (self->manifest == NULL)
    lose_not_verified("Can't add files to unverified manifest");

  if (!PyArg_ParseTuple(args, "O", &iterable) ||
      (iterator = PyObject_GetIter(iterable)) == NULL)
    goto error;

  while ((item = PyIter_Next(iterator)) != NULL) {

    if ((fast = PySequence_Fast(item, "FileAndHash entry must be a sequence")) == NULL)
      goto error;

    if (PySequence_Fast_GET_SIZE(fast) != 2)
      lose_type_error("FileAndHash entry must be two-element sequence");

    if (PyString_AsStringAndSize(PySequence_Fast_GET_ITEM(fast, 0), &file, &filelen) < 0 ||
        PyString_AsStringAndSize(PySequence_Fast_GET_ITEM(fast, 1), &hash, &hashlen) < 0)
      goto error;

    if ((fah = FileAndHash_new()) == NULL ||
        !ASN1_OCTET_STRING_set(fah->file, (unsigned char *) file, filelen) ||
        !ASN1_BIT_STRING_set(fah->hash, (unsigned char *) hash, hashlen) ||
        !sk_FileAndHash_push(self->manifest->fileList, fah))
      lose_no_memory();

    fah->hash->flags &= ~7;
    fah->hash->flags |= ASN1_STRING_FLAG_BITS_LEFT;

    fah = NULL;
    Py_XDECREF(item);
    Py_XDECREF(fast);
    item = fast = NULL;
  }

  ok = 1;

 error:
  Py_XDECREF(iterator);
  Py_XDECREF(item);
  Py_XDECREF(fast);
  FileAndHash_free(fah);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char manifest_object_get_files__doc__[] =
  "Return a tuple of <filename, hash> pairs representing the contents of\n"
  "this manifest.\n"
  ;

static PyObject *
manifest_object_get_files(manifest_object *self)
{
  PyObject *result = NULL;
  PyObject *item = NULL;
  int i;

  ENTERING(manifest_object_get_files);

  if (self->manifest == NULL)
    lose_not_verified("Can't get files from unverified manifest");

  if (self->manifest->fileList == NULL)
    lose("Inexplicable NULL manifest fileList pointer");

  if ((result = PyTuple_New(sk_FileAndHash_num(self->manifest->fileList))) == NULL)
    goto error;

  for (i = 0; i < sk_FileAndHash_num(self->manifest->fileList); i++) {
    FileAndHash *fah = sk_FileAndHash_value(self->manifest->fileList, i);

    item = Py_BuildValue("(s#s#)",
                         ASN1_STRING_data(fah->file),
                         (Py_ssize_t) ASN1_STRING_length(fah->file),
                         ASN1_STRING_data(fah->hash),
                         (Py_ssize_t) ASN1_STRING_length(fah->hash));
    if (item == NULL)
      goto error;

    PyTuple_SET_ITEM(result, i, item);
    item = NULL;
  }

  return result;

 error:
  Py_XDECREF(result);
  Py_XDECREF(item);
  return NULL;
}

static char manifest_object_sign__doc__[] =
  "Sign this manifest.  See the CMS class's .sign() method for details.\n"
  ;

static PyObject *
manifest_object_sign(manifest_object *self, PyObject *args)
{
  asymmetric_object *signkey = NULL;
  x509_object *signcert = NULL;
  PyObject *x509_iterable = Py_None;
  PyObject *crl_iterable = Py_None;
  char *oid = NULL;
  unsigned flags = 0;
  BIO *bio = NULL;
  int ok = 0;

  ENTERING(manifest_object_sign);

  if (!PyArg_ParseTuple(args, "O!O!|OOsI",
                        &POW_X509_Type, &signcert,
                        &POW_Asymmetric_Type, &signkey,
                        &x509_iterable,
                        &crl_iterable,
                        &oid,
                        &flags))
    goto error;

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  assert_no_unhandled_openssl_errors();

  if (!ASN1_item_i2d_bio(ASN1_ITEM_rptr(Manifest), bio, self->manifest))
    lose_openssl_error("Couldn't encode manifest");

  assert_no_unhandled_openssl_errors();

  if (!cms_object_sign_helper(&self->cms, bio, signcert, signkey,
                              x509_iterable, crl_iterable, oid, flags))
    lose_openssl_error("Couldn't sign manifest");

  assert_no_unhandled_openssl_errors();

  ok = 1;

 error:
  BIO_free(bio);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static struct PyMethodDef manifest_object_methods[] = {
  Define_Method(getVersion,			manifest_object_get_version,                    METH_NOARGS),
  Define_Method(setVersion,			manifest_object_set_version,                    METH_VARARGS),
  Define_Method(getManifestNumber,		manifest_object_get_manifest_number,            METH_NOARGS),
  Define_Method(setManifestNumber,		manifest_object_set_manifest_number,            METH_VARARGS),
  Define_Method(getThisUpdate,			manifest_object_get_this_update,                METH_NOARGS),
  Define_Method(setThisUpdate,			manifest_object_set_this_update,                METH_VARARGS),
  Define_Method(getNextUpdate,			manifest_object_get_next_update,                METH_NOARGS),
  Define_Method(setNextUpdate,			manifest_object_set_next_update,                METH_VARARGS),
  Define_Method(getAlgorithm,			manifest_object_get_algorithm,                  METH_NOARGS),
  Define_Method(setAlgorithm,			manifest_object_set_algorithm,                  METH_VARARGS),
  Define_Method(getFiles,			manifest_object_get_files,                      METH_NOARGS),
  Define_Method(addFiles,			manifest_object_add_files,                      METH_VARARGS),
  Define_Method(sign,				manifest_object_sign,                           METH_VARARGS),
  Define_Method(verify,				manifest_object_verify,                         METH_KEYWORDS),
  Define_Method(checkRPKIConformance,		manifest_object_check_rpki_conformance,         METH_KEYWORDS),
  Define_Method(extractWithoutVerifying,	manifest_object_extract_without_verifying,      METH_NOARGS),
  Define_Class_Method(pemRead,			manifest_object_pem_read,                       METH_VARARGS),
  Define_Class_Method(pemReadFile,		manifest_object_pem_read_file,                  METH_VARARGS),
  Define_Class_Method(derRead,			manifest_object_der_read,                       METH_VARARGS),
  Define_Class_Method(derReadFile,		manifest_object_der_read_file,                  METH_VARARGS),
  {NULL}
};

static char POW_Manifest_Type__doc__[] =
  "This class provides access to RPKI manifest payload.\n"
  "Most methods are inherited from or share code with the CMS class.\n"
  ;

static PyTypeObject POW_Manifest_Type = {
  PyObject_HEAD_INIT(0)
  0,                                            /* ob_size */
  "rpki.POW.Manifest",                          /* tp_name */
  sizeof(manifest_object),                      /* tp_basicsize */
  0,                                            /* tp_itemsize */
  (destructor)manifest_object_dealloc,          /* tp_dealloc */
  0,                                            /* tp_print */
  0,                                            /* tp_getattr */
  0,                                            /* tp_setattr */
  0,                                            /* tp_compare */
  0,                                            /* tp_repr */
  0,                                            /* tp_as_number */
  0,                                            /* tp_as_sequence */
  0,                                            /* tp_as_mapping */
  0,                                            /* tp_hash */
  0,                                            /* tp_call */
  0,                                            /* tp_str */
  0,                                            /* tp_getattro */
  0,                                            /* tp_setattro */
  0,                                            /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,     /* tp_flags */
  POW_Manifest_Type__doc__,                     /* tp_doc */
  0,                                            /* tp_traverse */
  0,                                            /* tp_clear */
  0,                                            /* tp_richcompare */
  0,                                            /* tp_weaklistoffset */
  0,                                            /* tp_iter */
  0,                                            /* tp_iternext */
  manifest_object_methods,                      /* tp_methods */
  0,                                            /* tp_members */
  0,                                            /* tp_getset */
  &POW_CMS_Type,                                /* tp_base */
  0,                                            /* tp_dict */
  0,                                            /* tp_descr_get */
  0,                                            /* tp_descr_set */
  0,                                            /* tp_dictoffset */
  0,                                            /* tp_init */
  0,                                            /* tp_alloc */
  manifest_object_new,                          /* tp_new */
};



/*
 * ROA object.
 */

static PyObject *
roa_object_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  roa_object *self = NULL;

  ENTERING(roa_object_new);

  if ((self = (roa_object *) cms_object_new(type, args, kwds)) != NULL &&
      (self->roa = ROA_new()) != NULL)
    return (PyObject *) self;

  Py_XDECREF(self);
  return NULL;
}

static void
roa_object_dealloc(roa_object *self)
{
  ENTERING(roa_object_dealloc);
  ROA_free(self->roa);
  cms_object_dealloc(&self->cms);
}

static char roa_object_verify__doc__[] =
  "Verify this ROA against a trusted certificate store.\n"
  "\n"
  CMS_OBJECT_VERIFY_HELPER__DOC__
  ;

static PyObject *
roa_object_verify(roa_object *self, PyObject *args, PyObject *kwds)
{
  BIO *bio = NULL;
  int ok = 0;

  ENTERING(roa_object_verify);

  if ((bio = cms_object_verify_helper(&self->cms, args, kwds)) == NULL)
    goto error;
  
  if (!ASN1_item_d2i_bio(ASN1_ITEM_rptr(ROA), bio, &self->roa))
    lose_openssl_error("Couldn't decode ROA");

  ok = 1;

 error:
  BIO_free(bio);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}


static char roa_object_extract_without_verifying__doc__[] =
  "Extract ROA payload from CMS wrapper without attempting CMS verification.\n"
  "\n"
  "NEVER USE THIS METHOD ON AN UNVERIFIED ROA!\n"
  ;

static PyObject *
roa_object_extract_without_verifying(roa_object *self)
{
  BIO *bio = NULL;
  int ok = 0;

  ENTERING(roa_object_extract_without_verifying);

  if ((bio = cms_object_extract_without_verifying_helper(&self->cms)) == NULL)
    goto error;

  if (!ASN1_item_d2i_bio(ASN1_ITEM_rptr(ROA), bio, &self->roa))
    lose_openssl_error("Couldn't decode ROA");

  ok = 1;

 error:
  BIO_free(bio);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char roa_object_check_rpki_conformance__doc__[] =
  "Check this ROA for conformance to the RPKI profile.\n"
  ;

static PyObject *
roa_object_check_rpki_conformance(roa_object *self, PyObject *args, PyObject *kwds)
{
  static char *kwlist[] = {"status", NULL};
  PyObject *status = Py_None;

  ENTERING(roa_object_check_rpki_conformance);

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!", kwlist, &PySet_Type, &status))
    goto error;

  if (!check_cms(self->cms.cms, status) || !check_roa(self->cms.cms, self->roa, status))
    goto error;

  Py_RETURN_NONE;

 error:
  return NULL;
}

static PyObject *
roa_object_pem_read_helper(PyTypeObject *type, BIO *bio)
{
  roa_object *self;

  ENTERING(roa_object_pem_read_helper);

  if ((self = (roa_object *) cms_object_pem_read_helper(type, bio)) != NULL)
    self->roa = NULL;

  return (PyObject *) self;
}

static PyObject *
roa_object_der_read_helper(PyTypeObject *type, BIO *bio)
{
  roa_object *self;

  ENTERING(roa_object_der_read_helper);

  if ((self = (roa_object *) cms_object_der_read_helper(type, bio)) != NULL)
    self->roa = NULL;

  return (PyObject *) self;
}

static char roa_object_pem_read__doc__[] =
  "Read a PEM-encoded ROA object from a string.\n"
  ;

static PyObject *
roa_object_pem_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(roa_object_pem_read);
  return read_from_string_helper(roa_object_pem_read_helper, type, args);
}

static char roa_object_pem_read_file__doc__[] =
  "Read a PEM-encoded ROA object from a file.\n"
  ;

static PyObject *
roa_object_pem_read_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(roa_object_pem_read_file);
  return read_from_file_helper(roa_object_pem_read_helper, type, args);
}

static char roa_object_der_read__doc__[] =
  "Read a DER-encoded ROA object from a string.\n"
  ;

static PyObject *
roa_object_der_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(roa_object_der_read);
  return read_from_string_helper(roa_object_der_read_helper, type, args);
}

static char roa_object_der_read_file__doc__[] =
  "Read a DER-encoded ROA object from a file.\n"
  ;

static PyObject *
roa_object_der_read_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(roa_object_der_read_file);
  return read_from_file_helper(roa_object_der_read_helper, type, args);
}

static char roa_object_get_version__doc__[] =
  "Return the version number of this ROA.\n"
  ;

static PyObject *
roa_object_get_version(roa_object *self)
{
  ENTERING(roa_object_get_version);

  if (self->roa == NULL)
    lose_not_verified("Can't get version of unverified ROA");

  if (self->roa->version)
    return Py_BuildValue("N", ASN1_INTEGER_to_PyLong(self->roa->version));
  else
    return PyInt_FromLong(0);

 error:
  return NULL;
}

static char roa_object_set_version__doc__[] =
  "Set the version number of this ROA.\n"
  "\n"
  "The \"version\" parameter should be a non-negative integer.\n"
  "\n"
  "As of this writing, zero is both the default and the only defined version.\n"
  "Attempting to set any version number other than zero will fail, as we\n"
  "don't understand how to write other versions, by definition.\n"
  ;

static PyObject *
roa_object_set_version(roa_object *self, PyObject *args)
{
  int version = 0;

  ENTERING(roa_object_set_version);

  if (self->roa == NULL)
    lose_not_verified("Can't set version of unverified ROA");

  if (!PyArg_ParseTuple(args, "|i", &version))
    goto error;

  if (version != 0)
    lose("RFC 6482 only defines ROA version zero");

  ASN1_INTEGER_free(self->roa->version);
  self->roa->version = NULL;

  Py_RETURN_NONE;

 error:
  return NULL;
}

static char roa_object_get_asid__doc__[] =
  "Return the Autonomous System ID of this ROA.\n"
  ;

static PyObject *
roa_object_get_asid(roa_object *self)
{
  ENTERING(roa_object_get_asid);

  if (self->roa == NULL)
    lose_not_verified("Can't get ASN of unverified ROA");

  return Py_BuildValue("N", ASN1_INTEGER_to_PyLong(self->roa->asID));

 error:
  return NULL;
}

static char roa_object_set_asid__doc__[] =
  "Sets the Autonomous System ID of this ROA.\n"
  "\n"
  "The \"asID\" parameter should be a non-negative integer.\n"
  ;

static PyObject *
roa_object_set_asid(roa_object *self, PyObject *args)
{
  PyObject *asID = NULL;
  PyObject *zero = NULL;
  int ok = 0;

  ENTERING(roa_object_set_asid);

  if (self->roa == NULL)
    lose_not_verified("Can't set ASN of unverified ROA");

  if (!PyArg_ParseTuple(args, "O", &asID))
    goto error;

  if ((zero = PyInt_FromLong(0)) == NULL)
    goto error;

  switch (PyObject_RichCompareBool(asID, zero, Py_GE)) {
  case -1:
    goto error;
  case 0:
    lose("Negative asID is not allowed");
  }

  ASN1_INTEGER_free(self->roa->asID);

  if ((self->roa->asID = PyLong_to_ASN1_INTEGER(asID)) == NULL)
    goto error;

  ok = 1;

 error:
  Py_XDECREF(zero);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char roa_object_get_prefixes__doc__[] =
  "Return this ROA's prefix list.  This is a two-element\n"
  "tuple: the first element is the IPv4 prefix set, the second is the\n"
  "IPv6 prefix set.\n"
  "\n"
  "Each prefix set is either None, if there are no prefixes for this IP\n"
  "version, or a sequence of three-element tuple representing ROA prefix\n"
  "entries.\n"
  "\n"
  "Each ROA prefix entry consists of the prefix itself (an IPAddress),\n"
  "the prefix length (an integer), and the maxPrefixLen value, which is\n"
  "either an integer or None depending on whether the maxPrefixLen value\n"
  "is set for this prefix.\n"
  ;

static PyObject *
roa_object_get_prefixes(roa_object *self)
{
  PyObject *result = NULL;
  PyObject *ipv4_result = NULL;
  PyObject *ipv6_result = NULL;
  PyObject *item = NULL;
  ipaddress_object *addr = NULL;
  int i, j;

  ENTERING(roa_object_get_prefixes);

  if (self->roa == NULL)
    lose_not_verified("Can't get prefixes from unverified ROA");

  for (i = 0; i < sk_ROAIPAddressFamily_num(self->roa->ipAddrBlocks); i++) {
    ROAIPAddressFamily *fam = sk_ROAIPAddressFamily_value(self->roa->ipAddrBlocks, i);
    const unsigned afi = (fam->addressFamily->data[0] << 8) | (fam->addressFamily->data[1]);
    const ipaddress_version *ip_type = NULL;
    PyObject **resultp = NULL;

    switch (afi) {
    case IANA_AFI_IPV4: resultp = &ipv4_result; ip_type = &ipaddress_version_4; break;
    case IANA_AFI_IPV6: resultp = &ipv6_result; ip_type = &ipaddress_version_6; break;
    default:            lose_value_error("Unknown AFI");
    }

    if (fam->addressFamily->length > 2)
      lose_value_error("Unsupported SAFI");

    if (*resultp != NULL)
      lose_value_error("Duplicate ROAIPAddressFamily");

    if ((*resultp = PyTuple_New(sk_ROAIPAddress_num(fam->addresses))) == NULL)
      goto error;

    for (j = 0; j < sk_ROAIPAddress_num(fam->addresses); j++) {
      ROAIPAddress *a = sk_ROAIPAddress_value(fam->addresses, j);
      unsigned prefixlen = ((a->IPAddress)->length * 8 - ((a->IPAddress)->flags & 7));

      if ((addr = (ipaddress_object *) POW_IPAddress_Type.tp_alloc(&POW_IPAddress_Type, 0)) == NULL)
        goto error;

      addr->type = ip_type;

      memset(addr->address, 0, sizeof(addr->address));

      if ((unsigned) a->IPAddress->length > addr->type->length)
        lose("ROAIPAddress BIT STRING too long for AFI");

      if (a->IPAddress->length > 0) {
        memcpy(addr->address, a->IPAddress->data, a->IPAddress->length);

        if ((a->IPAddress->flags & 7) != 0) {
          unsigned char mask = 0xFF >> (8 - (a->IPAddress->flags & 7));
          addr->address[a->IPAddress->length - 1] &= ~mask;
        }
      }

      if (a->maxLength == NULL)
        item = Py_BuildValue("(NIO)", addr, prefixlen, Py_None);
      else
        item = Py_BuildValue("(NIl)", addr, prefixlen, ASN1_INTEGER_get(a->maxLength));

      if (item == NULL)
        goto error;

      PyTuple_SET_ITEM(*resultp, j, item);
      item = NULL;
      addr = NULL;
    }
  }

  result = Py_BuildValue("(OO)",
                         (ipv4_result == NULL ? Py_None : ipv4_result),
                         (ipv6_result == NULL ? Py_None : ipv6_result));

 error:                         /* Fall through */
  Py_XDECREF(addr);
  Py_XDECREF(item);
  Py_XDECREF(ipv4_result);
  Py_XDECREF(ipv6_result);

  return result;
}

static char roa_object_set_prefixes__doc__[] =
  "Set this ROA's prefix list.\n"
  "\n"
  "This method takes two arguments, \"ipv4\" and \"ipv6\".  Each of these\n"
  "is either None, if no prefixes should be set for this IP version, or\n"
  "an iterable object returning ROA prefix entries in the same format as\n"
  "returned by the .getPrefixes() method.  The maxPrefixLen value may be\n"
  "omitted (that is, the ROA prefix entry tuple may be of length two\n"
  "rather than of length three); this will be taken as equivalent to\n"
  "specifying a maxPrefixLen value of None.\n"
  ;

static PyObject *
roa_object_set_prefixes(roa_object *self, PyObject *args, PyObject *kwds)
{
  static char *kwlist[] = {"ipv4", "ipv6", NULL};
  STACK_OF(ROAIPAddressFamily) *prefixes = NULL;
  ROAIPAddressFamily *fam = NULL;
  ROAIPAddress *a = NULL;
  PyObject *ipv4_arg = Py_None;
  PyObject *ipv6_arg = Py_None;
  PyObject *iterator = NULL;
  PyObject *item = NULL;
  PyObject *fast = NULL;
  int ok = 0;
  int v;

  ENTERING(roa_object_set_prefixes);

  if (self->roa == NULL)
    lose_not_verified("Can't set prefixes of unverified ROA");

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "|OO", kwlist, &ipv4_arg, &ipv6_arg))
    goto error;

  if ((prefixes = sk_ROAIPAddressFamily_new_null()) == NULL)
    lose_no_memory();

  for (v = 0; v < (int) (sizeof(ipaddress_versions)/sizeof(*ipaddress_versions)); v++) {
    const struct ipaddress_version *ip_type = ipaddress_versions[v];
    unsigned char afibuf[2];
    PyObject **argp;

    switch (ip_type->version) {
    case 4: argp = &ipv4_arg; break;
    case 6: argp = &ipv6_arg; break;
    default: continue;
    }

    if (*argp == Py_None)
      continue;

    afibuf[0] = (ip_type->afi >> 8) & 0xFF;
    afibuf[1] = (ip_type->afi     ) & 0xFF;

    if ((iterator = PyObject_GetIter(*argp)) == NULL)
      goto error;

    while ((item = PyIter_Next(iterator)) != NULL) {
      unsigned prefixlen, maxprefixlen, bitlen, bytelen;
      ipaddress_object *addr = NULL;
      PyObject *maxlenobj = Py_None;

      if ((fast = PySequence_Fast(item, "ROA prefix must be a sequence")) == NULL)
        goto error;

      switch (PySequence_Fast_GET_SIZE(fast)) {
      case 3:
        maxlenobj = PySequence_Fast_GET_ITEM(fast, 2);
        /* Fall through */
      case 2:
        if (!POW_IPAddress_Check(PySequence_Fast_GET_ITEM(fast, 0)))
          lose_type_error("First element of ROA prefix must be an IPAddress object");
        addr = (ipaddress_object *) PySequence_Fast_GET_ITEM(fast, 0);
        prefixlen = (unsigned) PyInt_AsLong(PySequence_Fast_GET_ITEM(fast, 1));
        if (PyErr_Occurred())
          goto error;
        break;
      default:
        lose_type_error("ROA prefix must be a two- or three-element sequence");
      }

      if (maxlenobj == Py_None) {
        maxprefixlen = prefixlen;
      } else {
        maxprefixlen = (unsigned) PyInt_AsLong(maxlenobj);
        if (PyErr_Occurred())
          goto error;
      }

      if (addr->type != ip_type)
        lose_value_error("Bad ROA prefix");

      if (prefixlen > addr->type->length * 8)
        lose("Bad prefix length");

      if (maxprefixlen > addr->type->length * 8 || maxprefixlen < prefixlen)
        lose("Bad maxLength value");

      bytelen = (prefixlen + 7) / 8;
      bitlen = prefixlen % 8;

      if ((a = ROAIPAddress_new()) == NULL ||
          (a->IPAddress == NULL && (a->IPAddress = ASN1_BIT_STRING_new()) == NULL) ||
          !ASN1_BIT_STRING_set(a->IPAddress, addr->address, bytelen))
        lose_no_memory();

      a->IPAddress->flags &= ~7;
      a->IPAddress->flags |= ASN1_STRING_FLAG_BITS_LEFT;
      if (bitlen > 0) {
        a->IPAddress->data[bytelen - 1] &= ~(0xFF >> bitlen);
        a->IPAddress->flags |= 8 - bitlen;
      }

      if (prefixlen != maxprefixlen &&
          ((a->maxLength = ASN1_INTEGER_new()) == NULL ||
           !ASN1_INTEGER_set(a->maxLength, maxprefixlen)))
        lose_no_memory();

      if (fam == NULL &&
          ((fam = ROAIPAddressFamily_new()) == NULL ||
           !sk_ROAIPAddressFamily_push(prefixes, fam) ||
           !ASN1_OCTET_STRING_set(fam->addressFamily, afibuf, sizeof(afibuf))))
        lose_no_memory();

      if (!sk_ROAIPAddress_push(fam->addresses, a))
        lose_no_memory();

      a = NULL;
      Py_XDECREF(item);
      Py_XDECREF(fast);
      item = fast = NULL;
    }

    fam = NULL;
    Py_XDECREF(iterator);
    iterator = NULL;
  }

  sk_ROAIPAddressFamily_pop_free(self->roa->ipAddrBlocks, ROAIPAddressFamily_free);
  self->roa->ipAddrBlocks = prefixes;
  prefixes = NULL;

  ok = 1;

 error:
  sk_ROAIPAddressFamily_pop_free(prefixes, ROAIPAddressFamily_free);
  ROAIPAddressFamily_free(fam);
  ROAIPAddress_free(a);
  Py_XDECREF(iterator);
  Py_XDECREF(item);
  Py_XDECREF(fast);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char roa_object_sign__doc__[] =
  "Sign this ROA.  See CMS.sign() for details.\n"
  ;

static PyObject *
roa_object_sign(roa_object *self, PyObject *args)
{
  asymmetric_object *signkey = NULL;
  x509_object *signcert = NULL;
  PyObject *x509_iterable = Py_None;
  PyObject *crl_iterable = Py_None;
  char *oid = NULL;
  unsigned flags = 0;
  BIO *bio = NULL;
  int ok = 0;

  ENTERING(roa_object_sign);

  if (!PyArg_ParseTuple(args, "O!O!|OOsI",
                        &POW_X509_Type, &signcert,
                        &POW_Asymmetric_Type, &signkey,
                        &x509_iterable,
                        &crl_iterable,
                        &oid,
                        &flags))
    goto error;

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  assert_no_unhandled_openssl_errors();

  if (!ASN1_item_i2d_bio(ASN1_ITEM_rptr(ROA), bio, self->roa))
    lose_openssl_error("Couldn't encode ROA");

  assert_no_unhandled_openssl_errors();

  if (!cms_object_sign_helper(&self->cms, bio, signcert, signkey,
                              x509_iterable, crl_iterable, oid, flags))
    lose_openssl_error("Couldn't sign ROA");

  assert_no_unhandled_openssl_errors();

  ok = 1;

 error:
  BIO_free(bio);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static struct PyMethodDef roa_object_methods[] = {
  Define_Method(getVersion,                     roa_object_get_version,                 METH_NOARGS),
  Define_Method(setVersion,                     roa_object_set_version,                 METH_VARARGS),
  Define_Method(getASID,                        roa_object_get_asid,                    METH_NOARGS),
  Define_Method(setASID,                        roa_object_set_asid,                    METH_VARARGS),
  Define_Method(getPrefixes,                    roa_object_get_prefixes,                METH_NOARGS),
  Define_Method(setPrefixes,                    roa_object_set_prefixes,                METH_KEYWORDS),
  Define_Method(sign,                           roa_object_sign,                        METH_VARARGS),
  Define_Method(verify,                         roa_object_verify,                      METH_KEYWORDS),
  Define_Method(extractWithoutVerifying,        roa_object_extract_without_verifying,   METH_NOARGS),
  Define_Method(checkRPKIConformance,           roa_object_check_rpki_conformance,      METH_KEYWORDS),
  Define_Class_Method(pemRead,                  roa_object_pem_read,                    METH_VARARGS),
  Define_Class_Method(pemReadFile,              roa_object_pem_read_file,               METH_VARARGS),
  Define_Class_Method(derRead,                  roa_object_der_read,                    METH_VARARGS),
  Define_Class_Method(derReadFile,              roa_object_der_read_file,               METH_VARARGS),
  {NULL}
};

static char POW_ROA_Type__doc__[] =
  "This class provides access to RPKI ROA payload.\n"
  "Most methods are inherited from or share code with the CMS class.\n"
  ;

static PyTypeObject POW_ROA_Type = {
  PyObject_HEAD_INIT(0)
  0,                                            /* ob_size */
  "rpki.POW.ROA",                               /* tp_name */
  sizeof(roa_object),                           /* tp_basicsize */
  0,                                            /* tp_itemsize */
  (destructor)roa_object_dealloc,               /* tp_dealloc */
  0,                                            /* tp_print */
  0,                                            /* tp_getattr */
  0,                                            /* tp_setattr */
  0,                                            /* tp_compare */
  0,                                            /* tp_repr */
  0,                                            /* tp_as_number */
  0,                                            /* tp_as_sequence */
  0,                                            /* tp_as_mapping */
  0,                                            /* tp_hash */
  0,                                            /* tp_call */
  0,                                            /* tp_str */
  0,                                            /* tp_getattro */
  0,                                            /* tp_setattro */
  0,                                            /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,     /* tp_flags */
  POW_ROA_Type__doc__,                          /* tp_doc */
  0,                                            /* tp_traverse */
  0,                                            /* tp_clear */
  0,                                            /* tp_richcompare */
  0,                                            /* tp_weaklistoffset */
  0,                                            /* tp_iter */
  0,                                            /* tp_iternext */
  roa_object_methods,                           /* tp_methods */
  0,                                            /* tp_members */
  0,                                            /* tp_getset */
  &POW_CMS_Type,                                /* tp_base */
  0,                                            /* tp_dict */
  0,                                            /* tp_descr_get */
  0,                                            /* tp_descr_set */
  0,                                            /* tp_dictoffset */
  0,                                            /* tp_init */
  0,                                            /* tp_alloc */
  roa_object_new,                               /* tp_new */
};



/*
 * PKCS10 object.
 */

static PyObject *
pkcs10_object_new(PyTypeObject *type, GCC_UNUSED PyObject *args, GCC_UNUSED PyObject *kwds)
{
  pkcs10_object *self;

  ENTERING(pkcs10_object_new);

  if ((self = (pkcs10_object *) type->tp_alloc(type, 0)) != NULL &&
      (self->pkcs10 = X509_REQ_new()) != NULL &&
      (self->exts = sk_X509_EXTENSION_new_null()) != NULL)
    return (PyObject *) self;

  Py_XDECREF(self);
  return NULL;
}

static void
pkcs10_object_dealloc(pkcs10_object *self)
{
  ENTERING(pkcs10_object_dealloc);
  X509_REQ_free(self->pkcs10);
  sk_X509_EXTENSION_pop_free(self->exts, X509_EXTENSION_free);
  self->ob_type->tp_free((PyObject*) self);
}

static PyObject *
pkcs10_object_pem_read_helper(PyTypeObject *type, BIO *bio)
{
  pkcs10_object *self = NULL;

  ENTERING(pkcs10_object_pem_read_helper);

  assert_no_unhandled_openssl_errors();

  if ((self = (pkcs10_object *) pkcs10_object_new(type, NULL, NULL)) == NULL)
    goto error;

  assert_no_unhandled_openssl_errors();

  if (!PEM_read_bio_X509_REQ(bio, &self->pkcs10, NULL, NULL))
    lose_openssl_error("Couldn't load PEM encoded PKCS#10 request");

  sk_X509_EXTENSION_pop_free(self->exts, X509_EXTENSION_free);
  self->exts = X509_REQ_get_extensions(self->pkcs10);

  assert_no_unhandled_openssl_errors();

  return (PyObject *) self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static PyObject *
pkcs10_object_der_read_helper(PyTypeObject *type, BIO *bio)
{
  pkcs10_object *self = NULL;

  ENTERING(pkcs10_object_der_read_helper);

  assert_no_unhandled_openssl_errors();

  if ((self = (pkcs10_object *) pkcs10_object_new(type, NULL, NULL)) == NULL)
    goto error;

  assert_no_unhandled_openssl_errors();

  if (!d2i_X509_REQ_bio(bio, &self->pkcs10))
    lose_openssl_error("Couldn't load DER encoded PKCS#10 request");

  sk_X509_EXTENSION_pop_free(self->exts, X509_EXTENSION_free);
  self->exts = X509_REQ_get_extensions(self->pkcs10);

  assert_no_unhandled_openssl_errors();

  return (PyObject *) self;

 error:
  Py_XDECREF(self);
  return NULL;
}

static char pkcs10_object_pem_read__doc__[] =
  "Read a PEM-encoded PKCS#10 object from a string.\n"
  ;

static PyObject *
pkcs10_object_pem_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(pkcs10_object_pem_read);
  return read_from_string_helper(pkcs10_object_pem_read_helper, type, args);
}

static char pkcs10_object_pem_read_file__doc__[] =
  "Read a PEM-encoded PKCS#10 object from a file.\n"
  ;

static PyObject *
pkcs10_object_pem_read_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(pkcs10_object_pem_read_file);
  return read_from_file_helper(pkcs10_object_pem_read_helper, type, args);
}

static char pkcs10_object_der_read__doc__[] =
  "Read a DER-encoded PKCS#10 object from a string.\n"
  ;

static PyObject *
pkcs10_object_der_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(pkcs10_object_der_read);
  return read_from_string_helper(pkcs10_object_der_read_helper, type, args);
}

static char pkcs10_object_der_read_file__doc__[] =
  "Read a DER-encoded PKCS#10 object from a file.\n"
  ;

static PyObject *
pkcs10_object_der_read_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(pkcs10_object_der_read_file);
  return read_from_file_helper(pkcs10_object_der_read_helper, type, args);
}

static char pkcs10_object_pem_write__doc__[] =
  "Returns the PEM encoding of this PKCS#10 object.\n"
  ;

static PyObject *
pkcs10_object_pem_write(pkcs10_object *self)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  ENTERING(pkcs10_object_pem_write);

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  if (!PEM_write_bio_X509_REQ(bio, self->pkcs10))
    lose_openssl_error("Unable to write PKCS#10 request");

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static char pkcs10_object_der_write__doc__[] =
  "Return the DER encoding of this PKCS#10 object.\n"
  ;

static PyObject *
pkcs10_object_der_write(pkcs10_object *self)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  ENTERING(pkcs10_object_der_write);

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  if (!i2d_X509_REQ_bio(bio, self->pkcs10))
    lose_openssl_error("Unable to write PKCS#10 request");

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static X509_EXTENSION *
pkcs10_object_extension_get_helper(pkcs10_object *self, int nid)
{
  if (self != NULL && self->exts != NULL)
    return X509v3_get_ext(self->exts, X509v3_get_ext_by_NID(self->exts, nid, -1));
  else
    return NULL;
}

static PyObject *
pkcs10_object_extension_set_helper(pkcs10_object *self, extension_wrapper ext)
{
  int ok = 0;

  if (ext.value == NULL)
    goto error;

  if (!X509V3_add1_i2d(&self->exts, ext.nid, ext.value, ext.critical, X509V3_ADD_REPLACE))
    lose_openssl_error("Couldn't add extension to PKCS #10 object");

  ok = 1;

 error:
  ext.destructor(ext.value);
  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char pkcs10_object_get_public_key__doc__[] =
  "Return the public key from this PKCS#10 request, as an Asymmetric\n"
  "object.\n"
  ;

static PyObject *
pkcs10_object_get_public_key(pkcs10_object *self)
{
  PyTypeObject *type = &POW_Asymmetric_Type;
  asymmetric_object *asym = NULL;

  ENTERING(pkcs10_object_get_public_key);

  if ((asym = (asymmetric_object *) type->tp_alloc(type, 0)) == NULL)
    goto error;

  if ((asym->pkey = X509_REQ_get_pubkey(self->pkcs10)) == NULL)
    lose_openssl_error("Couldn't extract public key from PKCS#10 request");

  whack_ec_key_to_namedCurve(asym->pkey);

  return (PyObject *) asym;

 error:
  Py_XDECREF(asym);
  return NULL;
}

static char pkcs10_object_set_public_key__doc__[] =
  "Set the public key for this PKCS#10 request.\n"
  "\n"
  "The \"key\" parameter should be an instance of the Asymmetric class,\n"
  "containing a public key.\n"
  ;

static PyObject *
pkcs10_object_set_public_key(pkcs10_object *self, PyObject *args)
{
  asymmetric_object *asym;

  ENTERING(pkcs10_object_set_public_key);

  if (!PyArg_ParseTuple(args, "O!", &POW_Asymmetric_Type, &asym))
    goto error;

  if (!X509_REQ_set_pubkey(self->pkcs10, asym->pkey))
    lose_openssl_error("Couldn't set certificate's PKCS#10 request");

  Py_RETURN_NONE;

 error:
  return NULL;
}

static char pkcs10_object_sign__doc__[] =
  "Sign a PKCS#10 request with a private key.\n"
  "\n"
  "The \"key\" parameter should be an instance of the Asymmetric class,\n"
  "containing a private key.\n"
  "\n"
  "The optional \"digest\" parameter indicates which digest to compute and\n"
  "sign, and should be one of the following:\n"
  "\n"
  "* SHA1_DIGEST\n"
  "* SHA256_DIGEST\n"
  "* SHA384_DIGEST\n"
  "* SHA512_DIGEST\n"
  "\n"
  "The default digest algorithm is SHA-256.\n"
  ;

static PyObject *
pkcs10_object_sign(pkcs10_object *self, PyObject *args)
{
  asymmetric_object *asym;
  int loc, digest_type = SHA256_DIGEST;
  const EVP_MD *digest_method = NULL;

  ENTERING(pkcs10_object_sign);

  if (!PyArg_ParseTuple(args, "O!|i", &POW_Asymmetric_Type, &asym, &digest_type))
    goto error;

  if ((digest_method = evp_digest_factory(digest_type)) == NULL)
    lose("Unsupported digest algorithm");

  while ((loc = X509_REQ_get_attr_by_NID(self->pkcs10, NID_ext_req, -1)) >= 0)
    X509_ATTRIBUTE_free(X509_REQ_delete_attr(self->pkcs10, loc));

  if (sk_X509_EXTENSION_num(self->exts) > 0 &&
      !X509_REQ_add_extensions(self->pkcs10, self->exts))
    lose_openssl_error("Couldn't add extensions block to PKCS#10 request");

  if (!X509_REQ_sign(self->pkcs10, asym->pkey, digest_method))
    lose_openssl_error("Couldn't sign PKCS#10 request");

  Py_RETURN_NONE;

 error:
  return NULL;
}

static char pkcs10_object_verify__doc__[] =
  "Verify a PKCS#10 request.\n"
  "\n"
  "This calls OpenSSL's X509_REQ_verify() method to check the request's\n"
  "self-signature.\n"
  ;

static PyObject *
pkcs10_object_verify(pkcs10_object *self)
{
  EVP_PKEY *pkey = NULL;
  int status;

  ENTERING(pkcs10_object_verify);

  if ((pkey = X509_REQ_get_pubkey(self->pkcs10)) == NULL)
    lose_openssl_error("Couldn't extract public key from PKCS#10 for verification");

  if ((status = X509_REQ_verify(self->pkcs10, pkey)) < 0)
    lose_openssl_error("Couldn't verify PKCS#10 signature");

  EVP_PKEY_free(pkey);
  return PyBool_FromLong(status);

 error:
  EVP_PKEY_free(pkey);
  return NULL;
}

static char pkcs10_object_get_version__doc__[] =
  "Return the version number of this PKCS#10 request.\n"
  ;

static PyObject *
pkcs10_object_get_version(pkcs10_object *self)
{
  ENTERING(pkcs10_object_get_version);
  return Py_BuildValue("l", X509_REQ_get_version(self->pkcs10));
}

static char pkcs10_object_set_version__doc__[] =
  "Set the version number of this PKCS#10 request.\n"
  "\n"
  "The \"version\" parameter should be an integer, but the only defined\n"
  "value is zero, so this field is optional and defaults to zero.\n"
;

static PyObject *
pkcs10_object_set_version(pkcs10_object *self, PyObject *args)
{
  long version = 0;

  ENTERING(pkcs10_object_set_version);

  if (!PyArg_ParseTuple(args, "|l", &version))
    goto error;

  if (version != 0)
    lose("RFC 6487 6.1.1 forbids non-zero values for this field");

  if (!X509_REQ_set_version(self->pkcs10, version))
    lose("Couldn't set certificate version");

  Py_RETURN_NONE;

 error:

  return NULL;
}

static char pkcs10_object_get_subject__doc__[] =
  "Return this PKCS #10 request's subject name.\n"
  "\n"
  "See the X509.getIssuer() method for details of the return value and\n"
  "use of the optional \"format\" parameter.\n"
  ;

static PyObject *
pkcs10_object_get_subject(pkcs10_object *self, PyObject *args)
{
  PyObject *result = NULL;
  int format = OIDNAME_FORMAT;

  ENTERING(pkcs10_object_get_subject);

  if (!PyArg_ParseTuple(args, "|i", &format))
    goto error;

  result = x509_object_helper_get_name(X509_REQ_get_subject_name(self->pkcs10),
                                       format);

 error:                         /* Fall through */
  return result;
}

static char pkcs10_object_set_subject__doc__[] =
  "Set this PKCS#10 request's subject name.\n"
  "\n"
  "The \"name\" parameter should be in the same format as the return\n"
  "value from the \"getSubject\" method.\n"
  ;

static PyObject *
pkcs10_object_set_subject(pkcs10_object *self, PyObject *args)
{
  PyObject *name_sequence = NULL;
  X509_NAME *name = NULL;

  ENTERING(pkcs10_object_set_subject);

  if (!PyArg_ParseTuple(args, "O", &name_sequence))
    goto error;

  if (!PySequence_Check(name_sequence))
    lose_type_error("Expected a sequence object");

  if ((name = x509_object_helper_set_name(name_sequence)) == NULL)
    goto error;

  if (!X509_REQ_set_subject_name(self->pkcs10, name))
    lose("Unable to set subject name");

  X509_NAME_free(name);

  Py_RETURN_NONE;

 error:
  X509_NAME_free(name);
  return NULL;
}

static char pkcs10_object_get_key_usage__doc__[] =
  EXTENSION_GET_KEY_USAGE__DOC__
  ;

static PyObject *
pkcs10_object_get_key_usage(pkcs10_object *self)
{
  return extension_get_key_usage(pkcs10_object_extension_get_helper(self, NID_key_usage));
}

static char pkcs10_object_set_key_usage__doc__[] =
  "Set the KeyUsage extension for this PKCS#10 request.\n"
  "\n"
  EXTENSION_SET_KEY_USAGE__DOC__
  ;

static PyObject *
pkcs10_object_set_key_usage(pkcs10_object *self, PyObject *args)
{
  return pkcs10_object_extension_set_helper(self, extension_set_key_usage(args));
}

static char pkcs10_object_get_eku__doc__[] =
  EXTENSION_GET_EKU__DOC__
  ;

static PyObject *
pkcs10_object_get_eku(pkcs10_object *self)
{
  return extension_get_eku(pkcs10_object_extension_get_helper(self, NID_ext_key_usage));
}

static char pkcs10_object_set_eku__doc__[] =
  "Set the ExtendedKeyUsage extension for this PKCS #10 request.\n"
  "\n"
  EXTENSION_SET_EKU__DOC__
  ;

static PyObject *
pkcs10_object_set_eku(pkcs10_object *self, PyObject *args)
{
  return pkcs10_object_extension_set_helper(self, extension_set_eku(args));
}

static char pkcs10_object_get_basic_constraints__doc__[] =
  "Return BasicConstraints value for this PKCS#10 request.\n"
  "\n"
  EXTENSION_GET_BASIC_CONSTRAINTS__DOC__
  ;

static PyObject *
pkcs10_object_get_basic_constraints(pkcs10_object *self)
{
  return extension_get_basic_constraints(pkcs10_object_extension_get_helper(self, NID_basic_constraints));
}

static char pkcs10_object_set_basic_constraints__doc__[] =
  "Set BasicConstraints value for this PKCS#10 request.\n"
  "\n"
  EXTENSION_SET_BASIC_CONSTRAINTS__DOC__
  ;

static PyObject *
pkcs10_object_set_basic_constraints(pkcs10_object *self, PyObject *args)
{
  return pkcs10_object_extension_set_helper(self, extension_set_basic_constraints(args));
}

static char pkcs10_object_get_sia__doc__[] =
  "Return the SIA values for this PKCS#10 request.\n"
  "\n"
  EXTENSION_GET_SIA__DOC__
  ;

static PyObject *
pkcs10_object_get_sia(pkcs10_object *self)
{
  return extension_get_sia(pkcs10_object_extension_get_helper(self, NID_sinfo_access));
}

static char pkcs10_object_set_sia__doc__[] =
  "Set SIA values for this PKCS#10 request.\n"
  "\n"
  EXTENSION_SET_SIA__DOC__
  ;

static PyObject *
pkcs10_object_set_sia(pkcs10_object *self, PyObject *args, PyObject *kwds)
{
  return pkcs10_object_extension_set_helper(self, extension_set_sia(args, kwds));
}

static char pkcs10_object_get_signature_algorithm__doc__[] =
  "Return this PKCS #10 reqeuest's signature algorithm OID.\n"
  ;

static PyObject *
pkcs10_object_get_signature_algorithm(pkcs10_object *self)
{
  ASN1_OBJECT *oid = NULL;

  ENTERING(pkcs10_object_get_signature_algorithm);

  X509_ALGOR_get0(&oid, NULL, NULL, self->pkcs10->sig_alg);

  return ASN1_OBJECT_to_PyString(oid);
}

static char pkcs10_object_get_extension_oids__doc__[] =
  "Return the set of extension OIDs used in this request.  This is mostly\n"
  "useful for enforcing restrictions on what extensions are allowed to be\n"
  "present, eg, to conform with the RPKI profile.\n"
  ;

static PyObject *
pkcs10_object_get_extension_oids(pkcs10_object *self)
{
  PyObject *result = NULL;
  PyObject *oid = NULL;
  int i;

  ENTERING(pkcs10_object_get_extension_oids);

  if ((result = PyFrozenSet_New(NULL)) == NULL)
    goto error;

  for (i = 0; i < sk_X509_EXTENSION_num(self->exts); i++) {
    X509_EXTENSION *ext = sk_X509_EXTENSION_value(self->exts, i);
    if ((oid = ASN1_OBJECT_to_PyString(X509_EXTENSION_get_object(ext))) == NULL ||
        PySet_Add(result, oid) < 0)
      goto error;
    Py_XDECREF(oid);
    oid = NULL;
  }

  return result;

 error:
  Py_XDECREF(result);
  Py_XDECREF(oid);
  return NULL;  
}

static char pkcs10_object_pprint__doc__[] =
  "Return a pretty-printed rendition of this PKCS#10 request.\n"
  ;

static PyObject *
pkcs10_object_pprint(pkcs10_object *self)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  ENTERING(pkcs10_object_pprint);

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  if (!X509_REQ_print(bio, self->pkcs10))
    lose_openssl_error("Unable to pretty-print PKCS#10 request");

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static struct PyMethodDef pkcs10_object_methods[] = {
  Define_Method(pemWrite,               pkcs10_object_pem_write,                METH_NOARGS),
  Define_Method(derWrite,               pkcs10_object_der_write,                METH_NOARGS),
  Define_Method(sign,                   pkcs10_object_sign,                     METH_VARARGS),
  Define_Method(verify,                 pkcs10_object_verify,                   METH_NOARGS),
  Define_Method(getPublicKey,           pkcs10_object_get_public_key,           METH_NOARGS),
  Define_Method(setPublicKey,           pkcs10_object_set_public_key,           METH_VARARGS),
  Define_Method(getVersion,             pkcs10_object_get_version,              METH_NOARGS),
  Define_Method(setVersion,             pkcs10_object_set_version,              METH_VARARGS),
  Define_Method(getSubject,             pkcs10_object_get_subject,              METH_VARARGS),
  Define_Method(setSubject,             pkcs10_object_set_subject,              METH_VARARGS),
  Define_Method(pprint,                 pkcs10_object_pprint,                   METH_NOARGS),
  Define_Method(getKeyUsage,            pkcs10_object_get_key_usage,            METH_NOARGS),
  Define_Method(setKeyUsage,            pkcs10_object_set_key_usage,            METH_VARARGS),
  Define_Method(getEKU,                 pkcs10_object_get_eku,                  METH_NOARGS),
  Define_Method(setEKU,                 pkcs10_object_set_eku,                  METH_VARARGS),
  Define_Method(getBasicConstraints,    pkcs10_object_get_basic_constraints,    METH_NOARGS),
  Define_Method(setBasicConstraints,    pkcs10_object_set_basic_constraints,    METH_VARARGS),
  Define_Method(getSIA,                 pkcs10_object_get_sia,                  METH_NOARGS),
  Define_Method(setSIA,                 pkcs10_object_set_sia,                  METH_KEYWORDS),
  Define_Method(getSignatureAlgorithm,  pkcs10_object_get_signature_algorithm,  METH_NOARGS),
  Define_Method(getExtensionOIDs,       pkcs10_object_get_extension_oids,       METH_NOARGS),
  Define_Class_Method(pemRead,          pkcs10_object_pem_read,                 METH_VARARGS),
  Define_Class_Method(pemReadFile,      pkcs10_object_pem_read_file,            METH_VARARGS),
  Define_Class_Method(derRead,          pkcs10_object_der_read,                 METH_VARARGS),
  Define_Class_Method(derReadFile,      pkcs10_object_der_read_file,            METH_VARARGS),
  {NULL}
};

static char POW_PKCS10_Type__doc__[] =
  "This class represents a PKCS#10 request.\n"
  ;

static PyTypeObject POW_PKCS10_Type = {
  PyObject_HEAD_INIT(0)
  0,                                        /* ob_size */
  "rpki.POW.PKCS10",                        /* tp_name */
  sizeof(pkcs10_object),                    /* tp_basicsize */
  0,                                        /* tp_itemsize */
  (destructor)pkcs10_object_dealloc,        /* tp_dealloc */
  0,                                        /* tp_print */
  0,                                        /* tp_getattr */
  0,                                        /* tp_setattr */
  0,                                        /* tp_compare */
  0,                                        /* tp_repr */
  0,                                        /* tp_as_number */
  0,                                        /* tp_as_sequence */
  0,                                        /* tp_as_mapping */
  0,                                        /* tp_hash */
  0,                                        /* tp_call */
  0,                                        /* tp_str */
  0,                                        /* tp_getattro */
  0,                                        /* tp_setattro */
  0,                                        /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /* tp_flags */
  POW_PKCS10_Type__doc__,                   /* tp_doc */
  0,                                        /* tp_traverse */
  0,                                        /* tp_clear */
  0,                                        /* tp_richcompare */
  0,                                        /* tp_weaklistoffset */
  0,                                        /* tp_iter */
  0,                                        /* tp_iternext */
  pkcs10_object_methods,                    /* tp_methods */
  0,                                        /* tp_members */
  0,                                        /* tp_getset */
  0,                                        /* tp_base */
  0,                                        /* tp_dict */
  0,                                        /* tp_descr_get */
  0,                                        /* tp_descr_set */
  0,                                        /* tp_dictoffset */
  0,                                        /* tp_init */
  0,                                        /* tp_alloc */
  pkcs10_object_new,                        /* tp_new */
};



/*
 * Module functions.
 */

static char pow_module_add_object__doc__[] =
  "Add new a new object identifier to OpenSSL's internal database.\n"
  "\n"
  "The \"oid\" should be an ASN.1 object identifer, represented as a string\n"
  "in dotted-decimal format.\n"
  "\n"
  "The \"shortName\" parameter should be the OpenSSL \"short name\" to use.\n"
  "\n"
  "The \"longName\" parameter should be the OpenSSL \"long name\" to use.\n"
  ;

static PyObject *
pow_module_add_object(GCC_UNUSED PyObject *self, PyObject *args)
{
  char *oid = NULL, *sn = NULL, *ln = NULL;

  ENTERING(pow_module_add_object);

  if (!PyArg_ParseTuple(args, "sss", &oid, &sn, &ln))
    goto error;

  if (!OBJ_create(oid, sn, ln))
    lose_openssl_error("Unable to add object");

  Py_RETURN_NONE;

 error:

  return NULL;
}

static char pow_module_get_error__doc__[] =
  "Pop one error off OpenSSL's global error stack and returns it as a string.\n"
  "\n"
  "Returns None if the error stack is empty.\n"
  ;

static PyObject *
pow_module_get_error(GCC_UNUSED PyObject *self)
{
  unsigned long error = ERR_get_error();
  char buf[256];

  ENTERING(pow_module_get_error);

  if (!error)
    Py_RETURN_NONE;

  ERR_error_string_n(error, buf, sizeof(buf));
  return Py_BuildValue("s", buf);
}

static char pow_module_clear_error__doc__[] =
  "Remove all errors from OpenSSL's global error stack.\n"
  ;

static PyObject *
pow_module_clear_error(GCC_UNUSED PyObject *self)
{
  ENTERING(pow_module_clear_error);
  ERR_clear_error();
  Py_RETURN_NONE;
}

static char pow_module_get_verification_errors__doc__[] =
  "Return strings for known OpenSSL certificate verification errors.\n"
  "Returns a list of (number, symbol, text) tuples.\n"
  ;

static PyObject *
pow_module_get_verification_errors(GCC_UNUSED PyObject *self)
{
  PyObject *result = NULL, *item = NULL;

  ENTERING(pow_module_get_verification_errors);

  /*
   * This function is only called once, and doesn't need to be
   * particularly efficient, so we use a list to keep the code simple.
   */

  if ((result = PyList_New(0)) == NULL)
    goto error;

#define Verification_Error(_v_)                                         \
  do {                                                                  \
    const char *msg = X509_verify_cert_error_string(_v_);               \
    if ((item = Py_BuildValue("(iss)", _v_, #_v_, msg)) == NULL ||      \
        PyList_Append(result, item) < 0)                                \
      goto error;                                                       \
    Py_XDECREF(item);                                                   \
    item = NULL;                                                        \
  } while (0)

  Verification_Error( X509_V_OK );
  Verification_Error( X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT );
  Verification_Error( X509_V_ERR_UNABLE_TO_GET_CRL );
  Verification_Error( X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE );
  Verification_Error( X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE );
  Verification_Error( X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY );
  Verification_Error( X509_V_ERR_CERT_SIGNATURE_FAILURE );
  Verification_Error( X509_V_ERR_CRL_SIGNATURE_FAILURE );
  Verification_Error( X509_V_ERR_CERT_NOT_YET_VALID );
  Verification_Error( X509_V_ERR_CERT_HAS_EXPIRED );
  Verification_Error( X509_V_ERR_CRL_NOT_YET_VALID );
  Verification_Error( X509_V_ERR_CRL_HAS_EXPIRED );
  Verification_Error( X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD );
  Verification_Error( X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD );
  Verification_Error( X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD );
  Verification_Error( X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD );
  Verification_Error( X509_V_ERR_OUT_OF_MEM );
  Verification_Error( X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT );
  Verification_Error( X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN );
  Verification_Error( X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY );
  Verification_Error( X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE );
  Verification_Error( X509_V_ERR_CERT_CHAIN_TOO_LONG );
  Verification_Error( X509_V_ERR_CERT_REVOKED );
  Verification_Error( X509_V_ERR_INVALID_CA );
  Verification_Error( X509_V_ERR_PATH_LENGTH_EXCEEDED );
  Verification_Error( X509_V_ERR_INVALID_PURPOSE );
  Verification_Error( X509_V_ERR_CERT_UNTRUSTED );
  Verification_Error( X509_V_ERR_CERT_REJECTED );
  Verification_Error( X509_V_ERR_SUBJECT_ISSUER_MISMATCH );
  Verification_Error( X509_V_ERR_AKID_SKID_MISMATCH );
  Verification_Error( X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH );
  Verification_Error( X509_V_ERR_KEYUSAGE_NO_CERTSIGN );
  Verification_Error( X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER );
  Verification_Error( X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION );
  Verification_Error( X509_V_ERR_KEYUSAGE_NO_CRL_SIGN );
  Verification_Error( X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION );
  Verification_Error( X509_V_ERR_INVALID_NON_CA );
  Verification_Error( X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED );
  Verification_Error( X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE );
  Verification_Error( X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED );
  Verification_Error( X509_V_ERR_INVALID_EXTENSION );
  Verification_Error( X509_V_ERR_INVALID_POLICY_EXTENSION );
  Verification_Error( X509_V_ERR_NO_EXPLICIT_POLICY );
  Verification_Error( X509_V_ERR_DIFFERENT_CRL_SCOPE );
  Verification_Error( X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE );
  Verification_Error( X509_V_ERR_UNNESTED_RESOURCE );
  Verification_Error( X509_V_ERR_PERMITTED_VIOLATION );
  Verification_Error( X509_V_ERR_EXCLUDED_VIOLATION );
  Verification_Error( X509_V_ERR_SUBTREE_MINMAX );
  Verification_Error( X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE );
  Verification_Error( X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX );
  Verification_Error( X509_V_ERR_UNSUPPORTED_NAME_SYNTAX );
  Verification_Error( X509_V_ERR_CRL_PATH_VALIDATION_ERROR );
#ifdef X509_V_ERR_SUITE_B_INVALID_VERSION
  Verification_Error( X509_V_ERR_SUITE_B_INVALID_VERSION );
#endif
#ifdef X509_V_ERR_SUITE_B_INVALID_ALGORITHM
  Verification_Error( X509_V_ERR_SUITE_B_INVALID_ALGORITHM );
#endif
#ifdef X509_V_ERR_SUITE_B_INVALID_CURVE
  Verification_Error( X509_V_ERR_SUITE_B_INVALID_CURVE );
#endif
#ifdef X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM
  Verification_Error( X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM );
#endif
#ifdef X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED
  Verification_Error( X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED );
#endif
#ifdef X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256
  Verification_Error( X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256 );
#endif
#ifdef X509_V_ERR_HOSTNAME_MISMATCH
  Verification_Error( X509_V_ERR_HOSTNAME_MISMATCH );
#endif
#ifdef X509_V_ERR_EMAIL_MISMATCH
  Verification_Error( X509_V_ERR_EMAIL_MISMATCH );
#endif
#ifdef X509_V_ERR_IP_ADDRESS_MISMATCH
  Verification_Error( X509_V_ERR_IP_ADDRESS_MISMATCH );
#endif
  Verification_Error( X509_V_ERR_APPLICATION_VERIFICATION );

#undef Verification_Error

  return result;

 error:
  Py_XDECREF(result);
  Py_XDECREF(item);
  return NULL;
}

static char pow_module_seed__doc__[] =
  "Add data to OpenSSL's pseudo-random number generator state.\n"
  "\n"
  "The \"data\" parameter is the seed to add.  Entropy of the data is\n"
  "assumed to be equal to the length of the data.\n"
  ;

static PyObject *
pow_module_seed(GCC_UNUSED PyObject *self, PyObject *args)
{
  char *data = NULL;
  Py_ssize_t datalen = 0;

  ENTERING(pow_module_seed);

  if (!PyArg_ParseTuple(args, "s#", &data, &datalen))
    goto error;

  RAND_seed(data, datalen);

  Py_RETURN_NONE;

 error:

  return NULL;
}

static char pow_module_add__doc__[] =
  "Add data to OpenSSL's pseudo-random number generator state.\n"
  "\n"
  "The \"data\" parameter is the data to add.\n"
  "\n"
  "The \"entropy\" parameter should be an estimate of the number of\n"
  "random bytes in the data parameter.\n"
  ;

static PyObject *
pow_module_add(GCC_UNUSED PyObject *self, PyObject *args)
{
  char *data = NULL;
  Py_ssize_t datalen = 0;
  double entropy = 0;

  ENTERING(pow_module_add);

  if (!PyArg_ParseTuple(args, "s#d", &data, &datalen, &entropy))
    goto error;

  RAND_add(data, datalen, entropy);

  Py_RETURN_NONE;

 error:
  return NULL;
}

static char pow_module_write_random_file__doc__[] =
  "Write the current state of OpenSSL's pseduo-random number generator to\n"
  "a file.\n"
  "\n"
  "The \"filename\" parameter is the name of the file to write.\n"
  ;

static PyObject *
pow_module_write_random_file(GCC_UNUSED PyObject *self, PyObject *args)
{
  char *filename = NULL;

  ENTERING(pow_module_write_random_file);

  if (!PyArg_ParseTuple(args, "s", &filename))
    goto error;

  if (RAND_write_file(filename) == -1)
    lose("Couldn't write random file");

  Py_RETURN_NONE;

 error:
  return NULL;
}

static char pow_module_read_random_file__doc__[] =
  "Restore the state of OpenSSLs pseudo-random number generator from\n"
  "data previously saved to a file.\n"
  "\n"
  "The \"filename\" parameter is the name of the file to read.\n"
  ;

static PyObject *
pow_module_read_random_file(GCC_UNUSED PyObject *self, PyObject *args)
{
  char *file = NULL;
  int len = -1;

  ENTERING(pow_module_read_random_file);

  if (!PyArg_ParseTuple(args, "s|i", &file, &len))
    goto error;

  if (!RAND_load_file(file, len))
    lose("Couldn't load random file");

  Py_RETURN_NONE;

 error:
  return NULL;
}

static char pow_module_custom_datetime__doc__[] =
  "Set constructor callback for customized datetime class.\n"
  ;

static PyObject *
pow_module_custom_datetime(GCC_UNUSED PyObject *self, PyObject *args)
{
  PyObject *cb = NULL;

  ENTERING(pow_module_custom_datetime);

  if (!PyArg_ParseTuple(args, "O", &cb))
    goto error;

  Py_XINCREF(cb);
  Py_XDECREF(custom_datetime);
  custom_datetime = cb;

  Py_RETURN_NONE;

 error:
  return NULL;
}


static struct PyMethodDef pow_module_methods[] = {
  Define_Method(getError,               pow_module_get_error,                   METH_NOARGS),
  Define_Method(clearError,             pow_module_clear_error,                 METH_NOARGS),
  Define_Method(getVerificationErrors,  pow_module_get_verification_errors,     METH_NOARGS),
  Define_Method(seed,                   pow_module_seed,                        METH_VARARGS),
  Define_Method(add,                    pow_module_add,                 	METH_VARARGS),
  Define_Method(readRandomFile,         pow_module_read_random_file,            METH_VARARGS),
  Define_Method(writeRandomFile,        pow_module_write_random_file,           METH_VARARGS),
  Define_Method(addObject,              pow_module_add_object,                  METH_VARARGS),
  Define_Method(customDatetime,         pow_module_custom_datetime,             METH_VARARGS),
  {NULL}
};



/*
 * Module initialization.
 */

void
init_POW(void)
{
  PyObject *m = Py_InitModule3("_POW", pow_module_methods, pow_module__doc__);
  int OpenSSL_ok = 1;

  /*
   * Python encourages us to use these functions instead of the ones
   * in libc, and OpenSSL allows us to do this.  The result seems to
   * work, and, in theory, gives Python's memory allocator a better
   * idea of how much memory we're really using.  Not sure why it
   * cares, but let's try to be nice about it.
   *
   * Note that this must be done BEFORE anything in OpenSSL uses
   * dynamic memory, and that this will probably fail in horrible ways
   * without the build-time code (-Bsymbolic, etc) which isolates our
   * copy of the OpenSSL code from any system shared libraries.
   * Enough other things already fail in horrible ways without that
   * isolation that adding one more doesn't make much difference, but
   * if you tinker with the build script and start seeing nasty
   * memory-related issues, this might be the cause.
   */
  CRYPTO_set_mem_functions(PyMem_Malloc, PyMem_Realloc, PyMem_Free);

  /*
   * Import the DateTime API
   */

  PyDateTime_IMPORT;

#define Define_Class(__type__)                                          \
  do {                                                                  \
    char *__name__ = strrchr(__type__.tp_name, '.');                    \
    if (PyType_Ready(&__type__) == 0 && __name__ != NULL) {             \
      Py_INCREF(&__type__);                                             \
      PyModule_AddObject(m, __name__+1, (PyObject *) &__type__);        \
    }                                                                   \
  } while (0)

  Define_Class(POW_X509_Type);
  Define_Class(POW_X509StoreCTX_Type);
  Define_Class(POW_CRL_Type);
  Define_Class(POW_Asymmetric_Type);
  Define_Class(POW_AsymmetricParams_Type);
  Define_Class(POW_Digest_Type);
  Define_Class(POW_CMS_Type);
  Define_Class(POW_IPAddress_Type);
  Define_Class(POW_Manifest_Type);
  Define_Class(POW_ROA_Type);
  Define_Class(POW_PKCS10_Type);

#undef Define_Class

#define Define_Exception(__name__, __parent__)                          \
  PyModule_AddObject(m, #__name__, ((__name__##Object)                  \
    = PyErr_NewException("rpki.POW." #__name__, __parent__, NULL)))

  Define_Exception(Error,               NULL);
  Define_Exception(OpenSSLError,        ErrorObject);
  Define_Exception(POWError,            ErrorObject);
  Define_Exception(NotVerifiedError,    ErrorObject);
  Define_Exception(ValidationError,     ErrorObject);

#undef Define_Exception

#define Define_Integer_Constant(__name__) \
  PyModule_AddIntConstant(m, #__name__, __name__)

  /* Object format types */
  Define_Integer_Constant(LONGNAME_FORMAT);
  Define_Integer_Constant(SHORTNAME_FORMAT);
  Define_Integer_Constant(OIDNAME_FORMAT);

  /* Message digests */
  Define_Integer_Constant(SHA1_DIGEST);
  Define_Integer_Constant(SHA256_DIGEST);
  Define_Integer_Constant(SHA384_DIGEST);
  Define_Integer_Constant(SHA512_DIGEST);

  /* CMS flags */
  Define_Integer_Constant(CMS_NOCERTS);
  Define_Integer_Constant(CMS_NOATTR);
  Define_Integer_Constant(CMS_NOINTERN);
  Define_Integer_Constant(CMS_NOCRL);
  Define_Integer_Constant(CMS_NO_SIGNER_CERT_VERIFY);
  Define_Integer_Constant(CMS_NO_ATTR_VERIFY);
  Define_Integer_Constant(CMS_NO_CONTENT_VERIFY);

  /* X509 validation flags */
  Define_Integer_Constant(X509_V_FLAG_CB_ISSUER_CHECK);
  Define_Integer_Constant(X509_V_FLAG_USE_CHECK_TIME);
  Define_Integer_Constant(X509_V_FLAG_CRL_CHECK);
  Define_Integer_Constant(X509_V_FLAG_CRL_CHECK_ALL);
  Define_Integer_Constant(X509_V_FLAG_IGNORE_CRITICAL);
  Define_Integer_Constant(X509_V_FLAG_X509_STRICT);
  Define_Integer_Constant(X509_V_FLAG_ALLOW_PROXY_CERTS);
  Define_Integer_Constant(X509_V_FLAG_POLICY_CHECK);
  Define_Integer_Constant(X509_V_FLAG_EXPLICIT_POLICY);
  Define_Integer_Constant(X509_V_FLAG_INHIBIT_ANY);
  Define_Integer_Constant(X509_V_FLAG_INHIBIT_MAP);
  Define_Integer_Constant(X509_V_FLAG_NOTIFY_POLICY);
  Define_Integer_Constant(X509_V_FLAG_CHECK_SS_SIGNATURE);
  
  /* X509 validation error codes */
  Define_Integer_Constant(X509_V_OK);
  Define_Integer_Constant(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT);
  Define_Integer_Constant(X509_V_ERR_UNABLE_TO_GET_CRL);
  Define_Integer_Constant(X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE);
  Define_Integer_Constant(X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE);
  Define_Integer_Constant(X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY);
  Define_Integer_Constant(X509_V_ERR_CERT_SIGNATURE_FAILURE);
  Define_Integer_Constant(X509_V_ERR_CRL_SIGNATURE_FAILURE);
  Define_Integer_Constant(X509_V_ERR_CERT_NOT_YET_VALID);
  Define_Integer_Constant(X509_V_ERR_CERT_HAS_EXPIRED);
  Define_Integer_Constant(X509_V_ERR_CRL_NOT_YET_VALID);
  Define_Integer_Constant(X509_V_ERR_CRL_HAS_EXPIRED);
  Define_Integer_Constant(X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD);
  Define_Integer_Constant(X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD);
  Define_Integer_Constant(X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD);
  Define_Integer_Constant(X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD);
  Define_Integer_Constant(X509_V_ERR_OUT_OF_MEM);
  Define_Integer_Constant(X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT);
  Define_Integer_Constant(X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN);
  Define_Integer_Constant(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY);
  Define_Integer_Constant(X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE);
  Define_Integer_Constant(X509_V_ERR_CERT_CHAIN_TOO_LONG);
  Define_Integer_Constant(X509_V_ERR_CERT_REVOKED);
  Define_Integer_Constant(X509_V_ERR_INVALID_CA);
  Define_Integer_Constant(X509_V_ERR_PATH_LENGTH_EXCEEDED);
  Define_Integer_Constant(X509_V_ERR_INVALID_PURPOSE);
  Define_Integer_Constant(X509_V_ERR_CERT_UNTRUSTED);
  Define_Integer_Constant(X509_V_ERR_CERT_REJECTED);
  Define_Integer_Constant(X509_V_ERR_SUBJECT_ISSUER_MISMATCH);
  Define_Integer_Constant(X509_V_ERR_AKID_SKID_MISMATCH);
  Define_Integer_Constant(X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH);
  Define_Integer_Constant(X509_V_ERR_KEYUSAGE_NO_CERTSIGN);
  Define_Integer_Constant(X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER);
  Define_Integer_Constant(X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION);
  Define_Integer_Constant(X509_V_ERR_KEYUSAGE_NO_CRL_SIGN);
  Define_Integer_Constant(X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION);
  Define_Integer_Constant(X509_V_ERR_INVALID_NON_CA);
  Define_Integer_Constant(X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED);
  Define_Integer_Constant(X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE);
  Define_Integer_Constant(X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED);
  Define_Integer_Constant(X509_V_ERR_INVALID_EXTENSION);
  Define_Integer_Constant(X509_V_ERR_INVALID_POLICY_EXTENSION);
  Define_Integer_Constant(X509_V_ERR_NO_EXPLICIT_POLICY);
  Define_Integer_Constant(X509_V_ERR_UNNESTED_RESOURCE);
  Define_Integer_Constant(X509_V_ERR_APPLICATION_VERIFICATION);

  /* AsymmetricParam EC curve codes */
  Define_Integer_Constant(EC_P256_CURVE);

#undef Define_Integer_Constant

  /*
   * Initialise library.
   *
   * We shouldn't need any of the SSL code or error strings anymore.
   *
   * If we cared deeply about avoiding references to symmetric cipher
   * algorithms and digest algorithms we're not using, we could
   * replace the call to OpenSSL_add_all_algorithms() with calls to
   * add just the specific algorithms we use rather than all of them.
   * For now, don't worry about it.
   */

  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  OpenSSL_ok &= create_missing_nids();

  x509_store_ctx_ex_data_idx = X509_STORE_CTX_get_ex_new_index(0, "x590_store_ctx_object for verify callback",
                                                               NULL, NULL, NULL);

  asn1_zero          = s2i_ASN1_INTEGER(NULL, "0x0");
  asn1_four_octets   = s2i_ASN1_INTEGER(NULL, "0xFFFFFFFF");
  asn1_twenty_octets = s2i_ASN1_INTEGER(NULL, "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF");

  if (PyErr_Occurred() || !OpenSSL_ok)
    Py_FatalError("Can't initialize module POW");
}

/*
 * Local Variables:
 * indent-tabs-mode: nil
 * End:
 */
