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
 ****
 *
 * Portions copyright (C) 2006--2008 American Registry for Internet
 * Numbers ("ARIN")
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

/* $Id: rcynic.c 4613 2012-07-30 23:24:15Z sra $ */

/*
 * Disable compilation of X509 certificate signature and verification
 * API.  We don't currently need this for RPKI but I'm not quite ready
 * to rip it out yet.  The current API has issues which I'd rather
 * defer until I decide whether we need to fix it, so just omit the
 * code for now.
 */
#define ENABLE_X509_CERTIFICATE_SIGNATURE_AND_VERIFICATION      0

#include <Python.h>

#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/cms.h>

#include <rpki/roa.h>
#include <rpki/manifest.h>

#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/*
 * Maximum size of a raw IP (v4 or v6) address, in bytes.
 */
#define RAW_IPADDR_BUFLEN    16

/*
 * Maximum size of an ASN.1 Integer converted from a Python Long, in bytes.
 */
#define MAX_ASN1_INTEGER_LEN    20

/* Asymmetric ciphers */
#define RSA_CIPHER            1

/* Digests */
#define MD5_DIGEST            2
#define SHA_DIGEST            3
#define SHA1_DIGEST           4
#define SHA256_DIGEST         6
#define SHA384_DIGEST         7
#define SHA512_DIGEST         8

/* Object format */
#define SHORTNAME_FORMAT      1
#define LONGNAME_FORMAT       2
#define OIDNAME_FORMAT        3

/* Output format */
#define PEM_FORMAT            1
#define DER_FORMAT            2

/* Object check functions */
#define POW_X509_Check(op)              PyObject_TypeCheck(op, &POW_X509_Type)
#define POW_X509Store_Check(op)         PyObject_TypeCheck(op, &POW_X509Store_Type)
#define POW_CRL_Check(op)               PyObject_TypeCheck(op, &POW_CRL_Type)
#define POW_Asymmetric_Check(op)        PyObject_TypeCheck(op, &POW_Asymmetric_Type)
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
  "needed for RPKI.\n"
  ;

#define LAME_DISCLAIMER_IN_ALL_CLASS_DOCUMENTATION \
  "The documentation for this class used to provide a nice example of how\n" \
  "to use the class.  Sadly, most of what was in that example is now\n" \
  "obsolete due to recent or impending API changes.  Once the new API is\n" \
  "stable, this documentation should be rewritten to provide such examples.\n"

/*
 * Handle NIDs we wish OpenSSL knew about.  This is carefully (we
 * hope) written to do nothing at all for any NID that OpenSSL knows
 * about; the intent is just to add definitions for things OpenSSL
 * doesn't know about yet.  Of necessity, this is a bit gross, since
 * it confounds runtime static variables with predefined macro names,
 * but we try to put all the magic associated with this in one place.
 */

#ifndef NID_rpkiManifest
static int NID_rpkiManifest;
#endif

#ifndef NID_signedObject
static int NID_signedObject;
#endif

static const struct {
  int *nid;
  const char *oid;
  const char *sn;
  const char *ln;
} missing_nids[] = {

#ifndef NID_rpkiManifest
  {&NID_rpkiManifest, "1.3.6.1.5.5.7.48.10", "id-ad-rpkiManifest", "RPKI Manifest"},
#endif

#ifndef NID_signedObject
  {&NID_signedObject, "1.3.6.1.5.5.7.48.11", "id-ad-signedObject", "Signed Object"}
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
 * Exception objects.
 */

static PyObject
  *ErrorObject,
  *OpenSSLErrorObject,
  *POWErrorObject,
  *NotVerifiedErrorObject;

/*
 * Declarations of type objects (definitions come later).
 */

static PyTypeObject
  POW_X509_Type,
  POW_X509Store_Type,
  POW_CRL_Type,
  POW_Asymmetric_Type,
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
  X509_STORE *store;
} x509_store_object;

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
  STACK_OF(X509_EXTENSION) *exts;
} pkcs10_object;



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

#define lose_openssl_error(_msg_)                                       \
  do {                                                                  \
    set_openssl_exception(OpenSSLErrorObject, (_msg_));                 \
    goto error;                                                         \
  } while (0)

#define lose_not_verified(_msg_)                                        \
  do {                                                                  \
    PyErr_SetString(NotVerifiedErrorObject, (_msg_));                   \
    goto error;                                                         \
  } while (0)

#define assert_no_unhandled_openssl_errors()                            \
  do {                                                                  \
    if (ERR_peek_error())                                               \
      lose_openssl_error(assert_helper(__LINE__));                      \
  } while (0)

static char *
assert_helper(int line)
{
  static const char fmt[] = "Unhandled OpenSSL error at " __FILE__ ":%d!";
  static char msg[sizeof(fmt) + 10];

  snprintf(msg, sizeof(msg), fmt, line);
  return msg;
}

/*
 * Consolidate some tedious EVP-related switch statements.
 */

static const EVP_MD *
evp_digest_factory(int digest_type)
{
  switch (digest_type) {
  case MD5_DIGEST:      return EVP_md5();
  case SHA_DIGEST:      return EVP_sha();
  case SHA1_DIGEST:     return EVP_sha1();
  case SHA256_DIGEST:   return EVP_sha256();
  case SHA384_DIGEST:   return EVP_sha384();
  case SHA512_DIGEST:   return EVP_sha512();
  default:              return NULL;
  }
}

/*
 * Raise an exception with data pulled from the OpenSSL error stack.
 * Exception value is a tuple with some internal structure.  If a
 * string error message is supplied, that string is the first element
 * of the exception value tuple.  Remainder of exception value tuple
 * is zero or more tuples, each representing one error from the stack.
 * Each error tuple contains six slots:
 * - the numeric error code
 * - string translation of numeric error code ("reason")
 * - name of library in which error occurred
 * - name of function in which error occurred
 * - name of file in which error occurred
 * - line number in file where error occurred
 */

static void
set_openssl_exception(PyObject *error_class, const char *msg)
{
  PyObject *errors;
  unsigned long err;
  const char *file;
  int line;

  errors = PyList_New(0);

  if (msg) {
    PyObject *s = Py_BuildValue("s", msg);
    (void) PyList_Append(errors, s);
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
    (void) PyList_Append(errors, t);
    Py_XDECREF(t);
  }

  PyErr_SetObject(error_class, PyList_AsTuple(errors));
  Py_XDECREF(errors);
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
      lose_type_error("each RDN must be a sequence with at least one element");

    for (j = 0; j < PySequence_Size(rdn_obj); j++) {

      if ((pair_obj = PySequence_GetItem(rdn_obj, j)) == NULL)
        goto error;

      if (!PySequence_Check(pair_obj) || PySequence_Size(pair_obj) != 2)
        lose_type_error("each name entry must be a two-element sequence");

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
  X509_NAME_ENTRY *entry = NULL;
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

    if ((entry = X509_NAME_get_entry(name, i)) == NULL)
      lose("Couldn't get certificate name");

    if (entry->set < 0 || entry->set < set || entry->set > set + 1)
      lose("X509_NAME->set value out of expected range");

    switch (format) {
    case SHORTNAME_FORMAT:
      oid = OBJ_nid2sn(OBJ_obj2nid(entry->object));
      break;
    case LONGNAME_FORMAT:
      oid = OBJ_nid2ln(OBJ_obj2nid(entry->object));
      break;
    case OIDNAME_FORMAT:
      oid = NULL;
      break;
    default:
      lose("Unknown name format");
    }

    if (oid == NULL) {
      if (OBJ_obj2txt(oidbuf, sizeof(oidbuf), entry->object, 1) <= 0)
        lose_openssl_error("Couldn't translate OID");
      oid = oidbuf;
    }

    if (entry->set > set) {

      set++;
      if ((item = Py_BuildValue("((ss#))", oid,
                                ASN1_STRING_data(entry->value),
                                ASN1_STRING_length(entry->value))) == NULL)
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
      if ((item = Py_BuildValue("(ss#)", oid,
                                ASN1_STRING_data(entry->value),
                                ASN1_STRING_length(entry->value))) == NULL)
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
x509_helper_sequence_to_stack(PyObject *x509_sequence)
{
  x509_object *x509obj = NULL;
  STACK_OF(X509) *x509_stack = NULL;
  int size = 0, i = 0;

  if (x509_sequence != Py_None && !PySequence_Check(x509_sequence))
    lose_type_error("Inapropriate type");

  if ((x509_stack = sk_X509_new_null()) == NULL)
    lose_no_memory();

  if (x509_sequence != Py_None) {
    size = PySequence_Size(x509_sequence);

    for (i = 0; i < size; i++) {
      if ((x509obj = (x509_object*) PySequence_GetItem(x509_sequence, i)) == NULL)
        goto error;

      if (!POW_X509_Check(x509obj))
        lose_type_error("Inapropriate type");

      if (!sk_X509_push(x509_stack, x509obj->x509))
        lose("Couldn't add X509 object to stack");

      Py_XDECREF(x509obj);
      x509obj = NULL;
    }
  }

  return x509_stack;

 error:
  sk_X509_free(x509_stack);
  Py_XDECREF(x509obj);
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

/*
 * Time conversion functions.  These follow RFC 5280, but use a single
 * text encoding that looks like GeneralizedTime as restricted by RFC
 * 5280; conversion to and from UTCTime is handled internally
 * according to the RFC 5280 rules.  The intent is to hide the
 * horrible short-sighted mess from Python code entirely.
 */

static PyObject *
ASN1_TIME_to_Python(ASN1_TIME *t)
{
  ASN1_GENERALIZEDTIME *g = NULL;
  PyObject *result = NULL;

  if ((g = ASN1_TIME_to_generalizedtime(t, NULL)) == NULL)
    lose_openssl_error("Couldn't convert ASN.1 TIME");

  result = Py_BuildValue("s", g->data);
  
 error:
  ASN1_GENERALIZEDTIME_free(g);
  return result;
}

static ASN1_TIME *
Python_to_ASN1_TIME(const char *s, const int object_requires_utctime)
{
  ASN1_TIME *result = NULL;
  int ok;
  
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
  int len = 0;

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
  int len = 0;

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
      (a->length < len + 1 && (a->data = OPENSSL_realloc(a->data, len + 1)) == NULL))
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

  for (i = 0; i < sizeof(missing_nids) / sizeof(*missing_nids); i++)
    if ((*missing_nids[i].nid = OBJ_txt2nid(missing_nids[i].oid)) == NID_undef &&
        (*missing_nids[i].nid = OBJ_create(missing_nids[i].oid,
                                           missing_nids[i].sn,
                                           missing_nids[i].ln)) == NID_undef)
      return 0;

  return 1;
}

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

  for (v = 0; v < sizeof(ipaddress_versions)/sizeof(*ipaddress_versions); v++)
    if (version == ipaddress_versions[v]->version)
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

  for (i = 0; i < self->type->length; i++)
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
  size_t len;
  int v;

  ENTERING(ipaddress_object_from_bytes);

  if (!PyArg_ParseTuple(args, "s#", &bytes, &len))
    goto error;

  if ((result = (ipaddress_object *) type->tp_alloc(type, 0)) == NULL)
    goto error;

  result->type = NULL;

  for (v = 0; v < sizeof(ipaddress_versions)/sizeof(*ipaddress_versions); v++)
    if (len == ipaddress_versions[v]->length)
      result->type = ipaddress_versions[v];

  if (result->type == NULL)
    lose("Unknown IP version number");

  memcpy(result->address, bytes, len);

 error:
  return (PyObject *) result;
}

static char ipaddress_object_to_bytes__doc__[] =
  "Returns a Python string of exactly 4 or 16 bytes representing\n"
  "the binary value of this IPAddress.\n"
  ;

static PyObject *
ipaddress_object_to_bytes(ipaddress_object *self)
{
  ENTERING(ipaddress_object_from_bytes);
  return PyString_FromStringAndSize(self->address, self->type->length);
}

static PyObject *
ipaddress_object_get_bits(ipaddress_object *self, void *closure)
{
  ENTERING(ipaddress_object_get_bits);
  return PyInt_FromLong(self->type->length * 8);
}

static PyObject *
ipaddress_object_get_version(ipaddress_object *self, void *closure)
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
    return Py_NotImplemented;

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

  for (i = 0; i < self->type->length; i++)
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

  for (i = 0; i < self->type->length; i++)
    result->address[i] = ~self->address[i];

 error:                         /* Fall through */
  return (PyObject *) result;
}

static struct PyMethodDef ipaddress_object_methods[] = {
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

static PyObject *
x509_object_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  x509_object *self;

  ENTERING(x509_object_new);

  if ((self = (x509_object *) type->tp_alloc(type, 0)) != NULL &&
      (self->x509 = X509_new()) != NULL)
    return (PyObject *) self;

  Py_XDECREF(self);
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
  "Class method to read a PEM-encoded X.509 object from a string.\n"
  ;

static PyObject *
x509_object_pem_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(x509_object_pem_read);
  return read_from_string_helper(x509_object_pem_read_helper, type, args);
}

static char x509_object_pem_read_file__doc__[] =
  "Class method to read a PEM-encoded X.509 object from a file.\n"
  ;

static PyObject *
x509_object_pem_read_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(x509_object_pem_read_file);
  return read_from_file_helper(x509_object_pem_read_helper, type, args);
}

static char x509_object_der_read__doc__[] =
  "Class method to read a DER-encoded X.509 object from a string.\n"
  ;

static PyObject *
x509_object_der_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(x509_object_der_read);
  return read_from_string_helper(x509_object_der_read_helper, type, args);
}

static char x509_object_der_read_file__doc__[] =
  "Class method to read a DER-encoded X.509 object from a file.\n"
  ;

static PyObject *
x509_object_der_read_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(x509_object_der_read_file);
  return read_from_file_helper(x509_object_der_read_helper, type, args);
}

static char x509_object_pem_write__doc__[] =
  "This method returns a PEM- encoded certificate as a string.\n"
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
  "This method returns a DER encoded certificate as a string.\n"
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

static char x509_object_get_public_key__doc__[] =
  "This method gets the public key for this certificate object.\n"
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

  return (PyObject *) asym;

 error:
  Py_XDECREF(asym);
  return NULL;
}

static char x509_object_set_public_key__doc__[] =
  "This method sets the public key for this certificate object.\n"
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
  "This method signs a certificate with a private key.\n"
  "\n"
  "The \"key\" parameter should be an instance of the Asymmetric class,\n"
  "containing a private key.\n"
  "\n"
  "The optional \"digest\" parameter indicates which digest to compute and\n"
  "sign, and should be one of the following:\n"
  "\n"
  "* MD5_DIGEST\n"
  "* SHA_DIGEST\n"
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

static char x509_object_get_version__doc__[] =
  "This method returns the version number from the version field of this certificate.\n"
  ;

static PyObject *
x509_object_get_version(x509_object *self)
{
  ENTERING(x509_object_get_version);
  return Py_BuildValue("l", X509_get_version(self->x509));
}

static char x509_object_set_version__doc__[] =
  "This method sets the version number in the version field of this certificate.\n"
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
  "This method get the serial number in the serial field of this certificate.\n"
  ;

static PyObject *
x509_object_get_serial(x509_object *self)
{
  ENTERING(x509_object_get_serial);
  return Py_BuildValue("N", ASN1_INTEGER_to_PyLong(X509_get_serialNumber(self->x509)));
}

static char x509_object_set_serial__doc__[] =
  "This method sets the serial number in the serial field of this certificate.\n"
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
  "This method returns a tuple representing the issuers name.\n"
  "Each element of this tuple is another tuple representing one\n"
  "\"Relative Distinguished Name\" (RDN), each element of which in turn\n"
  "is yet another tuple representing one AttributeTypeAndValue pair.\n"
  "In practice, RDNs containing multiple attributes are rare, thus the RDN\n"
  "tuples will usually be exactly one element long, but using this\n"
  "structure allows us to represent the general case.\n"
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
  "This method returns a tuple containing the subjects name.  See\n"
  "the \"getIssuer\" method for details of the return value\n"
  "and use of the optional \"format\" parameter.\n"
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
  "This method is used to set the certificate's subject name.\n"
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
    lose_type_error("Inapropriate type");

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
  "This method is used to set the certificate's issuer name.\n"
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
    lose_type_error("Inapropriate type");

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

static char x509_object_get_not_before__doc__[] =
  "This method returns the certificate's \"notBefore\" value\n"
  "in the form of a GeneralizedTime string as restricted by RFC 5280.\n"
  "The code automatically converts RFC-5280-compliant UTCTime strings\n"
  "into the GeneralizedTime format, so that Python code need not worry\n"
  "about the conversion rules.\n"
  ;

static PyObject *
x509_object_get_not_before (x509_object *self)
{
  ENTERING(x509_object_get_not_before);
  return ASN1_TIME_to_Python(X509_get_notBefore(self->x509));
}

static char x509_object_get_not_after__doc__[] =
  "This method returns the certificate's \"notAfter\" value\n"
  "in the form of a GeneralizedTime string as restricted by RFC 5280.\n"
  "The code automatically converts RFC-5280-compliant UTCTime strings\n"
  "into the GeneralizedTime format, so that Python code need not worry\n"
  "about the conversion rules.\n"
  ;

static PyObject *
x509_object_get_not_after (x509_object *self)
{
  ENTERING(x509_object_get_not_after);
  return ASN1_TIME_to_Python(X509_get_notAfter(self->x509));
}

static char x509_object_set_not_after__doc__[] =
  "This method sets the certificate's \"notAfter\" value.\n"
  "\n"
  "The \"time\" parameter should be in the form of a GeneralizedTime string\n"
  "as restricted by RFC 5280. The code automatically converts to UTCTime\n"
  "when the RFC 5280 rules require UTCTime instead of GeneralizedTime,\n"
  "so that Python code need not worry about the conversion rules.\n"
  ;

static PyObject *
x509_object_set_not_after (x509_object *self, PyObject *args)
{
  char *s = NULL;
  ASN1_TIME *t = NULL;

  ENTERING(x509_object_set_not_after);

  if (!PyArg_ParseTuple(args, "s", &s))
    goto error;

  if ((t = Python_to_ASN1_TIME(s, 1)) == NULL)
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
  "This method sets the certificate's \"notBefore\" value.\n"
  "\n"
  "The \"time\" parameter should be in the form of a GeneralizedTime string\n"
  "as restricted by RFC 5280. The code automatically converts to UTCTime\n"
  "when the RFC 5280 rules require UTCTime instead of GeneralizedTime,\n"
  "so that Python code need not worry about the conversion rules.\n"
  ;

static PyObject *
x509_object_set_not_before (x509_object *self, PyObject *args)
{
  char *s = NULL;
  ASN1_TIME *t = NULL;

  ENTERING(x509_object_set_not_before);

  if (!PyArg_ParseTuple(args, "s", &s))
    goto error;

  if ((t = Python_to_ASN1_TIME(s, 1)) == NULL)
    lose("Couldn't convert notBefore string");

  if (!X509_set_notBefore(self->x509, t))
    lose("Couldn't set notBefore");

  ASN1_TIME_free(t);
  Py_RETURN_NONE;

 error:
  ASN1_TIME_free(t);
  return NULL;
}

static char x509_object_add_extension__doc__[] =
  "This method provides a generalized mechanism for adding an X509v3\n"
  "extension to a certificate.  Sadly, this is less useful than it might\n"
  "at first appear, because the extension to be added must be encoded using\n"
  "ASN.1 DER for  encapsulation in the extension as an OCTET STRING.\n"
  "It might be possible to make this method more useful by combining it\n"
  "with code using the OpenSSL ASN1_generate_v3(), ASN1_generate_nconf(),\n"
  "X509V3_EXT_conf_nid(), or X509V3_EXT_nconf() functions, but for RPKI\n"
  "work we probably want extension-specific methods anyway.  For now, we\n"
  "retain this API function, but it may go away in the near future.\n"
  "\n"
  "This method takes three parameters:\n"
  "\n"
  "  * \"name\", an OpenSSL \"short name\"\n"
  "  * \"critical\", a boolean\n"
  "  * \"value\", the DER-encoded extension value as a Python string\n"
  ;

static PyObject *
x509_object_add_extension(x509_object *self, PyObject *args)
{
  PyObject *critical = NULL;
  int len = 0, ok = 0;
  char *name = NULL;
  unsigned char *buf = NULL;
  ASN1_OBJECT *oid = NULL;
  ASN1_OCTET_STRING *octetString = NULL;
  X509_EXTENSION *ext = NULL;

  ENTERING(x509_object_add_extension);

  if (!PyArg_ParseTuple(args, "sOs#", &name, &critical, &buf, &len))
    goto error;

  if ((oid = OBJ_txt2obj(name, 0)) == NULL)
    lose("Extension has unknown object identifier");

  if ((octetString = ASN1_OCTET_STRING_new()) == NULL ||
      !ASN1_OCTET_STRING_set(octetString, buf, len))
    lose_no_memory();

  if ((ext = X509_EXTENSION_create_by_OBJ(NULL, oid, PyObject_IsTrue(critical),
                                          octetString)) == NULL)
    lose_openssl_error("Unable to create ASN.1 X.509 Extension object");

  if (!X509_add_ext(self->x509, ext, -1))
    lose_no_memory();

  ok = 1;

 error:                         /* Fall through */
  ASN1_OBJECT_free(oid);
  ASN1_OCTET_STRING_free(octetString);
  X509_EXTENSION_free(ext);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char x509_object_clear_extensions__doc__[] =
  "This method clears all extensions attached to this certificate.\n"
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

static char x509_object_count_extensions__doc__[] =
  "This method returns the number of extensions attached to this certificate.\n"
  ;

static PyObject *
x509_object_count_extensions(x509_object *self)
{
  ENTERING(x509_object_count_extensions);
  return Py_BuildValue("i", X509_get_ext_count(self->x509));
}

static char x509_object_get_extension__doc__[] =
  "This method returns a tuple equivalent the parameters of the\n"
  "\"addExtension\" method, and suffers from similar limitations.\n"
  "\n"
  "The \"index\" parameter is the position in the extension list of\n"
  "the extension to be returned.\n"
  ;

static PyObject *
x509_object_get_extension(x509_object *self, PyObject *args)
{
  X509_EXTENSION *ext;
  char oid[512];
  int slot = 0;

  ENTERING(x509_object_get_extension);

  if (!PyArg_ParseTuple(args, "i", &slot))
    goto error;

  if ((ext = X509_get_ext(self->x509, slot)) == NULL)
    lose_openssl_error("Couldn't get extension");

  if (OBJ_obj2txt(oid, sizeof(oid), ext->object, 1) <= 0)
    lose_openssl_error("Couldn't translate OID");

  return Py_BuildValue("sNs#", oid,
                       PyBool_FromLong(ext->critical),
                       ASN1_STRING_data(ext->value),
                       ASN1_STRING_length(ext->value));

 error:
  return NULL;
}

static char x509_object_get_ski__doc__[] =
  "This method returns the Subject Key Identifier (SKI) value for this\n"
  "certificate, or None if the certificate has no SKI extension.\n"
  ;

static PyObject *
x509_object_get_ski(x509_object *self, PyObject *args)
{
  ENTERING(x509_object_get_ski);

  (void) X509_check_ca(self->x509); /* Calls x509v3_cache_extensions() */

  if (self->x509->skid == NULL)
    Py_RETURN_NONE;
  else
    return Py_BuildValue("s#",
                         ASN1_STRING_data(self->x509->skid),
                         ASN1_STRING_length(self->x509->skid));
}

static char x509_object_set_ski__doc__[] =
  "This method sets the Subject Key Identifier (SKI) value for this\n"
  "certificate.\n"
  ;

static PyObject *
x509_object_set_ski(x509_object *self, PyObject *args)
{
  ASN1_OCTET_STRING *ext = NULL;
  const unsigned char *buf = NULL;
  int len, ok = 0;

  ENTERING(x509_object_set_ski);

  if (!PyArg_ParseTuple(args, "s#", &buf, &len))
    goto error;

  if ((ext = ASN1_OCTET_STRING_new()) == NULL ||
      !ASN1_OCTET_STRING_set(ext, buf, len))
    lose_no_memory();

  /*
   * RFC 5280 4.2.1.2 says this MUST be non-critical.
   */

  if (!X509_add1_ext_i2d(self->x509, NID_subject_key_identifier,
                         ext, 0, X509V3_ADD_REPLACE))
    lose_openssl_error("Couldn't add SKI extension to certificate");

  ok = 1;

 error:
  ASN1_OCTET_STRING_free(ext);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char x509_object_get_aki__doc__[] =
  "This method returns the Authority Key Identifier (AKI) keyid value for\n"
  " this certificate, or None if the certificate has no AKI extension\n"
  "or has an AKI extension with no keyIdentifier value.\n"
  ;

static PyObject *
x509_object_get_aki(x509_object *self, PyObject *args)
{
  ENTERING(x509_object_get_aki);

  (void) X509_check_ca(self->x509); /* Calls x509v3_cache_extensions() */

  if (self->x509->akid == NULL || self->x509->akid->keyid == NULL)
    Py_RETURN_NONE;
  else
    return Py_BuildValue("s#",
                         ASN1_STRING_data(self->x509->akid->keyid),
                         ASN1_STRING_length(self->x509->akid->keyid));
}

static char x509_object_set_aki__doc__[] =
  "This method sets the Authority Key Identifier (AKI) value for this\n"
  "certificate.   We only support the keyIdentifier method, as that's\n"
  "the only form which is legal for RPKI certificates.\n"
  ;

static PyObject *
x509_object_set_aki(x509_object *self, PyObject *args)
{
  AUTHORITY_KEYID *ext = NULL;
  const unsigned char *buf = NULL;
  int len, ok = 0;

  ENTERING(x509_object_set_aki);

  if (!PyArg_ParseTuple(args, "s#", &buf, &len))
    goto error;

  if ((ext = AUTHORITY_KEYID_new()) == NULL ||
      (ext->keyid == NULL && (ext->keyid = ASN1_OCTET_STRING_new()) == NULL) ||
      !ASN1_OCTET_STRING_set(ext->keyid, buf, len))
    lose_no_memory();

  /*
   * RFC 5280 4.2.1.1 says this MUST be non-critical.
   */

  if (!X509_add1_ext_i2d(self->x509, NID_authority_key_identifier,
                         ext, 0, X509V3_ADD_REPLACE))
    lose_openssl_error("Couldn't add AKI extension to certificate");

  ok = 1;

 error:
  AUTHORITY_KEYID_free(ext);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char x509_object_get_key_usage__doc__[] =
  "This method returns a FrozenSet of strings representing the KeyUsage\n"
  "settings for this certificate, or None if the certificate has no\n"
  "KeyUsage extension.  The bits have the same names as in RFC 5280.\n"
  ;

static PyObject *
x509_object_get_key_usage(x509_object *self)
{
  extern X509V3_EXT_METHOD v3_key_usage;
  BIT_STRING_BITNAME *bit_name;
  ASN1_BIT_STRING *ext = NULL;
  PyObject *result = NULL;
  PyObject *token = NULL;

  ENTERING(x509_object_get_key_usage);

  if ((ext = X509_get_ext_d2i(self->x509, NID_key_usage, NULL, NULL)) == NULL)
    Py_RETURN_NONE;

  if ((result = PyFrozenSet_New(NULL)) == NULL)
    goto error;

  for (bit_name = v3_key_usage.usr_data; bit_name->sname != NULL; bit_name++) {
    if (ASN1_BIT_STRING_get_bit(ext, bit_name->bitnum) &&
        ((token = PyString_FromString(bit_name->sname)) == NULL ||
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

static char x509_object_set_key_usage__doc__[] =
  "This method sets the KeyUsage extension  for this certificate.\n"
  "\n"
  "Argument \"iterable\" should be an iterable object which returns zero or more\n"
  "strings naming bits to be enabled.  The bits have the same names as in RFC 5280.\n"
  "\n"
  "Optional argument \"critical\" is a boolean indicating whether the extension\n"
  "should be marked as critical or not.  RFC 5280 4.2.1.3 says this extension SHOULD\n"
  "be marked as critical when used, so the default is True.\n"
  ;

static PyObject *
x509_object_set_key_usage(x509_object *self, PyObject *args)
{
  extern X509V3_EXT_METHOD v3_key_usage;
  BIT_STRING_BITNAME *bit_name;
  ASN1_BIT_STRING *ext = NULL;
  PyObject *iterable = NULL;
  PyObject *critical = Py_True;
  PyObject *iterator = NULL;
  PyObject *token = NULL;
  const char *t;
  int ok = 0;

  ENTERING(x509_object_set_key_usage);

  if ((ext = ASN1_BIT_STRING_new()) == NULL)
    lose_no_memory();

  if (!PyArg_ParseTuple(args, "O|O", &iterable, &critical) ||
      (iterator = PyObject_GetIter(iterable)) == NULL)
    goto error;

  while ((token = PyIter_Next(iterator)) != NULL) {

    if ((t = PyString_AsString(token)) == NULL)
      goto error;

    for (bit_name = v3_key_usage.usr_data; bit_name->sname != NULL; bit_name++)
      if (!strcmp(t, bit_name->sname))
        break;

    if (bit_name->sname == NULL)
      lose("Unrecognized KeyUsage token");

    if (!ASN1_BIT_STRING_set_bit(ext, bit_name->bitnum, 1))
      lose_no_memory();

    Py_XDECREF(token);
    token = NULL;
  }

  if (!X509_add1_ext_i2d(self->x509, NID_key_usage, ext,
                         PyObject_IsTrue(critical),
                         X509V3_ADD_REPLACE))
    lose_openssl_error("Couldn't add KeyUsage extension to certificate");

  ok = 1;

 error:                         /* Fall through */
  ASN1_BIT_STRING_free(ext);
  Py_XDECREF(iterator);
  Py_XDECREF(token);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char x509_object_get_rfc3779__doc__[] =
  "This method returns the certificate's RFC 3779 resources.  This is a\n"
  "three-element tuple: the first element is the ASN resources, the\n"
  "second is the IPv4 resources, the third is the IPv6 resources.\n"
  "\n"
  "[Add more description here once final format is stable]\n"
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
          lose_type_error("Unexpected asIdsOrRanges type");
        }

        if (ASN1_STRING_type(b) == V_ASN1_NEG_INTEGER ||
            ASN1_STRING_type(e) == V_ASN1_NEG_INTEGER)
          lose_type_error("I don't believe in negative ASNs");

        if ((range_b = ASN1_INTEGER_to_PyLong(b)) == NULL ||
            (range_e = ASN1_INTEGER_to_PyLong(e)) == NULL ||
            (range = Py_BuildValue("(NN)", range_b, range_e)) == NULL)
          goto error;

        PyTuple_SET_ITEM(asn_result, i, range);
        range = range_b = range_e = NULL;
      }

      break;

    default:
      lose_type_error("Unexpected ASIdentifierChoice type");
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
      default:            lose_type_error("Unknown AFI");
      }

      if (*result_obj != NULL)
        lose_type_error("Duplicate IPAddressFamily");

      if (f->addressFamily->length > 2)
        lose_type_error("Unsupported SAFI");

      switch (f->ipAddressChoice->type) {

      case IPAddressChoice_inherit:
        if ((*result_obj = PyString_FromString("inherit")) == NULL)
          goto error;
        continue;

      case IPAddressChoice_addressesOrRanges:
        break;

      default:
        lose_type_error("Unexpected IPAddressChoice type");
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
          lose_type_error("Couldn't unpack IP addresses from BIT STRINGs");

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
  "This method sets the certificate's RFC 3779 resources.\n"
  "\n"
  "[Add description here once argument format is stable]\n"
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
  PyObject *range_b = NULL;
  PyObject *range_e = NULL;
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
        lose_type_error("ASID must be sequence of range pairs, or \"inherit\"");

      if (!v3_asid_add_inherit(asid, V3_ASID_ASNUM))
        lose_no_memory();

      empty = 0;

    } else {

      if ((iterator = PyObject_GetIter(asn_arg)) == NULL)
        goto error;

      while ((item = PyIter_Next(iterator)) != NULL) {

        if (!PyArg_ParseTuple(item, "OO", &range_b, &range_e) ||
            (asid_b = PyLong_to_ASN1_INTEGER(range_b)) == NULL)
          goto error;

        switch (PyObject_RichCompareBool(range_b, range_e, Py_EQ)) {
        case 0:
          if ((asid_e = PyLong_to_ASN1_INTEGER(range_e)) == NULL)
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
        item = range_b = range_e = NULL;
        empty = 0;
      }

      if (!empty && (!v3_asid_canonize(asid) ||
                     !X509_add1_ext_i2d(self->x509, NID_sbgp_autonomousSysNum,
                                        asid, 1, X509V3_ADD_REPLACE)))
        lose_openssl_error("Couldn't add ASID extension to certificate");

      Py_XDECREF(iterator);
      iterator = NULL;
    }
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

    for (v = 0; v < sizeof(ipaddress_versions)/sizeof(*ipaddress_versions); v++) {
      const struct ipaddress_version *ip_type = ipaddress_versions[v];
      PyObject **argp;

      switch (ip_type->version) {
      case 4: argp = &ipv4_arg; break;
      case 6: argp = &ipv6_arg; break;
      default: continue;        /* Never happens */
      }

      if (PyString_Check(*argp)) {

        if (strcmp(PyString_AsString(*argp), "inherit"))
          lose_type_error("Argument must be sequence of range pairs, or \"inherit\"");

        if (!v3_addr_add_inherit(addr, ip_type->afi, NULL))
          lose_no_memory();

        empty = 0;

      } else {

        if ((iterator = PyObject_GetIter(*argp)) == NULL)
          goto error;

        while ((item = PyIter_Next(iterator)) != NULL) {

          if (!PyArg_ParseTuple(item, "O!O!",
                                &POW_IPAddress_Type, &range_b, 
                                &POW_IPAddress_Type, &range_e))
            goto error;

          addr_b = (ipaddress_object *) range_b;
          addr_e = (ipaddress_object *) range_e;

          if (addr_b->type != ip_type ||
              addr_e->type != ip_type ||
              memcmp(addr_b->address, addr_e->address, ip_type->length) > 0)
            lose("IPAddrBlock must be sequence of address pairs, or \"inherit\"");

          if (!v3_addr_add_range(addr, ip_type->afi, NULL, addr_b->address, addr_e->address))
            lose_openssl_error("Couldn't add range to IPAddrBlock");

          Py_XDECREF(item);
          item = range_b = range_e = NULL;
          addr_b = addr_e = NULL;
        }

        Py_XDECREF(iterator);
        iterator = NULL;
        empty = 0;
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
  return NULL;
}

static char x509_object_get_basic_constraints__doc__[] =
  "Get BasicConstraints value for this certificate.  If the certificate\n"
  "has no BasicConstraints extension, this method returns None.\n"
  "Otherwise, it returns a two-element tuple.  The first element of the\n"
  "tuple is a boolean representing the extension's cA value; the second\n"
  "element of the tuple is either an integer representing the\n"
  "pathLenConstraint value or None if there is no pathLenConstraint.\n"
  ;

static PyObject *
x509_object_get_basic_constraints(x509_object *self)
{
  BASIC_CONSTRAINTS *ext = NULL;
  PyObject *result;

  ENTERING(x509_object_get_basic_constraints);

  if ((ext = X509_get_ext_d2i(self->x509, NID_basic_constraints, NULL, NULL)) == NULL)
    Py_RETURN_NONE;

  if (ext->pathlen == NULL)
    result = Py_BuildValue("(NO)", PyBool_FromLong(ext->ca), Py_None);
  else
    result = Py_BuildValue("(Nl)", PyBool_FromLong(ext->ca), ASN1_INTEGER_get(ext->pathlen));

  BASIC_CONSTRAINTS_free(ext);
  return result;
}

static char x509_object_set_basic_constraints__doc__[] =
  "Set BasicConstraints value for this certificate.\n"
  "\n"
  "First argument \"ca\" is a boolean indicating whether the certificate\n"
  "is a CA certificate or not.\n"
  "\n"
  "Optional second argument \"pathLenConstraint\" is a non-negative integer\n"
  "specifying the pathLenConstraint value for this certificate; this value\n"
  "may only be set for CA certificates."
  "\n"
  "Optional third argument \"critical\" specifies whether the extension\n"
  "should be marked as critical.  RFC 5280 4.2.1.9 requires that CA\n"
  "certificates mark this extension as critical, so the default is True.\n"
  ;

static PyObject *
x509_object_set_basic_constraints(x509_object *self, PyObject *args)
{
  BASIC_CONSTRAINTS *ext = NULL;
  PyObject *is_ca = NULL;
  PyObject *pathlen_obj = Py_None;
  PyObject *critical = Py_True;
  long pathlen = -1;
  int ok = 0;

  ENTERING(x509_object_set_basic_constraints);

  if (!PyArg_ParseTuple(args, "O|OO", &is_ca, &pathlen_obj, &critical))
    goto error;

  if (pathlen_obj != Py_None && (pathlen = PyInt_AsLong(pathlen_obj)) < 0)
    lose_type_error("Bad pathLenConstraint value");

  if ((ext = BASIC_CONSTRAINTS_new()) == NULL)
    lose_no_memory();

  ext->ca = PyObject_IsTrue(is_ca) ? 0xFF : 0;

  if (pathlen_obj != Py_None &&
      ((ext->pathlen == NULL && (ext->pathlen = ASN1_INTEGER_new()) == NULL) ||
       !ASN1_INTEGER_set(ext->pathlen, pathlen)))
    lose_no_memory();

  if (!X509_add1_ext_i2d(self->x509, NID_basic_constraints,
                         ext, PyObject_IsTrue(critical), X509V3_ADD_REPLACE))
    lose_openssl_error("Couldn't add BasicConstraints extension to certificate");

  ok = 1;

 error:
  BASIC_CONSTRAINTS_free(ext);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char x509_object_get_sia__doc__[] =
  "Get SIA values for this certificate.  If the certificate\n"
  "has no SIA extension, this method returns None.\n"
  "Otherwise, it returns a tuple containing three sequences:\n"
  "caRepository URIs, rpkiManifest URIs, and signedObject URIs.\n"
  "Any other accessMethods are ignored, as are any non-URI\n"
  "accessLocations.\n"
  ;

static PyObject *
x509_object_get_sia(x509_object *self)
{
  AUTHORITY_INFO_ACCESS *ext = NULL;
  PyObject *result = NULL;
  PyObject *result_caRepository = NULL;
  PyObject *result_rpkiManifest = NULL;
  PyObject *result_signedObject = NULL;
  int n_caRepository = 0;
  int n_rpkiManifest = 0;
  int n_signedObject = 0;
  const char *uri;
  PyObject *obj;
  int i, nid;

  ENTERING(x509_object_get_sia);

  if ((ext = X509_get_ext_d2i(self->x509, NID_sinfo_access, NULL, NULL)) == NULL)
    Py_RETURN_NONE;

  /*
   * Easiest to do this in two passes, first pass just counts URIs.
   */

  for (i = 0; i < sk_ACCESS_DESCRIPTION_num(ext); i++) {
    ACCESS_DESCRIPTION *a = sk_ACCESS_DESCRIPTION_value(ext, i);
    if (a->location->type != GEN_URI)
      continue;
    nid = OBJ_obj2nid(a->method);
    if (nid == NID_caRepository) {
      n_caRepository++;
      continue;
    }
    if (nid == NID_rpkiManifest) {
      n_rpkiManifest++;
      continue;
    }
    if (nid == NID_signedObject) {
      n_signedObject++;
      continue;
    }
  }

  if (((result_caRepository = PyTuple_New(n_caRepository)) == NULL) ||
      ((result_rpkiManifest = PyTuple_New(n_rpkiManifest)) == NULL) ||
      ((result_signedObject = PyTuple_New(n_signedObject)) == NULL))
    goto error;

  n_caRepository = n_rpkiManifest = n_signedObject = 0;

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
    if (nid == NID_rpkiManifest) {
      if ((obj = PyString_FromString(uri)) == NULL)
        goto error;
      PyTuple_SET_ITEM(result_rpkiManifest, n_rpkiManifest++, obj);
      continue;
    }
    if (nid == NID_signedObject) {
      if ((obj = PyString_FromString(uri)) == NULL)
        goto error;
      PyTuple_SET_ITEM(result_signedObject, n_signedObject++, obj);
      continue;
    }
  }

  result = Py_BuildValue("(OOO)",
                         result_caRepository,
                         result_rpkiManifest,
                         result_signedObject);

 error:
  AUTHORITY_INFO_ACCESS_free(ext);
  Py_XDECREF(result_caRepository);
  Py_XDECREF(result_rpkiManifest);
  Py_XDECREF(result_signedObject);
  return result;
}

static char x509_object_set_sia__doc__[] =
  "Set SIA values for this certificate.  Takes three arguments:\n"
  "caRepository URIs, rpkiManifest URIs, and signedObject URIs.\n"
  "Each of these should be an iterable which returns URIs.\n"
  "None is acceptable as an alternate way of specifying an empty\n"
  "sequence of URIs for a particular argument.\n"
  ;

static PyObject *
x509_object_set_sia(x509_object *self, PyObject *args)
{
  AUTHORITY_INFO_ACCESS *ext = NULL;
  PyObject *caRepository = NULL;
  PyObject *rpkiManifest = NULL;
  PyObject *signedObject = NULL;
  PyObject *iterator = NULL;
  ASN1_OBJECT *oid = NULL;
  PyObject **pobj = NULL;
  PyObject *item = NULL;
  ACCESS_DESCRIPTION *a = NULL;
  int i, nid = NID_undef, ok = 0;
  Py_ssize_t urilen;
  char *uri;

  ENTERING(x509_object_set_sia);

  if (!PyArg_ParseTuple(args, "OOO", &caRepository, &rpkiManifest, &signedObject))
    goto error;

  if ((ext = AUTHORITY_INFO_ACCESS_new()) == NULL)
    lose_no_memory();

  /*
   * This is going to want refactoring, because it's ugly, because we
   * want to reuse code for AIA, and because it'd be nice to support a
   * single URI as an abbreviation for a sequence containing one URI.
   */

  for (i = 0; i < 3; i++) {
    switch (i) {
    case 0: pobj = &caRepository; nid = NID_caRepository; break;
    case 1: pobj = &rpkiManifest; nid = NID_rpkiManifest; break;
    case 2: pobj = &signedObject; nid = NID_signedObject; break;
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
  }

  if (!X509_add1_ext_i2d(self->x509, NID_sinfo_access, ext, 0, X509V3_ADD_REPLACE))
    lose_openssl_error("Couldn't add SIA extension to certificate");

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

static char x509_object_get_aia__doc__[] =
  "Get AIA values for this certificate.  If the certificate\n"
  "has no AIA extension, this method returns None.\n"
  "Otherwise, it returns a sequence of caIssuers URIs.\n"
  "Any other accessMethods are ignored, as are any non-URI\n"
  "accessLocations.\n"
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
  "Set AIA values for this certificate.  Argument is a iterable\n"
  "which returns caIssuers URIs.\n"
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
  "If the certificate has no CRLDP extension, this method returns None.\n"
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
  "Set CRLDP values for this certificate.  Argument is a iterable\n"
  "which returns distributionPoint fullName URIs.\n"
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
  "Get Certificate Policies values for this certificate.  If the\n"
  "certificate has no Certificate Policies extension, this method returns\n"
  "None.  Otherwise, it returns a sequence of Object Identifiers.\n"
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
  "Set Certificate Policies for this certificate.  Argument is a iterable\n"
  "which returns policy OIDs.  Policy qualifier are not supported.\n"
  "The extension will be marked as critical.\n"
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

/*
 * May want EKU handlers eventually, skip for now.
 */

static char x509_object_pprint__doc__[] =
  "This method returns a pretty-printed rendition of the certificate.\n"
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
  Define_Method(addExtension,           x509_object_add_extension,              METH_VARARGS),
  Define_Method(clearExtensions,        x509_object_clear_extensions,           METH_NOARGS),
  Define_Method(countExtensions,        x509_object_count_extensions,           METH_NOARGS),
  Define_Method(getExtension,           x509_object_get_extension,              METH_VARARGS),
  Define_Method(pprint,                 x509_object_pprint,                     METH_NOARGS),
  Define_Method(getSKI,                 x509_object_get_ski,                    METH_NOARGS),
  Define_Method(setSKI,                 x509_object_set_ski,                    METH_VARARGS),
  Define_Method(getAKI,                 x509_object_get_aki,                    METH_NOARGS),
  Define_Method(setAKI,                 x509_object_set_aki,                    METH_VARARGS),
  Define_Method(getKeyUsage,            x509_object_get_key_usage,              METH_NOARGS),
  Define_Method(setKeyUsage,            x509_object_set_key_usage,              METH_VARARGS),
  Define_Method(getRFC3779,             x509_object_get_rfc3779,                METH_NOARGS),
  Define_Method(setRFC3779,             x509_object_set_rfc3779,                METH_KEYWORDS),
  Define_Method(getBasicConstraints,    x509_object_get_basic_constraints,      METH_NOARGS),
  Define_Method(setBasicConstraints,    x509_object_set_basic_constraints,      METH_VARARGS),
  Define_Method(getSIA,                 x509_object_get_sia,                    METH_NOARGS),
  Define_Method(setSIA,                 x509_object_set_sia,                    METH_VARARGS),
  Define_Method(getAIA,                 x509_object_get_aia,                    METH_NOARGS),
  Define_Method(setAIA,                 x509_object_set_aia,                    METH_VARARGS),
  Define_Method(getCRLDP,               x509_object_get_crldp,                  METH_NOARGS),
  Define_Method(setCRLDP,               x509_object_set_crldp,                  METH_VARARGS),
  Define_Method(getCertificatePolicies, x509_object_get_certificate_policies,   METH_NOARGS),
  Define_Method(setCertificatePolicies, x509_object_set_certificate_policies,   METH_VARARGS),
  Define_Class_Method(pemRead,          x509_object_pem_read,                   METH_VARARGS),
  Define_Class_Method(pemReadFile,      x509_object_pem_read_file,              METH_VARARGS),
  Define_Class_Method(derRead,          x509_object_der_read,                   METH_VARARGS),
  Define_Class_Method(derReadFile,      x509_object_der_read_file,              METH_VARARGS),
  {NULL}
};

static char POW_X509_Type__doc__[] =
  "This class represents an X.509 certificate.\n"
  "\n"
  LAME_DISCLAIMER_IN_ALL_CLASS_DOCUMENTATION
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
 * X509Store object.
 */

static PyObject *
x509_store_object_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  x509_store_object *self = NULL;

  ENTERING(x509_store_object_new);

  if ((self = (x509_store_object *) type->tp_alloc(type, 0)) != NULL &&
      (self->store = X509_STORE_new()) != NULL)
    return (PyObject *) self;

  Py_XDECREF(self);
  return NULL;
}

static void
x509_store_object_dealloc(x509_store_object *self)
{
  ENTERING(x509_store_object_dealloc);
  X509_STORE_free(self->store);
  self->ob_type->tp_free((PyObject*) self);
}

#if ENABLE_X509_CERTIFICATE_SIGNATURE_AND_VERIFICATION
#warning Check X509_verify_cert options
/*
 * I once knew all the grotty details of how X509_verify_cert() gets
 * its control flags and data, but don't remember off the top of my head,
 * and would prefer not to stop the current documentation cleanup pass
 * to relearn all of that.  So come back to this.
 *
 * Mostly what I'm worried about here is the ten zillion flags that
 * tell X509_verify_cert() whether to check CRLs, whether to verify
 * the whole chain, whether to enforce policy constraints, etc etc.
 * This may all be covered already, I just don't remember.  Might not
 * matter, as these methods are probably destined for deletion.
 */

static char x509_store_object_verify__doc__[] =
  "This method performs X.509 certificate verification using\n"
  "the OpenSSL X509_verify_cert() function.\n"
  "\n"
  "The \"certificate\" parameter is the certificate to verify, and\n"
  "should be an X509 object.\n"
  ;

static PyObject *
x509_store_object_verify(x509_store_object *self, PyObject *args)
{
  X509_STORE_CTX ctx;
  x509_object *x509 = NULL;
  int ok;

  if (!PyArg_ParseTuple(args, "O!", &POW_X509_Type, &x509))
    goto error;

  X509_STORE_CTX_init(&ctx, self->store, x509->x509, NULL);
  ok = X509_verify_cert(&ctx) == 1;
  X509_STORE_CTX_cleanup(&ctx);

  return PyBool_FromLong(ok);

 error:
  return NULL;
}

static char x509_store_object_verify_chain__doc__[] =
  "This method performs X.509 certificate verification using\n"
  "the OpenSSL X509_verify_cert() function.\n"
  "\n"
  "The \"certificate\" parameter is the certificate to verify, and\n"
  "should be an X509 object.\n"
  "\n"
  "the \"chain\" paramater should be a sequence of X509 objects which\n"
  "form a chain to a trusted certificate.\n"
  ;

static PyObject *
x509_store_object_verify_chain(x509_store_object *self, PyObject *args)
{
  PyObject *x509_sequence = NULL;
  X509_STORE_CTX ctx;
  x509_object *x509 = NULL;
  STACK_OF(X509) *x509_stack = NULL;
  int ok;

  if (!PyArg_ParseTuple(args, "O!O", &POW_X509_Type, &x509, &x509_sequence))
    goto error;

  if ((x509_stack = x509_helper_sequence_to_stack(x509_sequence)) == NULL)
    goto error;

  X509_STORE_CTX_init(&ctx, self->store, x509->x509, x509_stack);
  ok = X509_verify_cert(&ctx) == 1;
  X509_STORE_CTX_cleanup(&ctx);
  sk_X509_free(x509_stack);

  return PyBool_FromLong(ok);

 error:
  sk_X509_free(x509_stack);
  return NULL;
}

static char x509_store_object_verify_detailed__doc__[] =
  "This method performs X.509 certificate verification using\n"
  "the OpenSSL X509_verify_cert() function.\n"
  "\n"
  "The \"certificate\" parameter is the certificate to verify, and\n"
  "should be an X509 object.\n"
  "\n"
  "the \"chain\" paramater should be a sequence of X509 objects which\n"
  "form a chain to a trusted certificate.\n"
  "\n"
  "Unlike the \"verify\" and \"verifyChain\" methods, this method returns\n"
  "some information about what went wrong when verification fails.\n"
  "The return value is currently a 3-element tuple consisting of:\n"
  "\n"
  "  * The numeric return value from X509_verify_cert()\n"
  "  * The numeric error code value from the X509_STORE_CTX\n"
  "  * The numeric error_depth value from the X509_STORE_CTX\n"
  "\n"
  "Other values may added to this tuple later, if needed.\n"
  ;

static PyObject *
x509_store_object_verify_detailed(x509_store_object *self, PyObject *args)
{
  PyObject *x509_sequence = Py_None;
  X509_STORE_CTX ctx;
  x509_object *x509 = NULL;
  STACK_OF(X509) *x509_stack = NULL;
  PyObject *result = NULL;
  int ok;

  if (!PyArg_ParseTuple(args, "O!|O", &POW_X509_Type, &x509, &x509_sequence))
    goto error;

  if (x509_sequence && !(x509_stack = x509_helper_sequence_to_stack(x509_sequence)))
    goto error;

  X509_STORE_CTX_init(&ctx, self->store, x509->x509, x509_stack);
  ok = X509_verify_cert(&ctx) == 1;
  result = Py_BuildValue("(iii)", ok, ctx.error, ctx.error_depth);
  X509_STORE_CTX_cleanup(&ctx);

 error:                          /* fall through */
  sk_X509_free(x509_stack);
  return result;
}

#endif /* ENABLE_X509_CERTIFICATE_SIGNATURE_AND_VERIFICATION */

static char x509_store_object_add_trust__doc__[] =
  "This method adds a new trusted certificate to the store object.\n"
  "\n"
  "The \"certificate\" parameter should be an instance of the X509 class.\n"
  "\n"
  "Using trusted certificates to manage verification is relatively primitive,\n"
  "more sophisticated systems can be constructed at application level by\n"
  "constructing certificate chains to verify.\n"
  ;

static PyObject *
x509_store_object_add_trust(x509_store_object *self, PyObject *args)
{
  x509_object *x509 = NULL;

  ENTERING(x509_store_object_add_trust);

  if (!PyArg_ParseTuple(args, "O!", &POW_X509_Type, &x509))
    goto error;

  X509_STORE_add_cert(self->store, x509->x509);

  Py_RETURN_NONE;

 error:

  return NULL;
}

static char x509_store_object_add_crl__doc__[] =
  "This method adds a CRL to the store object.\n"
  "\n"
  "The \"crl\" parameter should be an instance of CRL.\n"
  ;

static PyObject *
x509_store_object_add_crl(x509_store_object *self, PyObject *args)
{
  crl_object *crl = NULL;

  ENTERING(x509_store_object_add_crl);

  if (!PyArg_ParseTuple(args, "O!", &POW_CRL_Type, &crl))
    goto error;

  X509_STORE_add_crl(self->store, crl->crl);

  Py_RETURN_NONE;

 error:

  return NULL;
}

static struct PyMethodDef x509_store_object_methods[] = {
#if ENABLE_X509_CERTIFICATE_SIGNATURE_AND_VERIFICATION
  Define_Method(verify,         x509_store_object_verify,               METH_VARARGS),
  Define_Method(verifyChain,    x509_store_object_verify_chain,         METH_VARARGS),
  Define_Method(verifyDetailed, x509_store_object_verify_detailed,      METH_VARARGS),
#endif
  Define_Method(addTrust,       x509_store_object_add_trust,            METH_VARARGS),
  Define_Method(addCrl,         x509_store_object_add_crl,              METH_VARARGS),
  {NULL}
};

static char POW_X509Store_Type__doc__[] =
  "This class provides basic access to the OpenSSL certificate store\n"
  "mechanism used in X.509 and CMS verification.\n"
  "\n"
  LAME_DISCLAIMER_IN_ALL_CLASS_DOCUMENTATION
  ;

static PyTypeObject POW_X509Store_Type = {
  PyObject_HEAD_INIT(0)
  0,                                        /* ob_size */
  "rpki.POW.X509Store",                     /* tp_name */
  sizeof(x509_store_object),                /* tp_basicsize */
  0,                                        /* tp_itemsize */
  (destructor)x509_store_object_dealloc,    /* tp_dealloc */
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
  POW_X509Store_Type__doc__,                /* tp_doc */
  0,                                        /* tp_traverse */
  0,                                        /* tp_clear */
  0,                                        /* tp_richcompare */
  0,                                        /* tp_weaklistoffset */
  0,                                        /* tp_iter */
  0,                                        /* tp_iternext */
  x509_store_object_methods,                /* tp_methods */
  0,                                        /* tp_members */
  0,                                        /* tp_getset */
  0,                                        /* tp_base */
  0,                                        /* tp_dict */
  0,                                        /* tp_descr_get */
  0,                                        /* tp_descr_set */
  0,                                        /* tp_dictoffset */
  0,                                        /* tp_init */
  0,                                        /* tp_alloc */
  x509_store_object_new,                    /* tp_new */
};



/*
 * CRL object.
 */

static PyObject *
crl_object_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  crl_object *self = NULL;

  ENTERING(crl_object_new);

  if ((self = (crl_object *) type->tp_alloc(type, 0)) != NULL &&
      (self->crl = X509_CRL_new()) != NULL)
    return (PyObject *) self;

  Py_XDECREF(self);
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
  "Class method to read a PEM-encoded CRL object from a string.\n"
  ;

static PyObject *
crl_object_pem_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(crl_object_pem_read);
  return read_from_string_helper(crl_object_pem_read_helper, type, args);
}

static char crl_object_pem_read_file__doc__[] =
  "Class method to read a PEM-encoded CRL object from a file.\n"
  ;

static PyObject *
crl_object_pem_read_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(crl_object_pem_read_file);
  return read_from_file_helper(crl_object_pem_read_helper, type, args);
}

static char crl_object_der_read__doc__[] =
  "Class method to read a DER-encoded CRL object from a string.\n"
  ;

static PyObject *
crl_object_der_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(crl_object_der_read);
  return read_from_string_helper(crl_object_der_read_helper, type, args);
}

static char crl_object_der_read_file__doc__[] =
  "Class method to read a DER-encoded CRL object from a file.\n"
  ;

static PyObject *
crl_object_der_read_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(crl_object_der_read_file);
  return read_from_file_helper(crl_object_der_read_helper, type, args);
}

static char crl_object_get_version__doc__[] =
  "This method returns the version number of this CRL.\n"
  ;

static PyObject *
crl_object_get_version(crl_object *self)
{
  ENTERING(crl_object_get_version);
  return Py_BuildValue("l", X509_CRL_get_version(self->crl));
}

static char crl_object_set_version__doc__[] =
  "This method sets the version number of this CRL.\n"
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
  "This method returns issuer name from this CRL.\n"
  "See the \"getIssuer\" method of the X509 class for more details.\n"
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
  "This method sets the CRL's issuer name.\n"
  "See the \"setIssuer\" method of the X509 class for details.\n"
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
    lose_type_error("Inapropriate type");

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

/*
 * NB: OpenSSL is confused about the name of this field, probably for
 * backwards compatability with some ancient mistake.  What RFC 5280
 * calls "thisUpdate", OpenSSL calls "lastUpdate".
 */

static char crl_object_set_this_update__doc__[] =
  "This method sets the CRL's \"thisUpdate\" value.\n"
  "\n"
  "The \"time\" parameter should be in the form of a GeneralizedTime string\n"
  "as restricted by RFC 5280. The code automatically converts to UTCTime\n"
  "when the RFC 5280 rules require UTCTime instead of GeneralizedTime,\n"
  "so that Python code need not worry about the conversion rules.\n"
  ;

static PyObject *
crl_object_set_this_update (crl_object *self, PyObject *args)
{
  char *s = NULL;
  ASN1_TIME *t = NULL;

  ENTERING(crl_object_set_this_update);

  if (!PyArg_ParseTuple(args, "s", &s))
    goto error;

  if ((t = Python_to_ASN1_TIME(s, 1)) == NULL)
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
  "This method returns the CRL's \"thisUpdate\" value\n"
  "in the form of a GeneralizedTime string as restricted by RFC 5280.\n"
  "The code automatically converts RFC-5280-compliant UTCTime strings\n"
  "into the GeneralizedTime format, so that Python code need not worry\n"
  "about the conversion rules.\n"
  ;

static PyObject *
crl_object_get_this_update (crl_object *self)
{
  ENTERING(crl_object_get_this_update);
  return ASN1_TIME_to_Python(X509_CRL_get_lastUpdate(self->crl)); /* sic */
}

static char crl_object_set_next_update__doc__[] =
  "This method sets the CRL's \"nextUpdate\" value.\n"
  "\n"
  "The \"time\" parameter should be in the form of a GeneralizedTime string\n"
  "as restricted by RFC 5280. The code automatically converts to UTCTime\n"
  "when the RFC 5280 rules require UTCTime instead of GeneralizedTime,\n"
  "so that Python code need not worry about the conversion rules.\n"
  ;

static PyObject *
crl_object_set_next_update (crl_object *self, PyObject *args)
{
  char *s = NULL;
  ASN1_TIME *t = NULL;

  ENTERING(crl_object_set_next_update);

  if (!PyArg_ParseTuple(args, "s", &s))
    goto error;

  if ((t = Python_to_ASN1_TIME(s, 1)) == NULL)
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
  "This method returns the CRL's \"nextUpdate\" value\n"
  "in the form of a GeneralizedTime string as restricted by RFC 5280.\n"
  "The code automatically converts RFC-5280-compliant UTCTime strings\n"
  "into the GeneralizedTime format, so that Python code need not worry\n"
  "about the conversion rules.\n"
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
  "The \"iterable\" parameter should be an iterable object, each element\n"
  "of which is a two-element sequence; the first element of this sequence\n"
  "should be the revoked serial number (an integer), the second element\n"
  "should be the revocation date (a timestamp in GeneralizedTime format).\n"
  ;

static PyObject *
crl_object_add_revocations(crl_object *self, PyObject *args)
{
  PyObject *iterable = NULL;
  PyObject *iterator = NULL;
  PyObject *item = NULL;
  PyObject *p_serial = NULL;
  X509_REVOKED *revoked = NULL;
  ASN1_INTEGER *a_serial = NULL;
  ASN1_TIME *a_date = NULL;
  int ok = 0;
  char *c_date;

  ENTERING(crl_object_add_revocations);

  if (!PyArg_ParseTuple(args, "O", &iterable) ||
      (iterator = PyObject_GetIter(iterable)) == NULL)
    goto error;

  while ((item = PyIter_Next(iterator)) != NULL) {

    if (!PyArg_ParseTuple(item, "Os", &p_serial, &c_date) ||
        (a_serial = PyLong_to_ASN1_INTEGER(p_serial)) == NULL)
      goto error;

    if ((revoked = X509_REVOKED_new()) == NULL ||
        !X509_REVOKED_set_serialNumber(revoked, a_serial))
      lose_no_memory();

    ASN1_INTEGER_free(a_serial);
    a_serial = NULL;

    if ((a_date = Python_to_ASN1_TIME(c_date, 1)) == NULL)
      lose("Couldn't convert revocationDate string");

    if (!X509_REVOKED_set_revocationDate(revoked, a_date))
      lose("Couldn't set revocationDate");

    ASN1_TIME_free(a_date);
    a_date = NULL;

    if (!X509_CRL_add0_revoked(self->crl, revoked))
      lose_no_memory();

    revoked = NULL;
    Py_XDECREF(item);
    item = NULL;
  }

  if (!X509_CRL_sort(self->crl))
    lose_openssl_error("Couldn't sort CRL");

  ok = 1;

 error:
  Py_XDECREF(iterator);
  Py_XDECREF(item);
  X509_REVOKED_free(revoked);
  ASN1_INTEGER_free(a_serial);
  ASN1_TIME_free(a_date);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char crl_object_get_revoked__doc__[] =
  "This method returns a tuple of X509Revoked objects representing the sequence\n"
  "of revoked certificates listed in the CRL.\n"
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

static char crl_object_add_extension__doc__[] =
  "This method adds an extension to this CRL.\n"
  "It takes the same arguments and has the same limitations as the\n"
  "X509.addExtension() method (q.v.).\n"
  ;

static PyObject *
crl_object_add_extension(crl_object *self, PyObject *args)
{
  PyObject *critical = NULL;
  int len = 0, ok = 0;
  char *name = NULL;
  unsigned char *buf = NULL;
  ASN1_OBJECT *oid = NULL;
  ASN1_OCTET_STRING *octetString = NULL;
  X509_EXTENSION *ext = NULL;

  ENTERING(crl_object_add_extension);

  if (!PyArg_ParseTuple(args, "sOs#", &name, &critical, &buf, &len))
    goto error;

  if ((oid = OBJ_txt2obj(name, 0)) == NULL)
    lose("Extension has unknown object identifier");

  if ((octetString = ASN1_OCTET_STRING_new()) == NULL ||
      !ASN1_OCTET_STRING_set(octetString, buf, len))
    lose_no_memory();

  if ((ext = X509_EXTENSION_create_by_OBJ(NULL, oid, PyObject_IsTrue(critical),
                                          octetString)) == NULL)
    lose_openssl_error("Unable to create ASN.1 X.509 Extension object");

  if (!X509_CRL_add_ext(self->crl, ext, -1))
    lose_no_memory();

  ok = 1;

 error:                         /* Fall through */
  ASN1_OBJECT_free(oid);
  ASN1_OCTET_STRING_free(octetString);
  X509_EXTENSION_free(ext);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char crl_object_clear_extensions__doc__[] =
  "This method clears all extensions attached to this CRL.\n"
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

static char crl_object_count_extensions__doc__[] =
  "This method returns the number of extensions attached to this CRL.\n"
  ;

static PyObject *
crl_object_count_extensions(crl_object *self)
{
  ENTERING(crl_object_count_extensions);
  return Py_BuildValue("i", X509_CRL_get_ext_count(self->crl));
}

static char crl_object_get_extension__doc__[] =
  "This method returns a tuple equivalent the parameters of the\n"
  "\"addExtension\" method, and suffers from similar limitations.\n"
  "\n"
  "The \"index\" parameter is the position in the extension list of\n"
  "the extension to be returned.\n"
  ;

static PyObject *
crl_object_get_extension(crl_object *self, PyObject *args)
{
  X509_EXTENSION *ext;
  char oid[512];
  int slot = 0;

  ENTERING(crl_object_get_extension);

  if (!PyArg_ParseTuple(args, "i", &slot))
    goto error;

  if ((ext = X509_CRL_get_ext(self->crl, slot)) == NULL)
    lose_openssl_error("Couldn't get extension");

  if (OBJ_obj2txt(oid, sizeof(oid), ext->object, 1) <= 0)
    lose_openssl_error("Couldn't translate OID");

  return Py_BuildValue("sNs#", oid,
                       PyBool_FromLong(ext->critical),
                       ASN1_STRING_data(ext->value),
                       ASN1_STRING_length(ext->value));

 error:
  return NULL;
}

static char crl_object_sign__doc__[] =
  "This method signs a CRL with a private key.\n"
  "\n"
  "The \"key\" parameter should be an instance of the Asymmetric class,\n"
  "containing a private key.\n"
  "\n"
  "The optional \"digest\" parameter indicates which digest to compute and\n"
  "sign, and should be one of the following:\n"
  "\n"
  "* MD5_DIGEST\n"
  "* SHA_DIGEST\n"
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
  "This method verifies the CRL's signature.\n"
  "The check is performed using OpenSSL's X509_CRL_verify() function.\n"
  "\n"
  "The \"key\" parameter should be an instance of the Asymmetric class\n"
  "containing the public key of the purported signer.\n"
  ;

static PyObject *
crl_object_verify(crl_object *self, PyObject *args)
{
  asymmetric_object *asym;

  ENTERING(crl_object_verify);

  if (!PyArg_ParseTuple(args, "O!", &POW_Asymmetric_Type, &asym))
    goto error;

  return PyBool_FromLong(X509_CRL_verify(self->crl, asym->pkey));

 error:
  return NULL;
}

static char crl_object_pem_write__doc__[] =
  "This method returns a PEM encoded CRL as a string.\n"
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
  "This method returns a DER encoded CRL as a string.\n"
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
  "This method returns the Authority Key Identifier (AKI) keyid value for\n"
  "this CRL, or None if the CRL has no AKI extension\n"
  "or has an AKI extension with no keyIdentifier value.\n"
  ;

static PyObject *
crl_object_get_aki(crl_object *self, PyObject *args)
{
  AUTHORITY_KEYID *ext = X509_CRL_get_ext_d2i(self->crl, NID_authority_key_identifier, NULL, NULL);
  int empty = (ext == NULL || ext->keyid == NULL);
  PyObject *result = NULL;

  ENTERING(crl_object_get_aki);

  if (!empty)
    result = Py_BuildValue("s#", ASN1_STRING_data(ext->keyid), ASN1_STRING_length(ext->keyid));

  AUTHORITY_KEYID_free(ext);

  if (empty)
    Py_RETURN_NONE;
  else
    return result;
}

static char crl_object_set_aki__doc__[] =
  "This method sets the Authority Key Identifier (AKI) value for this\n"
  "CRL.   We only support the keyIdentifier method, as that's\n"
  "the only form which is legal for RPKI certificates.\n"
  ;

static PyObject *
crl_object_set_aki(crl_object *self, PyObject *args)
{
  AUTHORITY_KEYID *ext = NULL;
  const unsigned char *buf = NULL;
  int len, ok = 0;

  ENTERING(crl_object_set_aki);

  if (!PyArg_ParseTuple(args, "s#", &buf, &len))
    goto error;

  if ((ext = AUTHORITY_KEYID_new()) == NULL ||
      (ext->keyid = ASN1_OCTET_STRING_new()) == NULL ||
      !ASN1_OCTET_STRING_set(ext->keyid, buf, len))
    lose_no_memory();

  if (!X509_CRL_add1_ext_i2d(self->crl, NID_authority_key_identifier,
                             ext, 0, X509V3_ADD_REPLACE))
    lose_openssl_error("Couldn't add AKI extension to CRL");

  ok = 1;

 error:
  AUTHORITY_KEYID_free(ext);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char crl_object_get_crl_number__doc__[] =
  "This method get the CRL Number extension value from this CRL.\n"
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
  "This method sets the CRL Number extension value in this CRL.\n"
  "\n"
  "The \"number\" parameter should ba an integer.\n"
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
  "This method returns a pretty-printed rendition of the CRL.\n"
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
  Define_Method(sign,                   crl_object_sign,                METH_VARARGS),
  Define_Method(verify,                 crl_object_verify,              METH_VARARGS),
  Define_Method(getVersion,             crl_object_get_version,         METH_NOARGS),
  Define_Method(setVersion,             crl_object_set_version,         METH_VARARGS),
  Define_Method(getIssuer,              crl_object_get_issuer,          METH_VARARGS),
  Define_Method(setIssuer,              crl_object_set_issuer,          METH_VARARGS),
  Define_Method(getThisUpdate,          crl_object_get_this_update,     METH_NOARGS),
  Define_Method(setThisUpdate,          crl_object_set_this_update,     METH_VARARGS),
  Define_Method(getNextUpdate,          crl_object_get_next_update,     METH_NOARGS),
  Define_Method(setNextUpdate,          crl_object_set_next_update,     METH_VARARGS),
  Define_Method(getRevoked,             crl_object_get_revoked,         METH_NOARGS),
  Define_Method(addRevocations,         crl_object_add_revocations,     METH_VARARGS),
  Define_Method(addExtension,           crl_object_add_extension,       METH_VARARGS),
  Define_Method(clearExtensions,        crl_object_clear_extensions,    METH_NOARGS),
  Define_Method(countExtensions,        crl_object_count_extensions,    METH_NOARGS),
  Define_Method(getExtension,           crl_object_get_extension,       METH_VARARGS),
  Define_Method(pemWrite,               crl_object_pem_write,           METH_NOARGS),
  Define_Method(derWrite,               crl_object_der_write,           METH_NOARGS),
  Define_Method(pprint,                 crl_object_pprint,              METH_NOARGS),
  Define_Method(getAKI,                 crl_object_get_aki,             METH_NOARGS),
  Define_Method(setAKI,                 crl_object_set_aki,             METH_VARARGS),
  Define_Method(getCRLNumber,           crl_object_get_crl_number,      METH_NOARGS),
  Define_Method(setCRLNumber,           crl_object_set_crl_number,      METH_VARARGS),
  Define_Class_Method(pemRead,          crl_object_pem_read,            METH_VARARGS),
  Define_Class_Method(pemReadFile,      crl_object_pem_read_file,       METH_VARARGS),
  Define_Class_Method(derRead,          crl_object_der_read,            METH_VARARGS),
  Define_Class_Method(derReadFile,      crl_object_der_read_file,       METH_VARARGS),
  {NULL}
};

static char POW_CRL_Type__doc__[] =
  "This class provides access to OpenSSL X509 CRL management facilities.\n"
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
asymmetric_object_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
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
  static char *kwlist[] = {"cipher", "key_size", NULL};
  int cipher_type = RSA_CIPHER, key_size = 2048;
  EVP_PKEY_CTX *ctx = NULL;
  int ok = 0;

  ENTERING(asymmetric_object_init);

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "|ii", kwlist, &cipher_type, &key_size))
    goto error;

  /*
   * This silliness is necessary until we move this to an RSA-specific class method.
   */
  if (cipher_type != RSA_CIPHER)
    lose("unsupported cipher");

  if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)) == NULL ||
      EVP_PKEY_keygen_init(ctx) <= 0 ||
      EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_size) <= 0)
    lose_openssl_error("Couldn't initialize EVP_PKEY_CTX");

  /*
   * Should set RSA_F4 for drill, although I think it's the default now.
   * Looks like the call is 
   *   int EVP_PKEY_CTX_set_rsa_keygen_pubexp(EVP_PKEY_CTX *ctx, BIGNUM *pubexp);
   * while RSA_F4 is a plain C long integer, so would need to make a bignum (sigh),
   * which is probably BN_new()/BN_set_word()/BN_free().
   */

  EVP_PKEY_free(self->pkey);
  self->pkey = NULL;

  if (EVP_PKEY_keygen(ctx, &self->pkey) <= 0)
    lose_openssl_error("Couldn't generate new RSA key");

  ok = 1;

 error:
  EVP_PKEY_CTX_free(ctx);

  if (ok)
    return 0;
  else
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
 */

static char asymmetric_object_pem_read_private__doc__[] =
  "Class method to read a PEM-encoded private key from a string.\n"
  "Optional second argument is a passphrase for the key.\n"
  ;

static PyObject *
asymmetric_object_pem_read_private(PyTypeObject *type, PyObject *args)
{
  PyObject *result = NULL;
  char *pass = NULL;
  char *src = NULL;
  BIO *bio = NULL;
  int len = 0;

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
  "Class method to read a PEM-encoded private key from a file.\n"
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

static PyObject *
asymmetric_object_der_read_private_helper(PyTypeObject *type, BIO *bio)
{
  asymmetric_object *self = NULL;

  ENTERING(asymmetric_object_der_read_private_helper);

  if ((self = (asymmetric_object *) asymmetric_object_new(&POW_Asymmetric_Type, NULL, NULL)) == NULL)
    goto error;

  if (!d2i_PrivateKey_bio(bio, &self->pkey))
    lose_openssl_error("Couldn't load private key");

  return (PyObject *) self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static char asymmetric_object_der_read_private__doc__[] =
  "Class method to read a DER-encoded private key from a string.\n"
  ;

static PyObject *
asymmetric_object_der_read_private(PyTypeObject *type, PyObject *args)
{
  ENTERING(asymmetric_object_der_read_private);
  return read_from_string_helper(asymmetric_object_der_read_private_helper, type, args);
}

static char asymmetric_object_der_read_private_file__doc__[] =
  "Class method to read a DER-encoded private key from a file.\n"
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

  if ((self = (asymmetric_object *) asymmetric_object_new(&POW_Asymmetric_Type, NULL, NULL)) == NULL)
    goto error;

  if (!PEM_read_bio_PUBKEY(bio, &self->pkey, NULL, NULL))
    lose_openssl_error("Couldn't load public key");

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

  if ((self = (asymmetric_object *) asymmetric_object_new(&POW_Asymmetric_Type, NULL, NULL)) == NULL)
    goto error;

  if (!d2i_PUBKEY_bio(bio, &self->pkey))
    lose_openssl_error("Couldn't load public key");

  return (PyObject *) self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static char asymmetric_object_pem_read_public__doc__[] =
  "Class method to read a PEM-encoded public key from a string.\n"
  ;

static PyObject *
asymmetric_object_pem_read_public(PyTypeObject *type, PyObject *args)
{
  ENTERING(asymmetric_object_pem_read_public);
  return read_from_string_helper(asymmetric_object_pem_read_public_helper, type, args);
}

static char asymmetric_object_pem_read_public_file__doc__[] =
  "Class method to read a PEM-encoded public key from a file.\n"
  ;

static PyObject *
asymmetric_object_pem_read_public_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(asymmetric_object_pem_read_public_file);
  return read_from_file_helper(asymmetric_object_pem_read_public_helper, type, args);
}

static char asymmetric_object_der_read_public__doc__[] =
  "Class method to read a DER-encoded public key from a string.\n"
  ;

static PyObject *
asymmetric_object_der_read_public(PyTypeObject *type, PyObject *args)
{
  ENTERING(asymmetric_object_der_read_public);
  return read_from_string_helper(asymmetric_object_der_read_public_helper, type, args);
}

static char asymmetric_object_der_read_public_file__doc__[] =
  "Class method to read a DER-encoded public key from a file.\n"
  ;

static PyObject *
asymmetric_object_der_read_public_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(asymmetric_object_der_read_public_file);
  return read_from_file_helper(asymmetric_object_der_read_public_helper, type, args);
}

static char asymmetric_object_pem_write_private__doc__[] =
  "This method writes an \"Asymmetric\" private key as a PEM string.\n"
  "\n"
  "This method takes an optional parameter \"passphrase\" which, if\n"
  "specified, will be used to encrypt the private key with AES-256-CBC.\n"
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
  "This method writes an \"Asymmetric\" public key as a PEM string.\n"
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
  "This method writes an \"Asymmetric\" private key as a DER string.\n"
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
  "This method writes an \"Asymmetric\" public key as a DER string.\n"
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

static char asymmetric_object_sign__doc__[] =
  "This method signs a digest of text to be protected.\n"
  "The Asymmetric object should be the  private key to be used for signing.\n"
  "\n"
  "The \"digesttext\" parameter should be a digest of the protected data.\n"
  "\n"
  "The \"digesttype\" parameter should be one of the following:\n"
  "\n"
  "  * MD5_DIGEST\n"
  "  * SHA_DIGEST\n"
  "  * SHA1_DIGEST\n"
  "  * SHA256_DIGEST\n"
  "  * SHA384_DIGEST\n"
  "  * SHA512_DIGEST\n"
  ;

static PyObject *
asymmetric_object_sign(asymmetric_object *self, PyObject *args)
{
  unsigned char *digest_text = NULL, *signed_text = NULL;
  unsigned int digest_type = 0;
  size_t signed_len = 0, digest_len = 0;
  EVP_PKEY_CTX *ctx = NULL;
  PyObject *result = NULL;

  ENTERING(asymmetric_object_sign);

  if (!PyArg_ParseTuple(args, "s#i", &digest_text, &digest_len, &digest_type))
    goto error;

  /*
   * If we need to find out what kind of public key this is, we can
   * use EVP_PKEY_asn1_get0_info() to get the pkey_id value, which
   * happens to map exactly to algorithm NIDs but conceptually is a
   * separate space.
   */

  if ((ctx = EVP_PKEY_CTX_new(self->pkey, NULL)) == NULL ||
      EVP_PKEY_sign_init(ctx) <= 0 ||
      EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
      EVP_PKEY_CTX_set_signature_md(ctx, evp_digest_factory(digest_type)) <= 0 ||
      EVP_PKEY_sign(ctx, NULL, &signed_len, digest_text, digest_len) <= 0)
    lose_openssl_error("Couldn't set up signing context");
  
  if ((signed_text = malloc(signed_len)) == NULL)
    lose_no_memory();

  if (EVP_PKEY_sign(ctx, signed_text, &signed_len, digest_text, digest_len) <= 0)
    lose_openssl_error("Couldn't sign digest");

  result = Py_BuildValue("s#", signed_text, signed_len);

 error:                         /* Fall through */
  EVP_PKEY_CTX_free(ctx);
  if (signed_text)
    free(signed_text);
  return result;
}

static char asymmetric_object_verify__doc__[] =
  "This method verifies a signed digest.  The Assymetric object should be\n"
  "the public key against which to verify the signature.\n"
  "\n"
  "The \"signedtext\" parameter should be the signed digest to verify.\n"
  "\n"
  "The \"digesttext\" parameter should be a digest of the same data used\n"
  "to produce signedtext.\n"
  "\n"
  "The \"digesttype\" parameter should be one of the following:\n"
  "\n"
  "  * MD5_DIGEST\n"
  "  * SHA_DIGEST\n"
  "  * SHA1_DIGEST\n"
  "  * SHA256_DIGEST\n"
  "  * SHA384_DIGEST\n"
  "  * SHA512_DIGEST\n"
  "\n"
  "This method returns a boolean value indicating whether the signature\n"
  "could be verified.\n"
  ;

static PyObject *
asymmetric_object_verify(asymmetric_object *self, PyObject *args)
{
  unsigned char *digest_text = NULL, *signed_text = NULL;
  int digest_type = 0, signed_len = 0, digest_len = 0;
  EVP_PKEY_CTX *ctx = NULL;
  int ok = 0, result;

  ENTERING(asymmetric_object_verify);

  if (!PyArg_ParseTuple(args, "s#s#i",
                        &signed_text, &signed_len,
                        &digest_text, &digest_len,
                        &digest_type))
    goto error;

  if ((ctx = EVP_PKEY_CTX_new(self->pkey, NULL)) == NULL ||
      EVP_PKEY_verify_init(ctx) <= 0 ||
      EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
      EVP_PKEY_CTX_set_signature_md(ctx, evp_digest_factory(digest_type)) <= 0)
    lose_openssl_error("Couldn't set up EVP_PKEY_CTX");

  if ((result = EVP_PKEY_verify(ctx, signed_text, signed_len, digest_text, digest_len)) < 0)
    lose_openssl_error("Unable to perform public key validation");

  ok = 1;

 error:
  EVP_PKEY_CTX_free(ctx);

  if (ok)
    return PyBool_FromLong(result);
  else
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

  ENTERING(asymmetric_object_calculate_ski);

  if (!X509_PUBKEY_set(&pubkey, self->pkey))
    lose_openssl_error("Couldn't extract public key");

  if (!EVP_Digest(pubkey->public_key->data, pubkey->public_key->length,
                  digest, &digest_length, EVP_sha1(), NULL))
    lose_openssl_error("Couldn't calculate SHA-1 digest of public key");

  result = PyString_FromStringAndSize(digest, digest_length);

 error:
  X509_PUBKEY_free(pubkey);
  return result;
}

static struct PyMethodDef asymmetric_object_methods[] = {
  Define_Method(pemWritePrivate,          asymmetric_object_pem_write_private,          METH_VARARGS),
  Define_Method(pemWritePublic,           asymmetric_object_pem_write_public,           METH_NOARGS),
  Define_Method(derWritePrivate,          asymmetric_object_der_write_private,          METH_NOARGS),
  Define_Method(derWritePublic,           asymmetric_object_der_write_public,           METH_NOARGS),
  Define_Method(sign,                     asymmetric_object_sign,                       METH_VARARGS),
  Define_Method(verify,                   asymmetric_object_verify,                     METH_VARARGS),
  Define_Method(calculateSKI,             asymmetric_object_calculate_ski,              METH_NOARGS),
  Define_Class_Method(pemReadPublic,      asymmetric_object_pem_read_public,            METH_VARARGS),
  Define_Class_Method(pemReadPublicFile,  asymmetric_object_pem_read_public_file,       METH_VARARGS),
  Define_Class_Method(derReadPublic,      asymmetric_object_der_read_public,            METH_VARARGS),
  Define_Class_Method(derReadPublicFile,  asymmetric_object_der_read_public_file,       METH_VARARGS),
  Define_Class_Method(pemReadPrivate,     asymmetric_object_pem_read_private,           METH_VARARGS),
  Define_Class_Method(pemReadPrivateFile, asymmetric_object_pem_read_private_file,      METH_VARARGS),
  Define_Class_Method(derReadPrivate,     asymmetric_object_der_read_private,           METH_VARARGS),
  Define_Class_Method(derReadPrivateFile, asymmetric_object_der_read_private_file,      METH_VARARGS),
  {NULL}
};

static char POW_Asymmetric_Type__doc__[] =
  "This class provides basic access to RSA signature and verification.\n"
  "\n"
  LAME_DISCLAIMER_IN_ALL_CLASS_DOCUMENTATION
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
 * Digest object.
 */

static PyObject *
digest_object_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
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
  "This method adds data to a digest.\n"
  "\n"
  "the \"data\" parameter should be a string containing the data to be added.\n"
  ;

static PyObject *
digest_object_update(digest_object *self, PyObject *args)
{
  char *data = NULL;
  int len = 0;

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
  "This method returns a copy of the Digest object.\n"
  ;

static PyObject *
digest_object_copy(digest_object *self, PyObject *args)
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
  "This method returns the digest of all the data which has been processed.\n"
  "This function can be called at any time and will not effect the internal\n"
  "structure of the Digest object.\n"
  ;

/*
 * Do we really need to do this copy?  Nice general operation, but does
 * anything we're doing for RPKI care?
 */

static PyObject *
digest_object_digest(digest_object *self)
{
  unsigned char digest_text[EVP_MAX_MD_SIZE];
  EVP_MD_CTX ctx;
  unsigned digest_len = 0;

  ENTERING(digest_object_digest);

  if (!EVP_MD_CTX_copy(&ctx, &self->digest_ctx))
    lose_openssl_error("Couldn't copy digest");

  EVP_DigestFinal(&ctx, digest_text, &digest_len);

  EVP_MD_CTX_cleanup(&ctx);

  return Py_BuildValue("s#", digest_text, digest_len);

 error:
  return NULL;
}

static struct PyMethodDef digest_object_methods[] = {
  Define_Method(update,         digest_object_update,   METH_VARARGS),
  Define_Method(digest,         digest_object_digest,   METH_NOARGS),
  Define_Method(copy,           digest_object_copy,     METH_VARARGS),
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
  "  * MD5_DIGEST\n"
  "  * SHA_DIGEST\n"
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
cms_object_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
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
  "Class method to read a PEM-encoded CMS object from a string.\n"
  ;

static PyObject *
cms_object_pem_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(cms_object_pem_read);
  return read_from_string_helper(cms_object_pem_read_helper, type, args);
}

static char cms_object_pem_read_file__doc__[] =
  "Class method to read a PEM-encoded CMS object from a file.\n"
  ;

static PyObject *
cms_object_pem_read_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(cms_object_pem_read_file);
  return read_from_file_helper(cms_object_pem_read_helper, type, args);
}

static char cms_object_der_read__doc__[] =
  "Class method to read a DER-encoded CMS object from a string.\n"
  ;

static PyObject *
cms_object_der_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(cms_object_der_read);
  return read_from_string_helper(cms_object_der_read_helper, type, args);
}

static char cms_object_der_read_file__doc__[] =
  "Class method to read a DER-encoded CMS object from a file.\n"
  ;

static PyObject *
cms_object_der_read_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(cms_object_der_read_file);
  return read_from_file_helper(cms_object_der_read_helper, type, args);
}

static char cms_object_pem_write__doc__[] =
  "This method returns a PEM encoded CMS message as a string.\n"
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
  "This method returns a DER encoded CMS message as a string.\n"
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
                       PyObject *x509_sequence,
                       PyObject *crl_sequence,
                       char *oid,
                       unsigned flags)                       
{
  crl_object *crlobj = NULL;
  STACK_OF(X509) *x509_stack = NULL;
  int i, n, ok = 0;
  CMS_ContentInfo *cms = NULL;
  ASN1_OBJECT *econtent_type = NULL;

  ENTERING(cms_object_sign_helper);

  assert_no_unhandled_openssl_errors();

  flags &= CMS_NOCERTS | CMS_NOATTR;
  flags |= CMS_BINARY | CMS_NOSMIMECAP | CMS_PARTIAL | CMS_USE_KEYID;

  if ((x509_stack = x509_helper_sequence_to_stack(x509_sequence)) == NULL)
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

  if (crl_sequence != Py_None) {

    if (!PySequence_Check(crl_sequence))
      lose_type_error("Inapropriate type");

    n = PySequence_Size(crl_sequence);

    for (i = 0; i < n; i++) {

      if ((crlobj = (crl_object *) PySequence_GetItem(crl_sequence, i)) == NULL)
        goto error;

      if (!POW_CRL_Check(crlobj))
        lose_type_error("Inappropriate type");

      if (!crlobj->crl)
        lose("CRL object with null CRL field!");

      if (!CMS_add1_crl(cms, crlobj->crl))
        lose_openssl_error("Couldn't add CRL to CMS");

      assert_no_unhandled_openssl_errors();

      Py_XDECREF(crlobj);
      crlobj = NULL;
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
  Py_XDECREF(crlobj);

  return ok;
}

static char cms_object_sign__doc__[] =
  "This method signs a message with a private key.\n"
  "\n"
  "The \"signcert\" parameter should be the certificate against which the\n"
  "message will eventually be verified, an X509 object.\n"
  "\n"
  "The \"key\" parameter should be the private key with which to sign the\n"
  "message, an Asymmetric object.\n"
  "\n"
  "The \"data\" parameter should be the message to be signed, a string.\n"
  "\n"
  "The optional \"certs\" parameter should be a sequence of X509 objects\n"
  "to be included in the signed message.\n"
  "\n"
  "The optional \"crls\" parameter should be a sequence of CRL objects\n"
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
  PyObject *x509_sequence = Py_None;
  PyObject *crl_sequence = Py_None;
  char *buf = NULL, *oid = NULL;
  int len;
  unsigned flags = 0;
  BIO *bio = NULL;
  int ok = 0;

  ENTERING(cms_object_sign);

  if (!PyArg_ParseTuple(args, "O!O!s#|OOsI",
                        &POW_X509_Type, &signcert,
                        &POW_Asymmetric_Type, &signkey,
                        &buf, &len,
                        &x509_sequence,
                        &crl_sequence,
                        &oid,
                        &flags))
    goto error;

  assert_no_unhandled_openssl_errors();

  if ((bio = BIO_new_mem_buf(buf, len)) == NULL)
    lose_no_memory();

  assert_no_unhandled_openssl_errors();

  if (!cms_object_sign_helper(self, bio, signcert, signkey,
                              x509_sequence, crl_sequence, oid, flags))
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

#warning Might want to convert flag bits here to keyword argument booleans

static BIO *
cms_object_verify_helper(cms_object *self, PyObject *args, PyObject *kwds)
{
  static char *kwlist[] = {"store", "certs", "flags", NULL};
  x509_store_object *store = NULL;
  PyObject *certs_sequence = Py_None;
  STACK_OF(X509) *certs_stack = NULL;
  unsigned flags = 0, ok = 0;
  BIO *bio = NULL;

  ENTERING(cms_object_verify_helper);

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "O!|OI", kwlist, &POW_X509Store_Type, &store, &certs_sequence, &flags))
    goto error;

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  assert_no_unhandled_openssl_errors();

  flags &= (CMS_NOINTERN | CMS_NOCRL | CMS_NO_SIGNER_CERT_VERIFY |
            CMS_NO_ATTR_VERIFY | CMS_NO_CONTENT_VERIFY);

  if (certs_sequence != Py_None &&
      (certs_stack = x509_helper_sequence_to_stack(certs_sequence)) == NULL)
    goto error;

  assert_no_unhandled_openssl_errors();

  if (CMS_verify(self->cms, certs_stack, store->store, NULL, bio, flags) <= 0)
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
  "This method verifies a message against a trusted store.\n"
  "\n"
  "The \"store\" parameter is an X509Store object, the trusted certificate\n"
  "store to use in verification.\n"
  "\n"
  "The optional \"certs\" parameter is a set of certificates to search\n"
  "for the signer's certificate.\n"
  "\n"
  "The optional \"flags\" parameter is an integer of bit flags,\n"
  "containing zero or more of the following:\n"
  "\n"
  "  * CMS_NOINTERN\n"
  "  * CMS_NOCRL\n"
  "  * CMS_NO_SIGNER_CERT_VERIFY\n"
  "  * CMS_NO_ATTR_VERIFY\n"
  "  * CMS_NO_CONTENT_VERIFY\n"
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

static char cms_object_eContentType__doc__[] =
  "This method returns the eContentType of a CMS message.\n"
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
  "This method returns the signingTime of a CMS message.\n"
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

  if (sk_ASN1_TYPE_num(xa->value.set) != 1)
    lose("Couldn't extract signerInfos from CMS message[6]");

  if ((so = sk_ASN1_TYPE_value(xa->value.set, 0)) == NULL)
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
  "This method returns a pretty-printed representation of a CMS message.\n"
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

static PyObject *
cms_object_helper_get_cert(void *cert)
{
  x509_object *obj;

  ENTERING(cms_object_helper_get_cert);

  if ((obj = (x509_object *) x509_object_new(&POW_X509_Type, NULL, NULL)) == NULL)
    return NULL;

  X509_free(obj->x509);
  obj->x509 = cert;
  return (PyObject *) obj;
}

static char cms_object_certs__doc__[] =
  "This method returns any certificates embedded in a CMS message, as a\n"
  "tuple of X509 objects.   This tuple will be empty if the message\n"
  "wrapper contains no certificates.\n"
  ;

static PyObject *
cms_object_certs(cms_object *self)
{
  STACK_OF(X509) *certs = NULL;
  PyObject *result = NULL;

  ENTERING(cms_object_certs);

  if ((certs = CMS_get1_certs(self->cms)) != NULL)
    result = stack_to_tuple_helper(CHECKED_PTR_OF(STACK_OF(X509), certs),
                                   cms_object_helper_get_cert);
  else if (!ERR_peek_error())
    result = Py_BuildValue("()");
  else
    lose_openssl_error("Couldn't extract certs from CMS message");

 error:                          /* fall through */
  sk_X509_pop_free(certs, X509_free);
  return result;
}

static PyObject *
cms_object_helper_get_crl(void *crl)
{
  crl_object *obj;

  ENTERING(cms_object_helper_get_crl);

  if ((obj = (crl_object *) crl_object_new(&POW_CRL_Type, NULL, NULL)) == NULL)
    return NULL;

  X509_CRL_free(obj->crl);
  obj->crl = crl;
  return (PyObject *) obj;
}

static char cms_object_crls__doc__[] =
  "This method returns any CRLs embedded in a CMS message, as a tuple of\n"
  "CRL objects.  This tuple will be empty if the message contains no CRLs.\n"
  ;

static PyObject *
cms_object_crls(cms_object *self)
{
  STACK_OF(X509_CRL) *crls = NULL;
  PyObject *result = NULL;

  ENTERING(cms_object_crls);

  if ((crls = CMS_get1_crls(self->cms)) != NULL)
    result = stack_to_tuple_helper(CHECKED_PTR_OF(STACK_OF(X509_CRL), crls),
                                   cms_object_helper_get_crl);
  else if (!ERR_peek_error())
    result = Py_BuildValue("()");
  else
    lose_openssl_error("Couldn't extract CRLs from CMS message");

 error:                          /* fall through */
  sk_X509_CRL_pop_free(crls, X509_CRL_free);
  return result;
}

static struct PyMethodDef cms_object_methods[] = {
  Define_Method(pemWrite,               cms_object_pem_write,           METH_NOARGS),
  Define_Method(derWrite,               cms_object_der_write,           METH_NOARGS),
  Define_Method(sign,                   cms_object_sign,                METH_VARARGS),
  Define_Method(verify,                 cms_object_verify,              METH_KEYWORDS),
  Define_Method(eContentType,           cms_object_eContentType,        METH_NOARGS),
  Define_Method(signingTime,            cms_object_signingTime,         METH_NOARGS),
  Define_Method(pprint,                 cms_object_pprint,              METH_NOARGS),
  Define_Method(certs,                  cms_object_certs,               METH_NOARGS),
  Define_Method(crls,                   cms_object_crls,                METH_NOARGS),
  Define_Class_Method(pemRead,          cms_object_pem_read,            METH_VARARGS),
  Define_Class_Method(pemReadFile,      cms_object_pem_read_file,       METH_VARARGS),
  Define_Class_Method(derRead,          cms_object_der_read,            METH_VARARGS),
  Define_Class_Method(derReadFile,      cms_object_der_read_file,       METH_VARARGS),
  {NULL}
};

static char POW_CMS_Type__doc__[] =
  "This class provides basic access OpenSSL's CMS functionality.\n"
  "At present this only handes signed objects, as those are the\n"
  "only kind of CMS objects used in RPKI.\n"
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
  "Needs doc.\n"
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
  "Class method to read a DER-encoded manifest object from a string.\n"
  ;

static PyObject *
manifest_object_der_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(manifest_object_der_read);
  return read_from_string_helper(manifest_object_der_read_helper, type, args);
}

static char manifest_object_der_read_file__doc__[] =
  "Class method to read a DER-encoded manifest object from a file.\n"
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
  "Class method to read a PEM-encoded manifest object from a string.\n"
  ;

static PyObject *
manifest_object_pem_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(manifest_object_pem_read);
  return read_from_string_helper(manifest_object_pem_read_helper, type, args);
}

static char manifest_object_pem_read_file__doc__[] =
  "Class method to read a PEM-encoded manifest object from a file.\n"
  ;

static PyObject *
manifest_object_pem_read_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(manifest_object_pem_read_file);
  return read_from_file_helper(manifest_object_pem_read_helper, type, args);
}

static char manifest_object_get_version__doc__[] =
  "This method returns the version number of this manifest.\n"
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
  "This method sets the version number of this manifest.\n"
  "\n"
  "The \"version\" parameter should be a non-negative integer.\n"
  "\n"
  "As of this writing, zero is both the default and the only defined version,\n"
  "so attempting to set any version number other than zero will fail, as we\n"
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
  "This method returns the manifest number of this manifest.\n"
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
  "This method sets the manifest number of this manifest.\n"
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
  "This method sets the manifest's \"thisUpdate\" value.\n"
  "\n"
  "The \"time\" parameter should be in the form of a GeneralizedTime string\n"
  "as restricted by RFC 5280.\n"
  ;

static PyObject *
manifest_object_set_this_update (manifest_object *self, PyObject *args)
{
  ASN1_TIME *t = NULL;
  char *s = NULL;

  ENTERING(manifest_object_set_this_update);

  if (!PyArg_ParseTuple(args, "s", &s))
    goto error;

  if (self->manifest == NULL)
    lose_not_verified("Can't set thisUpdate value of unverified manifest");

  if ((t = Python_to_ASN1_TIME(s, 0)) == NULL)
    lose("Couldn't convert thisUpdate string");

  ASN1_TIME_free(self->manifest->thisUpdate);
  self->manifest->thisUpdate = t;
  Py_RETURN_NONE;

 error:
  ASN1_TIME_free(t);
  return NULL;
}

static char manifest_object_get_this_update__doc__[] =
  "This method returns the manifest's \"thisUpdate\" value\n"
  "in the form of a GeneralizedTime string as restricted by RFC 5280.\n"
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
  "This method sets the manifest's \"nextUpdate\" value.\n"
  "\n"
  "The \"time\" parameter should be in the form of a GeneralizedTime string\n"
  "as restricted by RFC 5280.\n"
  ;

static PyObject *
manifest_object_set_next_update (manifest_object *self, PyObject *args)
{
  ASN1_TIME *t = NULL;
  char *s = NULL;

  ENTERING(manifest_object_set_next_update);

  if (!PyArg_ParseTuple(args, "s", &s))
    goto error;

  if (self->manifest == NULL)
    lose_not_verified("Can't set nextUpdate value of unverified manifest"); 

  if ((t = Python_to_ASN1_TIME(s, 0)) == NULL)
    lose("Couldn't parse nextUpdate string");

  ASN1_TIME_free(self->manifest->nextUpdate);
  self->manifest->nextUpdate = t;
  Py_RETURN_NONE;

 error:
  ASN1_TIME_free(t);
  return NULL;
}

static char manifest_object_get_next_update__doc__[] =
  "This method returns the manifest's \"nextUpdate\" value\n"
  "in the form of a GeneralizedTime string as restricted by RFC 5280.\n"
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
  "This method returns the manifest's fileHashAlg OID.\n"
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
  "This method sets the manifest's fileHashAlg OID.\n"
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
  "This method adds a collection of <filename, hash> pairs to this manifest.\n"
  "\n"
  "The \"iterable\" parameter should be an iterable object, each element\n"
  "of which is a two-element sequence; the first element of this sequence\n"
  "should be the filename (a text string), the second element should be the\n"
  "hash (a binary string).\n"
  ;

static PyObject *
manifest_object_add_files(manifest_object *self, PyObject *args)
{
  PyObject *iterable = NULL;
  PyObject *iterator = NULL;
  PyObject *item = NULL;
  FileAndHash *fah = NULL;
  char *file = NULL;
  char *hash = NULL;
  int filelen, hashlen, ok = 0;

  ENTERING(manifest_object_add_files);

  if (self->manifest == NULL)
    lose_not_verified("Can't add files to unverified manifest");

  if (!PyArg_ParseTuple(args, "O", &iterable) ||
      (iterator = PyObject_GetIter(iterable)) == NULL)
    goto error;

  while ((item = PyIter_Next(iterator)) != NULL) {

    if (!PyArg_ParseTuple(item, "s#s#", &file, &filelen, &hash, &hashlen))
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
    item = NULL;
  }

  ok = 1;

 error:
  Py_XDECREF(iterator);
  Py_XDECREF(item);
  FileAndHash_free(fah);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char manifest_object_get_files__doc__[] =
  "This method returns a tuple of <filename, hash> pairs representing the\n"
  "contents of this manifest.\n"
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

    if ((item = Py_BuildValue("(s#s#)",
                              ASN1_STRING_data(fah->file), ASN1_STRING_length(fah->file),
                              ASN1_STRING_data(fah->hash), ASN1_STRING_length(fah->hash))) == NULL)
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
  "Needs doc.\n"
  ;

static PyObject *
manifest_object_sign(manifest_object *self, PyObject *args)
{
  asymmetric_object *signkey = NULL;
  x509_object *signcert = NULL;
  PyObject *x509_sequence = Py_None;
  PyObject *crl_sequence = Py_None;
  char *oid = NULL;
  unsigned flags = 0;
  BIO *bio = NULL;
  int ok = 0;

  ENTERING(manifest_object_sign);

  if (!PyArg_ParseTuple(args, "O!O!|OOsI",
                        &POW_X509_Type, &signcert,
                        &POW_Asymmetric_Type, &signkey,
                        &x509_sequence,
                        &crl_sequence,
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
                              x509_sequence, crl_sequence, oid, flags))
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
  Define_Method(getVersion,             manifest_object_get_version,            METH_NOARGS),
  Define_Method(setVersion,             manifest_object_set_version,            METH_VARARGS),
  Define_Method(getManifestNumber,      manifest_object_get_manifest_number,    METH_NOARGS),
  Define_Method(setManifestNumber,      manifest_object_set_manifest_number,    METH_VARARGS),
  Define_Method(getThisUpdate,          manifest_object_get_this_update,        METH_NOARGS),
  Define_Method(setThisUpdate,          manifest_object_set_this_update,        METH_VARARGS),
  Define_Method(getNextUpdate,          manifest_object_get_next_update,        METH_NOARGS),
  Define_Method(setNextUpdate,          manifest_object_set_next_update,        METH_VARARGS),
  Define_Method(getAlgorithm,           manifest_object_get_algorithm,          METH_NOARGS),
  Define_Method(setAlgorithm,           manifest_object_set_algorithm,          METH_VARARGS),
  Define_Method(getFiles,               manifest_object_get_files,              METH_NOARGS),
  Define_Method(addFiles,               manifest_object_add_files,              METH_VARARGS),
  Define_Method(sign,                   manifest_object_sign,                   METH_VARARGS),
  Define_Method(verify,                 manifest_object_verify,                 METH_KEYWORDS),
  Define_Class_Method(pemRead,          manifest_object_pem_read,               METH_VARARGS),
  Define_Class_Method(pemReadFile,      manifest_object_pem_read_file,          METH_VARARGS),
  Define_Class_Method(derRead,          manifest_object_der_read,               METH_VARARGS),
  Define_Class_Method(derReadFile,      manifest_object_der_read_file,          METH_VARARGS),
  {NULL}
};

static char POW_Manifest_Type__doc__[] =
  "This class provides access to RPKI manifest payload.\n"
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
  "Needs doc.  For now, see CMS.verify().\n"
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
  "Class method to read a PEM-encoded ROA object from a string.\n"
  ;

static PyObject *
roa_object_pem_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(roa_object_pem_read);
  return read_from_string_helper(roa_object_pem_read_helper, type, args);
}

static char roa_object_pem_read_file__doc__[] =
  "Class method to read a PEM-encoded ROA object from a file.\n"
  ;

static PyObject *
roa_object_pem_read_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(roa_object_pem_read_file);
  return read_from_file_helper(roa_object_pem_read_helper, type, args);
}

static char roa_object_der_read__doc__[] =
  "Class method to read a DER-encoded ROA object from a string.\n"
  ;

static PyObject *
roa_object_der_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(roa_object_der_read);
  return read_from_string_helper(roa_object_der_read_helper, type, args);
}

static char roa_object_der_read_file__doc__[] =
  "Class method to read a DER-encoded ROA object from a file.\n"
  ;

static PyObject *
roa_object_der_read_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(roa_object_der_read_file);
  return read_from_file_helper(roa_object_der_read_helper, type, args);
}

static char roa_object_get_version__doc__[] =
  "This method returns the version number of this ROA.\n"
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
  "This method sets the version number of this ROA.\n"
  "\n"
  "The \"version\" parameter should be a non-negative integer.\n"
  "\n"
  "As of this writing, zero is both the default and the only defined version,\n"
  "so attempting to set any version number other than zero will fail, as we\n"
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
  "This method returns the Autonomous System ID of this ROA.\n"
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
  "This method sets the Autonomous System ID of this ROA.\n"
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
  "This method returns the ROA's prefix list.  This is a two-element\n"
  "tuple: the first element is the IPv4 prefix list, the second is the\n"
  "IPv6 prefix list.\n"
  "\n"
  "[Add more description here once final format is stable]\n"
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
    default:            lose_type_error("Unknown AFI");
    }

    if (fam->addressFamily->length > 2)
      lose_type_error("Unsupported SAFI");

    if (*resultp != NULL)
      lose_type_error("Duplicate ROAIPAddressFamily");

    if ((*resultp = PyTuple_New(sk_ROAIPAddress_num(fam->addresses))) == NULL)
      goto error;

    for (j = 0; j < sk_ROAIPAddress_num(fam->addresses); j++) {
      ROAIPAddress *a = sk_ROAIPAddress_value(fam->addresses, j);
      unsigned prefixlen = ((a->IPAddress)->length * 8 - ((a->IPAddress)->flags & 7));

      if ((addr = (ipaddress_object *) POW_IPAddress_Type.tp_alloc(&POW_IPAddress_Type, 0)) == NULL)
        goto error;

      addr->type = ip_type;

      memset(addr->address, 0, sizeof(addr->address));

      if (a->IPAddress->length > addr->type->length)
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
  "This method sets the ROA's prefix list.\n"
  "\n"
  "[Add description here once argument format is stable]\n"
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
  int ok = 0;
  int v;

  ENTERING(roa_object_set_prefixes);

  if (self->roa == NULL)
    lose_not_verified("Can't set prefixes of unverified ROA");

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "|OO", kwlist, &ipv4_arg, &ipv6_arg))
    goto error;

  if ((prefixes = sk_ROAIPAddressFamily_new_null()) == NULL)
    lose_no_memory();

  for (v = 0; v < sizeof(ipaddress_versions)/sizeof(*ipaddress_versions); v++) {
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

      if (!PyArg_ParseTuple(item, "O!I|O", &POW_IPAddress_Type, &addr, &prefixlen, &maxlenobj))
        goto error;

      if (maxlenobj == Py_None)
        maxprefixlen = prefixlen;
      else {
        maxprefixlen = (unsigned) PyInt_AsLong(maxlenobj);
        if (PyErr_Occurred())
          goto error;
      }

      if (addr->type != ip_type)
        lose_type_error("Bad ROA prefix");

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
      item = NULL;
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

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char roa_object_sign__doc__[] =
  "Needs doc.  For now, see CMS.sign.\n"
  ;

static PyObject *
roa_object_sign(roa_object *self, PyObject *args)
{
  asymmetric_object *signkey = NULL;
  x509_object *signcert = NULL;
  PyObject *x509_sequence = Py_None;
  PyObject *crl_sequence = Py_None;
  char *oid = NULL;
  unsigned flags = 0;
  BIO *bio = NULL;
  int ok = 0;

  ENTERING(roa_object_sign);

  if (!PyArg_ParseTuple(args, "O!O!|OOsI",
                        &POW_X509_Type, &signcert,
                        &POW_Asymmetric_Type, &signkey,
                        &x509_sequence,
                        &crl_sequence,
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
                              x509_sequence, crl_sequence, oid, flags))
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
  Define_Method(getVersion,             roa_object_get_version,         METH_NOARGS),
  Define_Method(setVersion,             roa_object_set_version,         METH_VARARGS),
  Define_Method(getASID,                roa_object_get_asid,            METH_NOARGS),
  Define_Method(setASID,                roa_object_set_asid,            METH_VARARGS),
  Define_Method(getPrefixes,            roa_object_get_prefixes,        METH_NOARGS),
  Define_Method(setPrefixes,            roa_object_set_prefixes,        METH_KEYWORDS),
  Define_Method(sign,                   roa_object_sign,                METH_VARARGS),
  Define_Method(verify,                 roa_object_verify,              METH_KEYWORDS),
  Define_Class_Method(pemRead,          roa_object_pem_read,            METH_VARARGS),
  Define_Class_Method(pemReadFile,      roa_object_pem_read_file,       METH_VARARGS),
  Define_Class_Method(derRead,          roa_object_der_read,            METH_VARARGS),
  Define_Class_Method(derReadFile,      roa_object_der_read_file,       METH_VARARGS),
  {NULL}
};

static char POW_ROA_Type__doc__[] =
  "This class provides access to RPKI roa payload.\n"
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
pkcs10_object_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
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
  "Class method to read a PEM-encoded PKCS#10 object from a string.\n"
  ;

static PyObject *
pkcs10_object_pem_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(pkcs10_object_pem_read);
  return read_from_string_helper(pkcs10_object_pem_read_helper, type, args);
}

static char pkcs10_object_pem_read_file__doc__[] =
  "Class method to read a PEM-encoded PKCS#10 object from a file.\n"
  ;

static PyObject *
pkcs10_object_pem_read_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(pkcs10_object_pem_read_file);
  return read_from_file_helper(pkcs10_object_pem_read_helper, type, args);
}

static char pkcs10_object_der_read__doc__[] =
  "Class method to read a DER-encoded PKCS#10 object from a string.\n"
  ;

static PyObject *
pkcs10_object_der_read(PyTypeObject *type, PyObject *args)
{
  ENTERING(pkcs10_object_der_read);
  return read_from_string_helper(pkcs10_object_der_read_helper, type, args);
}

static char pkcs10_object_der_read_file__doc__[] =
  "Class method to read a DER-encoded PKCS#10 object from a file.\n"
  ;

static PyObject *
pkcs10_object_der_read_file(PyTypeObject *type, PyObject *args)
{
  ENTERING(pkcs10_object_der_read_file);
  return read_from_file_helper(pkcs10_object_der_read_helper, type, args);
}

static char pkcs10_object_pem_write__doc__[] =
  "This method returns a PEM-encoded PKCS#10 object as a string.\n"
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
  "This method returns a DER-encoded PKCS#10 object as a string.\n"
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

static char pkcs10_object_get_public_key__doc__[] =
  "This method gets the public key for this PKCS#10 request.\n"
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

  return (PyObject *) asym;

 error:
  Py_XDECREF(asym);
  return NULL;
}

static char pkcs10_object_set_public_key__doc__[] =
  "This method sets the public key for this PKCS#10 request.\n"
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
  "This method signs a PKCS#10 request with a private key.\n"
  "\n"
  "The \"key\" parameter should be an instance of the Asymmetric class,\n"
  "containing a private key.\n"
  "\n"
  "The optional \"digest\" parameter indicates which digest to compute and\n"
  "sign, and should be one of the following:\n"
  "\n"
  "* MD5_DIGEST\n"
  "* SHA_DIGEST\n"
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
  "This method returns the version number from the version field of this PKCS#10 request.\n"
  ;

static PyObject *
pkcs10_object_get_version(pkcs10_object *self)
{
  ENTERING(pkcs10_object_get_version);
  return Py_BuildValue("l", X509_REQ_get_version(self->pkcs10));
}

static char pkcs10_object_set_version__doc__[] =
  "This method sets the version number in the version field of this PKCS#10 request.\n"
  "The \"version\" parameter should be an integer, but the only value is zero, so\n"
  "this field is optional and defaults to zero.\n"
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
  "This method returns a tuple containing the subject's name.  See\n"
  "the X509.getIssuer() method for details of the return value\n"
  "and use of the optional \"format\" parameter.\n"
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
  "This method is used to set the PKCS#10 request's subject name.\n"
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
    lose_type_error("Inapropriate type");

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
  "This method returns a FrozenSet of strings representing the KeyUsage\n"
  "settings for this PKCS#10 request, or None if the request has no\n"
  "KeyUsage extension.  The bits have the same names as in RFC 5280.\n"
  ;

static PyObject *
pkcs10_object_get_key_usage(pkcs10_object *self)
{
  extern X509V3_EXT_METHOD v3_key_usage;
  BIT_STRING_BITNAME *bit_name;
  ASN1_BIT_STRING *ext = NULL;
  PyObject *result = NULL;
  PyObject *token = NULL;

  ENTERING(pkcs10_object_get_key_usage);

  if ((ext = X509V3_get_d2i(self->exts, NID_key_usage, NULL, NULL)) == NULL)
    Py_RETURN_NONE;

  if ((result = PyFrozenSet_New(NULL)) == NULL)
    goto error;

  for (bit_name = v3_key_usage.usr_data; bit_name->sname != NULL; bit_name++) {
    if (ASN1_BIT_STRING_get_bit(ext, bit_name->bitnum) &&
        ((token = PyString_FromString(bit_name->sname)) == NULL ||
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

static char pkcs10_object_set_key_usage__doc__[] =
  "This method sets the KeyUsage extension  for this PKCS#10 request.\n"
  "\n"
  "Argument \"iterable\" should be an iterable object which returns zero or more\n"
  "strings naming bits to be enabled.  The bits have the same names as in RFC 5280.\n"
  "\n"
  "Optional argument \"critical\" is a boolean indicating whether the extension\n"
  "should be marked as critical or not.  RFC 5280 4.2.1.3 says this extension SHOULD\n"
  "be marked as critical when used, so the default is True.\n"
  ;

static PyObject *
pkcs10_object_set_key_usage(pkcs10_object *self, PyObject *args)
{
  extern X509V3_EXT_METHOD v3_key_usage;
  BIT_STRING_BITNAME *bit_name;
  ASN1_BIT_STRING *ext = NULL;
  PyObject *iterable = NULL;
  PyObject *critical = Py_True;
  PyObject *iterator = NULL;
  PyObject *token = NULL;
  const char *t;
  int ok = 0;

  ENTERING(pkcs10_object_set_key_usage);

  if ((ext = ASN1_BIT_STRING_new()) == NULL)
    lose_no_memory();

  if (!PyArg_ParseTuple(args, "O|O", &iterable, &critical) ||
      (iterator = PyObject_GetIter(iterable)) == NULL)
    goto error;

  while ((token = PyIter_Next(iterator)) != NULL) {

    if ((t = PyString_AsString(token)) == NULL)
      goto error;

    for (bit_name = v3_key_usage.usr_data; bit_name->sname != NULL; bit_name++)
      if (!strcmp(t, bit_name->sname))
        break;

    if (bit_name->sname == NULL)
      lose("Unrecognized KeyUsage token");

    if (!ASN1_BIT_STRING_set_bit(ext, bit_name->bitnum, 1))
      lose_no_memory();

    Py_XDECREF(token);
    token = NULL;
  }

  if (!X509V3_add1_i2d(&self->exts, NID_key_usage, ext,
                       PyObject_IsTrue(critical),
                       X509V3_ADD_REPLACE))
    lose_openssl_error("Couldn't add KeyUsage extension to certificate");

  ok = 1;

 error:                         /* Fall through */
  ASN1_BIT_STRING_free(ext);
  Py_XDECREF(iterator);
  Py_XDECREF(token);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char pkcs10_object_get_basic_constraints__doc__[] =
  "Get BasicConstraints value for this PKCS#10 request.  If the request\n"
  "has no BasicConstraints extension, this method returns None.\n"
  "Otherwise, it returns a two-element tuple.  The first element of the\n"
  "tuple is a boolean representing the extension's cA value; the second\n"
  "element of the tuple is either an integer representing the\n"
  "pathLenConstraint value or None if there is no pathLenConstraint.\n"
  ;

static PyObject *
pkcs10_object_get_basic_constraints(pkcs10_object *self)
{
  BASIC_CONSTRAINTS *ext = NULL;
  PyObject *result;

  ENTERING(pkcs10_object_get_basic_constraints);

  if ((ext = X509V3_get_d2i(self->exts, NID_basic_constraints, NULL, NULL)) == NULL)
    Py_RETURN_NONE;

  if (ext->pathlen == NULL)
    result = Py_BuildValue("(NO)", PyBool_FromLong(ext->ca), Py_None);
  else
    result = Py_BuildValue("(Nl)", PyBool_FromLong(ext->ca), ASN1_INTEGER_get(ext->pathlen));

  BASIC_CONSTRAINTS_free(ext);
  return result;
}

static char pkcs10_object_set_basic_constraints__doc__[] =
  "Set BasicConstraints value for this PKCS#10 request.\n"
  "\n"
  "First argument \"ca\" is a boolean indicating whether the request\n"
  "is for a CA certificate or not.\n"
  "\n"
  "Optional second argument \"pathLenConstraint\" is a non-negative integer\n"
  "specifying the pathLenConstraint value for this certificate; this value\n"
  "may only be set for CA certificates."
  "\n"
  "Optional third argument \"critical\" specifies whether the extension\n"
  "should be marked as critical.  RFC 5280 4.2.1.9 requires that CA\n"
  "certificates mark this extension as critical, so the default is True.\n"
  ;

static PyObject *
pkcs10_object_set_basic_constraints(pkcs10_object *self, PyObject *args)
{
  BASIC_CONSTRAINTS *ext = NULL;
  PyObject *is_ca = NULL;
  PyObject *pathlen_obj = Py_None;
  PyObject *critical = Py_True;
  long pathlen = -1;
  int ok = 0;

  ENTERING(pkcs10_object_set_basic_constraints);

  if (!PyArg_ParseTuple(args, "O|OO", &is_ca, &pathlen_obj, &critical))
    goto error;

  if (pathlen_obj != Py_None && (pathlen = PyInt_AsLong(pathlen_obj)) < 0)
    lose_type_error("Bad pathLenConstraint value");

  if ((ext = BASIC_CONSTRAINTS_new()) == NULL)
    lose_no_memory();

  ext->ca = PyObject_IsTrue(is_ca) ? 0xFF : 0;

  if (pathlen_obj != Py_None &&
      ((ext->pathlen == NULL && (ext->pathlen = ASN1_INTEGER_new()) == NULL) ||
       !ASN1_INTEGER_set(ext->pathlen, pathlen)))
    lose_no_memory();

  if (!X509V3_add1_i2d(&self->exts, NID_basic_constraints, ext,
                       PyObject_IsTrue(critical), X509V3_ADD_REPLACE))
    lose_openssl_error("Couldn't add BasicConstraints extension to certificate");

  ok = 1;

 error:
  BASIC_CONSTRAINTS_free(ext);

  if (ok)
    Py_RETURN_NONE;
  else
    return NULL;
}

static char pkcs10_object_get_sia__doc__[] =
  "Get SIA values for this PKCS#10 request.  If the request\n"
  "has no SIA extension, this method returns None.\n"
  "Otherwise, it returns a tuple containing three sequences:\n"
  "caRepository URIs, rpkiManifest URIs, and signedObject URIs.\n"
  "Any other accessMethods are ignored, as are any non-URI\n"
  "accessLocations.\n"
  ;

static PyObject *
pkcs10_object_get_sia(pkcs10_object *self)
{
  AUTHORITY_INFO_ACCESS *ext = NULL;
  PyObject *result = NULL;
  PyObject *result_caRepository = NULL;
  PyObject *result_rpkiManifest = NULL;
  PyObject *result_signedObject = NULL;
  int n_caRepository = 0;
  int n_rpkiManifest = 0;
  int n_signedObject = 0;
  const char *uri;
  PyObject *obj;
  int i, nid;

  ENTERING(pkcs10_object_get_sia);

  if ((ext = X509V3_get_d2i(self->exts, NID_sinfo_access, NULL, NULL)) == NULL)
    Py_RETURN_NONE;

  /*
   * Easiest to do this in two passes, first pass just counts URIs.
   */

  for (i = 0; i < sk_ACCESS_DESCRIPTION_num(ext); i++) {
    ACCESS_DESCRIPTION *a = sk_ACCESS_DESCRIPTION_value(ext, i);
    if (a->location->type != GEN_URI)
      continue;
    nid = OBJ_obj2nid(a->method);
    if (nid == NID_caRepository) {
      n_caRepository++;
      continue;
    }
    if (nid == NID_rpkiManifest) {
      n_rpkiManifest++;
      continue;
    }
    if (nid == NID_signedObject) {
      n_signedObject++;
      continue;
    }
  }

  if (((result_caRepository = PyTuple_New(n_caRepository)) == NULL) ||
      ((result_rpkiManifest = PyTuple_New(n_rpkiManifest)) == NULL) ||
      ((result_signedObject = PyTuple_New(n_signedObject)) == NULL))
    goto error;

  n_caRepository = n_rpkiManifest = n_signedObject = 0;

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
    if (nid == NID_rpkiManifest) {
      if ((obj = PyString_FromString(uri)) == NULL)
        goto error;
      PyTuple_SET_ITEM(result_rpkiManifest, n_rpkiManifest++, obj);
      continue;
    }
    if (nid == NID_signedObject) {
      if ((obj = PyString_FromString(uri)) == NULL)
        goto error;
      PyTuple_SET_ITEM(result_signedObject, n_signedObject++, obj);
      continue;
    }
  }

  result = Py_BuildValue("(OOO)",
                         result_caRepository,
                         result_rpkiManifest,
                         result_signedObject);

 error:
  AUTHORITY_INFO_ACCESS_free(ext);
  Py_XDECREF(result_caRepository);
  Py_XDECREF(result_rpkiManifest);
  Py_XDECREF(result_signedObject);
  return result;
}

static char pkcs10_object_set_sia__doc__[] =
  "Set SIA values for this PKCS#10 request.  Takes three arguments:\n"
  "caRepository URIs, rpkiManifest URIs, and signedObject URIs.\n"
  "Each of these should be an iterable which returns URIs.\n"
  "None is acceptable as an alternate way of specifying an empty\n"
  "sequence of URIs for a particular argument.\n"
  ;

static PyObject *
pkcs10_object_set_sia(pkcs10_object *self, PyObject *args)
{
  AUTHORITY_INFO_ACCESS *ext = NULL;
  PyObject *caRepository = NULL;
  PyObject *rpkiManifest = NULL;
  PyObject *signedObject = NULL;
  PyObject *iterator = NULL;
  ASN1_OBJECT *oid = NULL;
  PyObject **pobj = NULL;
  PyObject *item = NULL;
  ACCESS_DESCRIPTION *a = NULL;
  int i, nid = NID_undef, ok = 0;
  Py_ssize_t urilen;
  char *uri;

  ENTERING(pkcs10_object_set_sia);

  if (!PyArg_ParseTuple(args, "OOO", &caRepository, &rpkiManifest, &signedObject))
    goto error;

  if ((ext = AUTHORITY_INFO_ACCESS_new()) == NULL)
    lose_no_memory();

  /*
   * This is going to want refactoring, because it's ugly, because we
   * want to reuse code for AIA, and because it'd be nice to support a
   * single URI as an abbreviation for a sequence containing one URI.
   */

  for (i = 0; i < 3; i++) {
    switch (i) {
    case 0: pobj = &caRepository; nid = NID_caRepository; break;
    case 1: pobj = &rpkiManifest; nid = NID_rpkiManifest; break;
    case 2: pobj = &signedObject; nid = NID_signedObject; break;
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
  }

  if (!X509V3_add1_i2d(&self->exts, NID_sinfo_access, ext, 0, X509V3_ADD_REPLACE))
    lose_openssl_error("Couldn't add SIA extension to certificate");

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

static char pkcs10_object_get_signature_algorithm__doc__[] =
  "Extract signature algorithm OID from this request.\n"
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
  "Get the set of extension OIDs used in this request.  This is mostly\n"
  "useful for enforcing restrictions on what extensions are allowed to be\n"
  "present, to conform with a profile.\n"
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
    if ((oid = ASN1_OBJECT_to_PyString(ext->object)) == NULL ||
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

/*
 * May want EKU handlers eventually, skip for now.
 */

static char pkcs10_object_pprint__doc__[] =
  "This method returns a pretty-printed rendition of the PKCS#10 request.\n"
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
  Define_Method(getBasicConstraints,    pkcs10_object_get_basic_constraints,    METH_NOARGS),
  Define_Method(setBasicConstraints,    pkcs10_object_set_basic_constraints,    METH_VARARGS),
  Define_Method(getSIA,                 pkcs10_object_get_sia,                  METH_NOARGS),
  Define_Method(setSIA,                 pkcs10_object_set_sia,                  METH_VARARGS),
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
  "\n"
  LAME_DISCLAIMER_IN_ALL_CLASS_DOCUMENTATION
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
  "This function dynamically adds new a new object identifier to OpenSSL's\n"
  "internal database.\n"
  "\n"
  "The \"oid\" should be an ASN.1 object identifer, represented as a string\n"
  "in dotted-decimal format.\n"
  "\n"
  "The \"shortName\" parameter should be the OpenSSL \"short name\" to use.\n"
  "\n"
  "The \"longName\" parameter should be the OpenSSL \"long name\" to use.\n"
  ;

static PyObject *
pow_module_add_object(PyObject *self, PyObject *args)
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
  "Pops one error off OpenSSL's global error stack and returns it as a string.\n"
  "Returns None if the error stack is empty.\n"
  ;

static PyObject *
pow_module_get_error(PyObject *self)
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
pow_module_clear_error(PyObject *self)
{
  ENTERING(pow_module_clear_error);
  ERR_clear_error();
  Py_RETURN_NONE;
}

static char pow_module_seed__doc__[] =
  "Add data to OpenSSL's pseudo-random number generator state.\n"
  "\n"
  "The \"data\" parameter is the seed to add.  Entropy of the data is\n"
  "assumed to be equal to the length of the data.\n"
  ;

static PyObject *
pow_module_seed(PyObject *self, PyObject *args)
{
  char *data = NULL;
  int datalen = 0;

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
pow_module_add(PyObject *self, PyObject *args)
{
  char *data = NULL;
  int datalen = 0;
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
  "This function writes the current state of OpenSSL's pseduo-random\n"
  "number generator to a file.\n"
  "\n"
  "The \"filename\" parameter is the name of the file to write.\n"
  ;

static PyObject *
pow_module_write_random_file(PyObject *self, PyObject *args)
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
  "This function restores the state of OpenSSLs pseudo-random number\n"
  "generator from state previously saved to a file.\n"
  "\n"
  "The \"filename\" parameter is the name of the file to read.\n"
  ;

static PyObject *
pow_module_read_random_file(PyObject *self, PyObject *args)
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

static struct PyMethodDef pow_module_methods[] = {
  Define_Method(getError,       pow_module_get_error,           METH_NOARGS),
  Define_Method(clearError,     pow_module_clear_error,         METH_NOARGS),
  Define_Method(seed,           pow_module_seed,                METH_VARARGS),
  Define_Method(add,            pow_module_add,                 METH_VARARGS),
  Define_Method(readRandomFile, pow_module_read_random_file,    METH_VARARGS),
  Define_Method(writeRandomFile, pow_module_write_random_file,  METH_VARARGS),
  Define_Method(addObject,      pow_module_add_object,          METH_VARARGS),
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

#define Define_Class(__type__)                                          \
  do {                                                                  \
    char *__name__ = strrchr(__type__.tp_name, '.');                    \
    if (PyType_Ready(&__type__) == 0 && __name__ != NULL) {             \
      Py_INCREF(&__type__);                                             \
      PyModule_AddObject(m, __name__+1, (PyObject *) &__type__);        \
    }                                                                   \
  } while (0)

  Define_Class(POW_X509_Type);
  Define_Class(POW_X509Store_Type);
  Define_Class(POW_CRL_Type);
  Define_Class(POW_Asymmetric_Type);
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

#undef Define_Exception

#define Define_Integer_Constant(__name__) \
  PyModule_AddIntConstant(m, #__name__, __name__)

  /* Object format types */
  Define_Integer_Constant(LONGNAME_FORMAT);
  Define_Integer_Constant(SHORTNAME_FORMAT);
  Define_Integer_Constant(OIDNAME_FORMAT);

  /* Asymmetric ciphers */
  Define_Integer_Constant(RSA_CIPHER);

  /* Message digests */
  Define_Integer_Constant(MD5_DIGEST);
  Define_Integer_Constant(SHA_DIGEST);
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

  if (PyErr_Occurred() || !OpenSSL_ok)
    Py_FatalError("Can't initialize module POW");
}

/*
 * Local Variables:
 * indent-tabs-mode: nil
 * End:
 */
