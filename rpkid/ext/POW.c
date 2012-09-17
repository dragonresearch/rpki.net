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

#define	ENABLE_X509_CERTIFICATE_SIGNATURE_AND_VERIFICATION	0	

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

#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/*
 * Maximum size of a raw IP (v4 or v6) address, in bytes.
 */
#define RAW_IPADDR_BUFLEN    16

/*
 * Maximum size of a raw autonomous system number, in bytes.
 */
#define	RAW_ASNUMBER_BUFLEN   4

/* PEM encoded data types */
#define RSA_PUBLIC_KEY        1
#define RSA_PRIVATE_KEY       2
#define DSA_PUBLIC_KEY        3
#define DSA_PRIVATE_KEY       4
#define DH_PUBLIC_KEY         5
#define DH_PRIVATE_KEY        6
#define X509_CERTIFICATE      7
#define X_X509_CRL            8     /* X509_CRL already used by OpenSSL library */
#define CMS_MESSAGE           9

/* Asymmetric ciphers */
#define RSA_CIPHER            1
#define DSA_CIPHER            2
#define DH_CIPHER             3

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
#define POW_X509_Check(op)         PyObject_TypeCheck(op, &x509type)
#define POW_X509_Store_Check(op)   PyObject_TypeCheck(op, &x509_storetype)
#define POW_X509_CRL_Check(op)     PyObject_TypeCheck(op, &x509_crltype)
#define POW_Asymmetric_Check(op)   PyObject_TypeCheck(op, &asymmetrictype)
#define POW_Digest_Check(op)       PyObject_TypeCheck(op, &digesttype)
#define POW_CMS_Check(op)          PyObject_TypeCheck(op, &cmstype)
#define	POW_IPAddress_Check(op)    PyObject_TypeCheck(op, &ipaddresstype)

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

/*========== Pre-definitions ==========*/
static PyObject
  *ErrorObject,
  *OpenSSLErrorObject,
  *POWErrorObject;

static PyTypeObject
  x509type,
  x509_storetype,
  x509_crltype,
  asymmetrictype,
  digesttype,
  cmstype,
  ipaddresstype;

/*========== Pre-definitions ==========*/

/*========== C structs ==========*/

typedef struct {
  PyObject_HEAD
  unsigned char address[16];
  unsigned char version;
  unsigned char length;
  unsigned short af;
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
} x509_crl_object;

typedef struct {
  PyObject_HEAD
  void *cipher;
  int key_type;
  int cipher_type;
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

/*========== C structs ==========*/

/*========== helper functions ==========*/

/*
 * Minimal intervention debug-by-printf() hack, use only for good.
 */

#if 0
#define KVETCH(_msg_)   write(2, _msg_ "\n", sizeof(_msg_))
#else
#define KVETCH(_msg_)
#endif

/*
 * Error handling macros.  These macros make two assumptions:
 *
 * 1) All the macros assume that there's a cleanup label named
 *    "error" which these macros can use as a goto target.
 *
 * 2) assert_no_unhandled_openssl_errors() assumes that the return
 *    value is stored in a PyObject* variable named "result".
 *
 * These are icky assumptions, but they make it easier to provide
 * uniform error handling and make the code easier to read, not to
 * mention making it easier to track down obscure OpenSSL errors.
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

#define assert_no_unhandled_openssl_errors()                            \
  do {                                                                  \
    if (ERR_peek_error()) {                                             \
      if (result) {                                                     \
        Py_XDECREF(result);                                             \
        result = NULL;                                                  \
      }                                                                 \
      lose_openssl_error(assert_helper(__LINE__));                      \
    }                                                                   \
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

static int
evp_digest_nid(int digest_type)
{
  switch (digest_type) {
  case MD5_DIGEST:      return NID_md5;
  case SHA_DIGEST:      return NID_sha;
  case SHA1_DIGEST:     return NID_sha1;
  case SHA256_DIGEST:   return NID_sha256;
  case SHA384_DIGEST:   return NID_sha384;
  case SHA512_DIGEST:   return NID_sha512;
  default:              return NID_undef;
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

      if ((asn1_type = ASN1_PRINTABLE_type(value_str, -1)) != V_ASN1_PRINTABLESTRING)
        asn1_type = V_ASN1_UTF8STRING;

      if (!X509_NAME_add_entry_by_txt(name, type_str, asn1_type,
                                      value_str, strlen(value_str),
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
        lose("Couldn't translate OID");
      oid = oidbuf;
    }

    if (entry->set > set) {

      set++;
      if ((item = Py_BuildValue("((ss#))", oid, entry->value->data, entry->value->length)) == NULL)
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
      if ((item = Py_BuildValue("(ss#)", oid, entry->value->data, entry->value->length)) == NULL)
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
  ASN1_GENERALIZEDTIME *g = ASN1_TIME_to_generalizedtime(t, NULL);
  PyObject *result = NULL;
  if (g) {
    result = Py_BuildValue("s", g->data);
    ASN1_GENERALIZEDTIME_free(g);
  }
  return result;
}

static ASN1_TIME *
Python_to_ASN1_TIME(const char *s)
{
  ASN1_TIME *t = NULL;
  int ok;

  if (s == NULL || strlen(s) < 10 || (t = ASN1_TIME_new()) == NULL)
    return NULL;

  if ((s[0] == '1' && s[1] == '9' && s[2] > '4') ||
      (s[0] == '2' && s[1] == '0' && s[2] < '5'))
    ok = ASN1_UTCTIME_set_string(t, s + 2);
  else
    ok = ASN1_GENERALIZEDTIME_set_string(t, s);

  if (ok)
    return t;

  ASN1_TIME_free(t);
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

/*
 * Simplify entries in method definition tables.  See the "Common
 * Object Structures" section of the API manual for available flags.
 */
#define Define_Method(__python_name__, __c_name__, __flags__) \
  { #__python_name__, (PyCFunction) __c_name__, __flags__, __c_name__##__doc__ }

/*
 * Convert a Python long to an ASN1_INTEGER.
 * Do not read after eating.
 */
static ASN1_INTEGER *
Python_Long_to_ASN1_INTEGER(PyObject *arg)
{
  PyObject *obj = NULL;
  ASN1_INTEGER *a = NULL;
  unsigned char buf[RAW_ASNUMBER_BUFLEN];
  unsigned char *b = buf;
  size_t len;

  memset(buf, 0, sizeof(buf));

  if ((obj = PyNumber_Long(arg)) == NULL ||
      _PyLong_AsByteArray((PyLongObject *) obj, buf, sizeof(buf), 0, 0) < 0)
    goto error;

  Py_XDECREF(obj);
  obj = NULL;

  while (b < buf + sizeof(buf) - 1 && *b == 0)
    b++;
  len = buf + sizeof(buf) - b;

  if ((a = ASN1_INTEGER_new()) == NULL ||
      (a->length < len + 1 &&
       (a->data = OPENSSL_realloc(a->data, len + 1)) == NULL))
    lose_no_memory();

  a->type = V_ASN1_INTEGER;
  a->length = len;
  a->data[len] = 0;

  memcpy(a->data, b, len);

  return a;

 error:
  Py_XDECREF(obj);
  ASN1_INTEGER_free(a);
  return NULL;
}

/*========== helper functions ==========*/

/*========== IPAddress code ==========*/

static PyObject *
ipaddress_object_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  static char *kwlist[] = {"initializer", "version", NULL};
  ipaddress_object *self = NULL;
  PyObject *init = NULL;
  PyObject *pylong = NULL;
  int version = 0;
  const char *s = NULL;

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|i", kwlist, &init, &version) ||
      (self = (ipaddress_object *) type->tp_alloc(type, 0)) == NULL)
    goto error;

  if (POW_IPAddress_Check(init)) {
    ipaddress_object *src = (ipaddress_object *) init;

    memcpy(self->address, src->address, sizeof(self->address));
    self->version = src->version;
    self->length  = src->length;
    self->af      = src->af;

    return (PyObject *) self;
  }

  if ((s = PyString_AsString(init)) == NULL)
    PyErr_Clear();
  else if (version == 0)
    version = strchr(s, ':') ? 6 : 4;

  switch (version) {
  case 4: self->length =  4; self->af = AF_INET;  break;
  case 6: self->length = 16; self->af = AF_INET6; break;
  default: lose("Unknown IP version number");
  }
  self->version = version; 

  if (s != NULL) {
    if (inet_pton(self->af, s, self->address) <= 0)
      lose("Couldn't parse IP address");
    return (PyObject *) self;
  }

  if ((pylong = PyNumber_Long(init)) != NULL) {
    if (_PyLong_AsByteArray((PyLongObject *) pylong, self->address, self->length, 0, 0) < 0)
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

  if (!inet_ntop(self->af, self->address, addrstr, sizeof(addrstr)))
    lose("Couldn't convert IP address");

  return PyString_FromString(addrstr);

 error:
  return NULL;
}

static PyObject *
ipaddress_object_repr(ipaddress_object *self)
{
  char addrstr[sizeof("aaaa:bbbb:cccc:dddd:eeee:ffff:255.255.255.255") + 1];

  if (!inet_ntop(self->af, self->address, addrstr, sizeof(addrstr)))
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

  for (i = 0; i < self->length; i++)
    h ^= self->address[i] << ((i & 3) << 3);

  return (long) h == -1 ? 0 : (long) h;
}

static PyObject *
ipaddress_object_get_bits(ipaddress_object *self, void *closure)
{
  return PyInt_FromLong(self->length * 8);
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
      (addr1 != NULL && addr2 != NULL && addr1->version != addr2->version) ||
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

  result->version = addr->version;
  result->length  = addr->length;
  result->af      = addr->af;

  if (_PyLong_AsByteArray((PyLongObject *) obj4, result->address, result->length, 0, 0) < 0) {
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

  if (!POW_IPAddress_Check(arg))
    return Py_NotImplemented;

  return _PyLong_FromByteArray(addr->address, addr->length, 0, 0);
}

static PyObject *
ipaddress_object_number_int(PyObject *arg)
{
  return ipaddress_object_number_long(arg);
}

static PyObject *
ipaddress_object_number_add(PyObject *arg1, PyObject *arg2)
{
  return ipaddress_object_number_binary_helper(PyNumber_Add, arg1, arg2);
}

static PyObject *
ipaddress_object_number_subtract(PyObject *arg1, PyObject *arg2)
{
  return ipaddress_object_number_binary_helper(PyNumber_Subtract, arg1, arg2);
}

static PyObject *
ipaddress_object_number_lshift(PyObject *arg1, PyObject *arg2)
{
  return ipaddress_object_number_binary_helper(PyNumber_Lshift, arg1, arg2);
}

static PyObject *
ipaddress_object_number_rshift(PyObject *arg1, PyObject *arg2)
{
  return ipaddress_object_number_binary_helper(PyNumber_Rshift, arg1, arg2);
}

static PyObject *
ipaddress_object_number_and(PyObject *arg1, PyObject *arg2)
{
  return ipaddress_object_number_binary_helper(PyNumber_And, arg1, arg2);
}

static PyObject *
ipaddress_object_number_xor(PyObject *arg1, PyObject *arg2)
{
  return ipaddress_object_number_binary_helper(PyNumber_Xor, arg1, arg2);
}

static PyObject *
ipaddress_object_number_or(PyObject *arg1, PyObject *arg2)
{
  return ipaddress_object_number_binary_helper(PyNumber_Or, arg1, arg2);
}

static int
ipaddress_object_number_nonzero(ipaddress_object *self)
{
  int i;

  for (i = 0; i < self->length; i++)
    if (self->address[i] != 0)
      return 1;
  return 0;
}

static PyObject *
ipaddress_object_number_invert(ipaddress_object *self)
{
  ipaddress_object *result = NULL;
  int i;

  if ((result = (ipaddress_object *) self->ob_type->tp_alloc(self->ob_type, 0)) == NULL)
    goto error;

  result->version = self->version;
  result->length  = self->length;
  result->af      = self->af;

  for (i = 0; i < self->length; i++)
    result->address[i] = ~self->address[i];

 error:                         /* Fall through */
  return (PyObject *) result;
}

static PyGetSetDef ipaddress_getsetters[] = {
  {"bits", (getter) ipaddress_object_get_bits},
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
  0,                            		/* nb_inplace_subtract */
  0,                            		/* nb_inplace_multiply */
  0,                            		/* nb_inplace_divide */
  0,                            		/* nb_inplace_remainder */
  0,                            		/* nb_inplace_power */
  0,                            		/* nb_inplace_lshift */
  0,                            		/* nb_inplace_rshift */
  0,                            		/* nb_inplace_and */
  0,                            		/* nb_inplace_xor */
  0,                            		/* nb_inplace_or */
  0,                                            /* nb_floor_divide */
  0,                                            /* nb_true_divide */
  0,                            		/* nb_inplace_floor_divide */
  0,                            		/* nb_inplace_true_divide */
  0,                                            /* nb_index */
};

static PyTypeObject ipaddresstype = {
  PyObject_HEAD_INIT(NULL)
  0,                                        /* ob_size */
  "POW.IPAddress",                          /* tp_name */
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
  0,                                        /* tp_methods */
  0,                                        /* tp_members */
  ipaddress_getsetters,                     /* tp_getset */
  0,                                        /* tp_base */
  0,                                        /* tp_dict */
  0,                                        /* tp_descr_get */
  0,                                        /* tp_descr_set */
  0,                                        /* tp_dictoffset */
  0,                                        /* tp_init */
  0,                                        /* tp_alloc */
  ipaddress_object_new,                     /* tp_new */
};

/*========== IPAddress code ==========*/

/*========== X509 code ==========*/

static PyObject *
x509_object_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  x509_object *self;

  if ((self = (x509_object *) type->tp_alloc(type, 0)) != NULL &&
      (self->x509 = X509_new()) != NULL)
    return (PyObject *) self;

  Py_XDECREF(self);
  return NULL;
}

static x509_object *
x509_object_pem_read(BIO *in)
{
  x509_object *self = NULL;

  if ((self = (x509_object *) x509_object_new(&x509type, NULL, NULL)) == NULL)
    goto error;

  X509_free(self->x509);

  if ((self->x509 = PEM_read_bio_X509(in, NULL, NULL, NULL)) == NULL)
    lose_openssl_error("Couldn't load PEM encoded certificate");

  return self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static x509_object *
x509_object_der_read(unsigned char *src, int len)
{
  x509_object *self;

  if ((self = (x509_object *) x509_object_new(&x509type, NULL, NULL)) == NULL)
    goto error;

  if(!d2i_X509(&self->x509, (const unsigned char **) &src, len))
    lose_openssl_error("Couldn't load PEM encoded certificate");

  return self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static PyObject *
x509_object_write_helper(x509_object *self, int format)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  switch (format) {

  case DER_FORMAT:
    if (!i2d_X509_bio(bio, self->x509))
      lose_openssl_error("Unable to write certificate");
    break;

  case PEM_FORMAT:
    if (!PEM_write_bio_X509(bio, self->x509))
      lose_openssl_error("Unable to write certificate");
    break;

  default:
    lose("Internal error, unknown output format");
  }

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static char x509_object_pem_write__doc__[] =
  "This method returns a PEM- encoded certificate as a string.\n"
  ;

static PyObject *
x509_object_pem_write(x509_object *self)
{
  return x509_object_write_helper(self, PEM_FORMAT);
}

static char x509_object_der_write__doc__[] =
  "This method returns a DER encoded certificate as a string.\n"
  ;

static PyObject *
x509_object_der_write(x509_object *self)
{
  return x509_object_write_helper(self, DER_FORMAT);
}

/*
 * Currently this function only supports RSA keys.
 */

static char x509_object_set_public_key__doc__[] =
  "This method sets the public key for this certificate object.\n"
  "The \"key\" parameter should be an instance of the Asymmetric class,\n"
  "containing a public key.\n"
  ;

static PyObject *
x509_object_set_public_key(x509_object *self, PyObject *args)
{
  EVP_PKEY *pkey = NULL;
  asymmetric_object *asym;

  if (!PyArg_ParseTuple(args, "O!", &asymmetrictype, &asym))
    goto error;

  if ((pkey = EVP_PKEY_new()) == NULL)
    lose_no_memory();

  if (!EVP_PKEY_assign_RSA(pkey, asym->cipher) ||
      !X509_set_pubkey(self->x509, pkey))
    lose_openssl_error("Couldn't set certificate's public key");

  Py_RETURN_NONE;

 error:
  EVP_PKEY_free(pkey);
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
  EVP_PKEY *pkey = NULL;
  asymmetric_object *asym;
  int digest_type = SHA256_DIGEST;
  const EVP_MD *digest_method = NULL;

  if (!PyArg_ParseTuple(args, "O!|i", &asymmetrictype, &asym, &digest_type))
    goto error;

  if ((pkey = EVP_PKEY_new()) == NULL)
    lose_no_memory();

  if (asym->key_type != RSA_PRIVATE_KEY)
    lose("Don't know how to use this type of key");

  if (!EVP_PKEY_assign_RSA(pkey, asym->cipher))
    lose_openssl_error("EVP_PKEY assignment error");

  if ((digest_method = evp_digest_factory(digest_type)) == NULL)
    lose("Unsupported digest algorithm");

  if (!X509_sign(self->x509, pkey, digest_method))
    lose_openssl_error("Couldn't sign certificate");

  Py_RETURN_NONE;

 error:
  EVP_PKEY_free(pkey);
  return NULL;
}

static char x509_object_get_version__doc__[] =
  "This method returns the version number from the version field of this certificate.\n"
  ;

static PyObject *
x509_object_get_version(x509_object *self)
{
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
  return Py_BuildValue("l", ASN1_INTEGER_get(X509_get_serialNumber(self->x509)));
}

static char x509_object_set_serial__doc__[] =
  "This method sets the serial number in the serial field of this certificate.\n"
  "The \"serial\" parameter should ba an integer.\n"
  ;

static PyObject *
x509_object_set_serial(x509_object *self, PyObject *args)
{
  long c_serial = 0;
  ASN1_INTEGER *a_serial = NULL;

  if (!PyArg_ParseTuple(args, "l", &c_serial))
    goto error;

  if ((a_serial = ASN1_INTEGER_new()) == NULL ||
      !ASN1_INTEGER_set(a_serial, c_serial) ||
      !X509_set_serialNumber(self->x509, a_serial))
    lose_no_memory();

  ASN1_INTEGER_free(a_serial);
  Py_RETURN_NONE;

 error:
  ASN1_INTEGER_free(a_serial);
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

  if (!PyArg_ParseTuple(args, "s", &s))
    goto error;

  if ((t = Python_to_ASN1_TIME(s)) == NULL)
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

  if (!PyArg_ParseTuple(args, "s", &s))
    goto error;

  if ((t = Python_to_ASN1_TIME(s)) == NULL)
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
  int ext_num = 0, ext_nid = 0;
  char const *ext_ln = NULL;
  char unknown_ext [] = "unknown";
  X509_EXTENSION *ext;

  if (!PyArg_ParseTuple(args, "i", &ext_num))
    goto error;

  if ((ext = X509_get_ext(self->x509, ext_num)) == NULL)
    lose_openssl_error("Couldn't get extension");

#warning OpenSSL NIDs and longNames again, should take format or just return decimal OID

  if ((ext_nid = OBJ_obj2nid(ext->object)) == NID_undef)
    lose("Extension has unknown object identifier");

  if ((ext_ln = OBJ_nid2sn(ext_nid)) == NULL)
    ext_ln = unknown_ext;

  return Py_BuildValue("sNs#", ext_ln, PyBool_FromLong(ext->critical),
                       ext->value->data, ext->value->length);

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
  (void) X509_check_ca(self->x509); /* Calls x509v3_cache_extensions() */

  if (self->x509->skid == NULL)
    Py_RETURN_NONE;
  else
    return Py_BuildValue("s#", self->x509->skid->data, self->x509->skid->length);
}

static char x509_object_get_aki__doc__[] =
  "This method returns the Authority Key Identifier (AKI) keyid value for\n"
  " this certificate, or None if the certificate has no AKI extension\n"
  "or has an AKI extension with no keyid value.\n"
  ;

static PyObject *
x509_object_get_aki(x509_object *self, PyObject *args)
{
  (void) X509_check_ca(self->x509); /* Calls x509v3_cache_extensions() */

  if (self->x509->akid == NULL || self->x509->akid->keyid == NULL)
    Py_RETURN_NONE;
  else
    return Py_BuildValue("s#", self->x509->akid->keyid->data, self->x509->akid->keyid->length);
}

static char x509_object_get_key_usage__doc__[] =
  "This method returns a FrozenSet of strings representing the KeyUsage\n"
  "settings for this certificate, or None if the certificate has no\n"
  "KeyUsage extension.  The bits have the same names as in RFC 5280.\n"
  ;

static PyObject *
x509_object_get_key_usage(x509_object *self, PyObject *args)
{
  extern X509V3_EXT_METHOD v3_key_usage;
  BIT_STRING_BITNAME *bit_name;
  ASN1_BIT_STRING *ext = NULL;
  PyObject *result = NULL;
  PyObject *token = NULL;

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
  ;

static PyObject *
x509_object_set_key_usage(x509_object *self, PyObject *args)
{
  extern X509V3_EXT_METHOD v3_key_usage;
  BIT_STRING_BITNAME *bit_name;
  ASN1_BIT_STRING *ext = NULL;
  PyObject *iterable = NULL;
  PyObject *critical = NULL;
  PyObject *iterator = NULL;
  PyObject *token = NULL;
  const char *t;
  int ok = 0;

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
                         (critical != NULL && PyObject_IsTrue(critical)),
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

  if ((asid = X509_get_ext_d2i(self->x509, NID_sbgp_autonomousSysNum, NULL, NULL)) != NULL) {
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

        if ((range_b = _PyLong_FromByteArray(ASN1_STRING_data(b),
                                             ASN1_STRING_length(b),
                                             0, 0)) == NULL ||
            (range_e = _PyLong_FromByteArray(ASN1_STRING_data(e),
                                             ASN1_STRING_length(e),
                                             0, 0)) == NULL ||
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
      const unsigned int afi = v3_addr_get_afi(f);
      PyObject **result_obj = NULL;
      int addr_len = 0;

      switch (afi) {
      case IANA_AFI_IPV4: result_obj = &ipv4_result; break;
      case IANA_AFI_IPV6: result_obj = &ipv6_result; break;
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
        IPAddressOrRange *aor = sk_IPAddressOrRange_value(f->ipAddressChoice->u.addressesOrRanges,
                                    j);
        ipaddress_object *addr_b = NULL;
        ipaddress_object *addr_e = NULL;
        
        if ((range_b = ipaddresstype.tp_alloc(&ipaddresstype, 0)) == NULL ||
            (range_e = ipaddresstype.tp_alloc(&ipaddresstype, 0)) == NULL)
          goto error;

        addr_b = (ipaddress_object *) range_b;
        addr_e = (ipaddress_object *) range_e;

        if ((addr_len = v3_addr_get_range(aor, afi, addr_b->address, addr_e->address, sizeof(addr_b->address))) == 0)
          lose_type_error("Couldn't unpack IP addresses from BIT STRINGs");

        switch (afi) {
        case IANA_AFI_IPV4:
          addr_b->version = addr_e->version =  4;
          addr_b->length  = addr_e->length  =  4;
          addr_b->af      = addr_e->af      = AF_INET;
          break;
        case IANA_AFI_IPV6:
          addr_b->version = addr_e->version =  6;
          addr_b->length  = addr_e->length  = 16;
          addr_b->af      = addr_e->af      = AF_INET6;
          break;
        }

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

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "|OOO", kwlist, &asn_arg, &ipv4_arg, &ipv6_arg))
    goto error;

  if (asn_arg != Py_None) {

    if ((asid = ASIdentifiers_new()) == NULL)
      lose_no_memory();

    if (PyString_Check(asn_arg)) {

      if (strcmp(PyString_AsString(asn_arg), "inherit"))
        lose_type_error("ASID must be sequence of range pairs, or \"inherit\"");

      if (!v3_asid_add_inherit(asid, V3_ASID_ASNUM))
        lose_no_memory();

    } else {
      
      if ((iterator = PyObject_GetIter(asn_arg)) == NULL)
        goto error;

      while ((item = PyIter_Next(iterator)) != NULL) {

        if (!PyArg_ParseTuple(item, "OO", &range_b, &range_e) ||
            (asid_b = Python_Long_to_ASN1_INTEGER(range_b)) == NULL)
          goto error;

        switch (PyObject_RichCompareBool(range_b, range_e, Py_EQ)) {
        case 0:
          if ((asid_e = Python_Long_to_ASN1_INTEGER(range_e)) == NULL)
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
      }

      if (!v3_asid_canonize(asid) ||
          !X509_add1_ext_i2d(self->x509, NID_sbgp_autonomousSysNum,
                             asid, 1, X509V3_ADD_REPLACE))
        lose_openssl_error("Couldn't add ASID extension to certificate");

      Py_XDECREF(iterator);
      iterator = NULL;
    }
  }

  if (ipv4_arg != Py_None || ipv6_arg != Py_None) {
    int afi;

    if ((addr = sk_IPAddressFamily_new_null()) == NULL)
      lose_no_memory();

    /*
     * Cheap trick to let us inline all of this instead of being
     * forced to use a separate function.  Should probably use a
     * separate function anyway, but am waiting until I have the ROA
     * code written to decide how best to refactor all of this.
     */

    for (afi = 0; afi < IANA_AFI_IPV4 + IANA_AFI_IPV6; afi++) {
      PyObject **argp;
      int len;

      switch (afi) {
      case IANA_AFI_IPV4: len =  4; argp = &ipv4_arg; break;
      case IANA_AFI_IPV6: len = 16; argp = &ipv6_arg; break;
      default: continue;
      }

      if (PyString_Check(*argp)) {

        if (strcmp(PyString_AsString(*argp), "inherit"))
          lose_type_error("Argument must be sequence of range pairs, or \"inherit\"");

        if (!v3_addr_add_inherit(addr, afi, NULL))
          lose_no_memory();

      } else {

        if ((iterator = PyObject_GetIter(*argp)) == NULL)
          goto error;

        while ((item = PyIter_Next(iterator)) != NULL) {

          if (!PyArg_ParseTuple(item, "OO", &range_b, &range_e))
            goto error;

          addr_b = (ipaddress_object *) range_b;
          addr_e = (ipaddress_object *) range_e;

          if (!POW_IPAddress_Check(range_b) ||
              !POW_IPAddress_Check(range_e) ||
              addr_b->version != addr_e->version ||
              addr_b->length != len ||
              addr_e->length != len ||
              memcmp(addr_b->address, addr_e->address, addr_b->length) > 0)
            lose_type_error("IPAddrBlock must be sequence of address pairs, or \"inherit\"");

          if (!v3_addr_add_range(addr, afi, NULL, addr_b->address, addr_e->address))
            lose_openssl_error("Couldn't add range to IPAddrBlock");

          Py_XDECREF(item);
          item = range_b = range_e = NULL;
          addr_b = addr_e = NULL;
        }

        Py_XDECREF(iterator);
        iterator = NULL;
      }
    }

    if (!v3_addr_canonize(addr) ||
        !X509_add1_ext_i2d(self->x509, NID_sbgp_ipAddrBlock,
                           addr, 1, X509V3_ADD_REPLACE))
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

static char x509_object_pprint__doc__[] =
  "This method returns a pretty-printed rendition of the certificate.\n"
  ;

static PyObject *
x509_object_pprint(x509_object *self)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

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
  Define_Method(pemWrite,       x509_object_pem_write,          METH_NOARGS),
  Define_Method(derWrite,       x509_object_der_write,          METH_NOARGS),
  Define_Method(sign,           x509_object_sign,               METH_VARARGS),
  Define_Method(setPublicKey,   x509_object_set_public_key,     METH_VARARGS),
  Define_Method(getVersion,     x509_object_get_version,        METH_NOARGS),
  Define_Method(setVersion,     x509_object_set_version,        METH_VARARGS),
  Define_Method(getSerial,      x509_object_get_serial,         METH_NOARGS),
  Define_Method(setSerial,      x509_object_set_serial,         METH_VARARGS),
  Define_Method(getIssuer,      x509_object_get_issuer,         METH_VARARGS),
  Define_Method(setIssuer,      x509_object_set_issuer,         METH_VARARGS),
  Define_Method(getSubject,     x509_object_get_subject,        METH_VARARGS),
  Define_Method(setSubject,     x509_object_set_subject,        METH_VARARGS),
  Define_Method(getNotBefore,   x509_object_get_not_before,     METH_NOARGS),
  Define_Method(getNotAfter,    x509_object_get_not_after,      METH_NOARGS),
  Define_Method(setNotAfter,    x509_object_set_not_after,      METH_VARARGS),
  Define_Method(setNotBefore,   x509_object_set_not_before,     METH_VARARGS),
  Define_Method(addExtension,   x509_object_add_extension,      METH_VARARGS),
  Define_Method(clearExtensions, x509_object_clear_extensions,  METH_NOARGS),
  Define_Method(countExtensions, x509_object_count_extensions,  METH_NOARGS),
  Define_Method(getExtension,   x509_object_get_extension,      METH_VARARGS),
  Define_Method(pprint,         x509_object_pprint,             METH_NOARGS),
  Define_Method(getSKI,         x509_object_get_ski,            METH_NOARGS),
  Define_Method(getAKI,         x509_object_get_aki,            METH_NOARGS),
  Define_Method(getKeyUsage,	x509_object_get_key_usage,	METH_NOARGS),
  Define_Method(setKeyUsage,	x509_object_set_key_usage,	METH_VARARGS),
  Define_Method(getRFC3779,	x509_object_get_rfc3779,	METH_NOARGS),
  Define_Method(setRFC3779,	x509_object_set_rfc3779,	METH_KEYWORDS),
  {NULL}
};

static void
x509_object_dealloc(x509_object *self)
{
  X509_free(self->x509);
  self->ob_type->tp_free((PyObject*) self);
}

static char x509type__doc__[] =
  "This class represents an X.509 certificate.\n"
  "\n"
  LAME_DISCLAIMER_IN_ALL_CLASS_DOCUMENTATION
  ;

static PyTypeObject x509type = {
  PyObject_HEAD_INIT(0)
  0,                                        /* ob_size */
  "POW.X509",                               /* tp_name */
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
  x509type__doc__,                          /* tp_doc */
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

/*========== X509 Code ==========*/

/*========== x509 store Code ==========*/

static PyObject *
x509_store_object_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  x509_store_object *self = NULL;

  if ((self = (x509_store_object *) type->tp_alloc(type, 0)) != NULL &&
      (self->store = X509_STORE_new()) != NULL)
    return (PyObject *) self;

  Py_XDECREF(self);
  return NULL;
}

#if ENABLE_X509_CERTIFICATE_SIGNATURE_AND_VERIFICATION

static char x509_store_object_verify__doc__[] =
  "This method performs X.509 certificate verification using\n"
  "the OpenSSL X509_verify_cert() function.\n"
  "\n"
  "The \"certificate\" parameter is the certificate to verify, and\n"
  "should be an X509 object.\n"
  ;

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
 * even matter, not sure whether anything is calling this method.
 */

static PyObject *
x509_store_object_verify(x509_store_object *self, PyObject *args)
{
  X509_STORE_CTX ctx;
  x509_object *x509 = NULL;
  int ok;

  if (!PyArg_ParseTuple(args, "O!", &x509type, &x509))
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

  if (!PyArg_ParseTuple(args, "O!O", &x509type, &x509, &x509_sequence))
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

  if (!PyArg_ParseTuple(args, "O!|O", &x509type, &x509, &x509_sequence))
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

  if (!PyArg_ParseTuple(args, "O!", &x509type, &x509))
    goto error;

  X509_STORE_add_cert(self->store, x509->x509);

  Py_RETURN_NONE;

 error:

  return NULL;
}

static char x509_store_object_add_crl__doc__[] =
  "This method adds a CRL to the store object.\n"
  "\n"
  "The \"crl\" parameter should be an instance of X509Crl.\n"
  ;

#warning These badly capitalized class names are starting to bug me, clean them up

static PyObject *
x509_store_object_add_crl(x509_store_object *self, PyObject *args)
{
  x509_crl_object *crl = NULL;

  if (!PyArg_ParseTuple(args, "O!", &x509_crltype, &crl))
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

static void
x509_store_object_dealloc(x509_store_object *self)
{
  X509_STORE_free(self->store);
  self->ob_type->tp_free((PyObject*) self);
}

static char x509_storetype__doc__[] =
  "This class provides basic access to the OpenSSL certificate store\n"
  "mechanism used in X.509 and CMS verification.\n"
  "\n"
  LAME_DISCLAIMER_IN_ALL_CLASS_DOCUMENTATION
  ;

static PyTypeObject x509_storetype = {
  PyObject_HEAD_INIT(0)
  0,                                        /* ob_size */
  "POW.X509Store",                          /* tp_name */
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
  x509_storetype__doc__,                    /* tp_doc */
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

/*========== x509 store Code ==========*/

/*========== x509 crl Code ==========*/

static PyObject *
x509_crl_object_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  x509_crl_object *self = NULL;

  if ((self = (x509_crl_object *) type->tp_alloc(type, 0)) != NULL &&
      (self->crl = X509_CRL_new()) != NULL)
    return (PyObject *) self;

  Py_XDECREF(self);
  return NULL;
}

static x509_crl_object *
x509_crl_object_pem_read(BIO *in)
{
  x509_crl_object *self;

  if ((self = (x509_crl_object *) x509_crl_object_new(&x509_crltype, NULL, NULL)) == NULL)
    goto error;

  X509_CRL_free(self->crl);

  if ((self->crl = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL)) == NULL)
    lose_openssl_error("Couldn't PEM encoded load CRL");

  return self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static x509_crl_object *
x509_crl_object_der_read(unsigned char *src, int len)
{
  x509_crl_object *self;

  if ((self = (x509_crl_object *) x509_crl_object_new(&x509_crltype, NULL, NULL)) == NULL)
    goto error;

  if (!d2i_X509_CRL(&self->crl, (const unsigned char **) &src, len))
    lose_openssl_error("Couldn't load DER encoded CRL");

  return self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static char x509_crl_object_get_version__doc__[] =
  "This method returns the version number of this CRL.\n"
  ;

static PyObject *
x509_crl_object_get_version(x509_crl_object *self)
{
  return Py_BuildValue("l", X509_CRL_get_version(self->crl));
}

static char x509_crl_object_set_version__doc__[] =
  "This method sets the version number of this CRL.\n"
  "\n"
  "The \"version\" parameter should be a positive integer.\n"
  ;

static PyObject *
x509_crl_object_set_version(x509_crl_object *self, PyObject *args)
{
  long version = 0;

  if (!PyArg_ParseTuple(args, "i", &version))
    goto error;

  if (!X509_CRL_set_version(self->crl, version))
    lose_no_memory();

  Py_RETURN_NONE;

 error:
  return NULL;
}

static char x509_crl_object_get_issuer__doc__[] =
  "This method returns issuer name from this CRL.\n"
  "See the \"getIssuer\" method of the X509 class for more details.\n"
  ;

static PyObject *
x509_crl_object_get_issuer(x509_crl_object *self, PyObject *args)
{
  PyObject *result = NULL;
  int format = OIDNAME_FORMAT;

  if (!PyArg_ParseTuple(args, "|i", &format))
    goto error;

  result = x509_object_helper_get_name(X509_CRL_get_issuer(self->crl), format);

 error:                         /* Fall through */
  return result;
}

static char x509_crl_object_set_issuer__doc__[] =
  "This method sets the CRL's issuer name.\n"
  "See the \"setIssuer\" method of the X509 class for details.\n"
  ;

static PyObject *
x509_crl_object_set_issuer(x509_crl_object *self, PyObject *args)
{
  PyObject *name_sequence = NULL;
  X509_NAME *name = NULL;

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

static char x509_crl_object_set_this_update__doc__[] =
  "This method sets the CRL's \"thisUpdate\" value.\n"
  "\n"
  "The \"time\" parameter should be in the form of a GeneralizedTime string\n"
  "as restricted by RFC 5280. The code automatically converts to UTCTime\n"
  "when the RFC 5280 rules require UTCTime instead of GeneralizedTime,\n"
  "so that Python code need not worry about the conversion rules.\n"
  ;

static PyObject *
x509_crl_object_set_this_update (x509_crl_object *self, PyObject *args)
{
  char *s = NULL;
  ASN1_TIME *t = NULL;

  if (!PyArg_ParseTuple(args, "s", &s))
    goto error;

  if ((t = Python_to_ASN1_TIME(s)) == NULL)
    lose("Couldn't convert thisUpdate string");

  if (!X509_CRL_set_lastUpdate(self->crl, t)) /* sic */
    lose("Couldn't set thisUpdate");

  ASN1_TIME_free(t);
  Py_RETURN_NONE;

 error:
  ASN1_TIME_free(t);
  return NULL;
}

static char x509_crl_object_get_this_update__doc__[] =
  "This method returns the CRL's \"thisUpdate\" value\n"
  "in the form of a GeneralizedTime string as restricted by RFC 5280.\n"
  "The code automatically converts RFC-5280-compliant UTCTime strings\n"
  "into the GeneralizedTime format, so that Python code need not worry\n"
  "about the conversion rules.\n"
  ;

static PyObject *
x509_crl_object_get_this_update (x509_crl_object *self)
{
  return ASN1_TIME_to_Python(X509_CRL_get_lastUpdate(self->crl)); /* sic */
}

static char x509_crl_object_set_next_update__doc__[] =
  "This method sets the CRL's \"nextUpdate\" value.\n"
  "\n"
  "The \"time\" parameter should be in the form of a GeneralizedTime string\n"
  "as restricted by RFC 5280. The code automatically converts to UTCTime\n"
  "when the RFC 5280 rules require UTCTime instead of GeneralizedTime,\n"
  "so that Python code need not worry about the conversion rules.\n"
  ;

static PyObject *
x509_crl_object_set_next_update (x509_crl_object *self, PyObject *args)
{
  char *s = NULL;
  ASN1_TIME *t = NULL;

  if (!PyArg_ParseTuple(args, "s", &s))
    goto error;

  if ((t = Python_to_ASN1_TIME(s)) == NULL)
    lose("Couldn't parse nextUpdate string");

  if (!X509_CRL_set_nextUpdate(self->crl, t))
    lose("Couldn't set nextUpdate");

  ASN1_TIME_free(t);
  Py_RETURN_NONE;

 error:
  ASN1_TIME_free(t);
  return NULL;
}

static char x509_crl_object_get_next_update__doc__[] =
  "This method returns the CRL's \"nextUpdate\" value\n"
  "in the form of a GeneralizedTime string as restricted by RFC 5280.\n"
  "The code automatically converts RFC-5280-compliant UTCTime strings\n"
  "into the GeneralizedTime format, so that Python code need not worry\n"
  "about the conversion rules.\n"
  ;

static PyObject *
x509_crl_object_get_next_update (x509_crl_object *self)
{
  return ASN1_TIME_to_Python(X509_CRL_get_nextUpdate(self->crl));
}

static char x509_crl_object_add_revocations__doc__[] =
  "This method adds a collection of revocations to this CRL.\n"
  "\n"
  "The \"iterable\" parameter should be an iterable object, each element\n"
  "of which is a two-element sequence; the first element of this sequence\n"
  "should be the revoked serial number (an integer), the second element\n"
  "should be the revocation date (a timestamp in GeneralizedTime format).\n"
  ;

static PyObject *
x509_crl_object_add_revocations(x509_crl_object *self, PyObject *args)
{
  PyObject *iterable = NULL;
  PyObject *iterator = NULL;
  PyObject *item = NULL;
  X509_REVOKED *revoked = NULL;
  ASN1_INTEGER *a_serial = NULL;
  ASN1_TIME *a_date = NULL;
  int ok = 0;
  long c_serial;
  char *c_date;

  if (!PyArg_ParseTuple(args, "O", &iterable) ||
      (iterator = PyObject_GetIter(iterable)) == NULL)
    goto error;

  while ((item = PyIter_Next(iterator)) != NULL) {

    if (!PyArg_ParseTuple(item, "ls", &c_serial, &c_date))
      goto error;

    if ((revoked = X509_REVOKED_new()) == NULL)
      lose_no_memory();

    if ((a_serial = ASN1_INTEGER_new()) == NULL ||
        !ASN1_INTEGER_set(a_serial, c_serial) ||
        !X509_REVOKED_set_serialNumber(revoked, a_serial))
      lose_no_memory();
    ASN1_INTEGER_free(a_serial);
    a_serial = NULL;

    if ((a_date = Python_to_ASN1_TIME(c_date)) == NULL)
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

static char x509_crl_object_get_revoked__doc__[] =
  "This method returns a tuple of X509Revoked objects representing the sequence\n"
  "of revoked certificates listed in the CRL.\n"
  ;

static PyObject *
x509_crl_object_get_revoked(x509_crl_object *self)
{
  STACK_OF(X509_REVOKED) *revoked = NULL;
  X509_REVOKED *r = NULL;
  PyObject *result = NULL;
  PyObject *item = NULL;
  int i;

  if ((revoked = X509_CRL_get_REVOKED(self->crl)) == NULL)
    lose("Inexplicable NULL revocation list pointer");

  if ((result = PyTuple_New(sk_X509_REVOKED_num(revoked))) == NULL)
    goto error;

  for (i = 0; i < sk_X509_REVOKED_num(revoked); i++) {
    r = sk_X509_REVOKED_value(revoked, i);

    if ((item = Py_BuildValue("(lN)",
                              ASN1_INTEGER_get(r->serialNumber), 
                              ASN1_TIME_to_Python(r->revocationDate))) == NULL)
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

static char x509_crl_object_add_extension__doc__[] =
  "This method adds an extension to this CRL.\n"
  "It takes the same arguments and has the same limitations as the\n"
  "X509.addExtension() method (q.v.).\n"
  ;

static PyObject *
x509_crl_object_add_extension(x509_crl_object *self, PyObject *args)
{
  PyObject *critical = NULL;
  int len = 0, ok = 0;
  char *name = NULL;
  unsigned char *buf = NULL;
  ASN1_OBJECT *oid = NULL;
  ASN1_OCTET_STRING *octetString = NULL;
  X509_EXTENSION *ext = NULL;

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

static char x509_crl_object_clear_extensions__doc__[] =
  "This method clears all extensions attached to this CRL.\n"
  ;

static PyObject *
x509_crl_object_clear_extensions(x509_crl_object *self)
{
  X509_EXTENSION *ext;

  while ((ext = X509_CRL_delete_ext(self->crl, 0)) != NULL)
    X509_EXTENSION_free(ext);

  Py_RETURN_NONE;
}

static char x509_crl_object_count_extensions__doc__[] =
  "This method returns the number of extensions attached to this CRL.\n"
  ;

static PyObject *
x509_crl_object_count_extensions(x509_crl_object *self)
{
  return Py_BuildValue("i", X509_CRL_get_ext_count(self->crl));
}

static char x509_crl_object_get_extension__doc__[] =
  "This method returns a tuple equivalent the parameters of the\n"
  "\"addExtension\" method, and suffers from similar limitations.\n"
  "\n"
  "The \"index\" parameter is the position in the extension list of\n"
  "the extension to be returned.\n"
  ;

static PyObject *
x509_crl_object_get_extension(x509_crl_object *self, PyObject *args)
{
  int ext_num = 0, ext_nid = 0;
  char const *ext_ln = NULL;
  char unknown_ext [] = "unknown";
  X509_EXTENSION *ext;

  if (!PyArg_ParseTuple(args, "i", &index))
    goto error;

  if ((ext = X509_CRL_get_ext(self->crl, ext_num)) == NULL)
    lose_openssl_error("Couldn't get extension");

  if ((ext_nid = OBJ_obj2nid(ext->object)) == NID_undef)
    lose("Extension has unknown object identifier");

  if ((ext_ln = OBJ_nid2sn(ext_nid)) == NULL)
    ext_ln = unknown_ext;

  return Py_BuildValue("sNs#", ext_ln, PyBool_FromLong(ext->critical),
                       ext->value->data, ext->value->length);

 error:

  return NULL;
}

static char x509_crl_object_sign__doc__[] =
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
x509_crl_object_sign(x509_crl_object *self, PyObject *args)
{
  EVP_PKEY *pkey = NULL;
  asymmetric_object *asym;
  int digest_type = SHA256_DIGEST;
  const EVP_MD *digest_method = NULL;

  if (!PyArg_ParseTuple(args, "O!|i", &asymmetrictype, &asym, &digest_type))
    goto error;

  if ((pkey = EVP_PKEY_new()) == NULL)
    lose_no_memory();

  if (asym->key_type != RSA_PRIVATE_KEY)
    lose("Don't know how to use this type of key");

  if ((digest_method = evp_digest_factory(digest_type)) == NULL)
    lose("Unsupported digest algorithm");

  if (!EVP_PKEY_assign_RSA(pkey, asym->cipher) ||
      !X509_CRL_sign(self->crl, pkey, digest_method))
    lose_openssl_error("Couldn't sign CRL");

  Py_RETURN_NONE;

 error:
  EVP_PKEY_free(pkey);
  return NULL;
}

static char x509_crl_object_verify__doc__[] =
  "This method verifies the CRL's signature.\n"
  "The check is performed using OpenSSL's X509_CRL_verify() function.\n"
  "\n"
  "The \"key\" parameter should be an instance of the Asymmetric class\n"
  "containing the public key of the purported signer.\n"
  ;

static PyObject *
x509_crl_object_verify(x509_crl_object *self, PyObject *args)
{
  EVP_PKEY *pkey = NULL;
  asymmetric_object *asym;

  if (!PyArg_ParseTuple(args, "O!", &asymmetrictype, &asym))
    goto error;

  if ((pkey = EVP_PKEY_new()) == NULL)
    lose_no_memory();

  if (!EVP_PKEY_assign_RSA(pkey, asym->cipher))
    lose_openssl_error("EVP_PKEY assignment error");

  return PyBool_FromLong(X509_CRL_verify(self->crl, pkey));

 error:
  EVP_PKEY_free(pkey);
  return NULL;
}

static PyObject *
x509_crl_object_write_helper(x509_crl_object *self, int format)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  switch (format) {

  case DER_FORMAT:
    if (!i2d_X509_CRL_bio(bio, self->crl))
      lose_openssl_error("Unable to write CRL");
    break;

  case PEM_FORMAT:
    if (!PEM_write_bio_X509_CRL(bio, self->crl))
      lose_openssl_error("Unable to write CRL");

  default:
    lose("Internal error, unknown output format");
  }

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static char x509_crl_object_pem_write__doc__[] =
  "This method returns a PEM encoded CRL as a string.\n"
  ;

static PyObject *
x509_crl_object_pem_write(x509_crl_object *self)
{
  return x509_crl_object_write_helper(self, PEM_FORMAT);
}

static char x509_crl_object_der_write__doc__[] =
  "This method returns a DER encoded CRL as a string.\n"
  ;

static PyObject *
x509_crl_object_der_write(x509_crl_object *self)
{
  return x509_crl_object_write_helper(self, DER_FORMAT);
}

static char x509_crl_object_pprint__doc__[] =
  "This method returns a pretty-printed rendition of the CRL.\n"
  ;

static PyObject *
x509_crl_object_pprint(x509_crl_object *self)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  if (!X509_CRL_print(bio, self->crl))
    lose_openssl_error("Unable to pretty-print CRL");

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static struct PyMethodDef x509_crl_object_methods[] = {
  Define_Method(sign,           x509_crl_object_sign,                   METH_VARARGS),
  Define_Method(verify,         x509_crl_object_verify,                 METH_VARARGS),
  Define_Method(getVersion,     x509_crl_object_get_version,            METH_NOARGS),
  Define_Method(setVersion,     x509_crl_object_set_version,            METH_VARARGS),
  Define_Method(getIssuer,      x509_crl_object_get_issuer,             METH_VARARGS),
  Define_Method(setIssuer,      x509_crl_object_set_issuer,             METH_VARARGS),
  Define_Method(getThisUpdate,  x509_crl_object_get_this_update,        METH_NOARGS),
  Define_Method(setThisUpdate,  x509_crl_object_set_this_update,        METH_VARARGS),
  Define_Method(getNextUpdate,  x509_crl_object_get_next_update,        METH_NOARGS),
  Define_Method(setNextUpdate,  x509_crl_object_set_next_update,        METH_VARARGS),
  Define_Method(getRevoked,     x509_crl_object_get_revoked,            METH_NOARGS),
  Define_Method(addRevocations,	x509_crl_object_add_revocations,	METH_VARARGS),
  Define_Method(addExtension,   x509_crl_object_add_extension,          METH_VARARGS),
  Define_Method(clearExtensions, x509_crl_object_clear_extensions,      METH_NOARGS),
  Define_Method(countExtensions, x509_crl_object_count_extensions,      METH_NOARGS),
  Define_Method(getExtension,   x509_crl_object_get_extension,          METH_VARARGS),
  Define_Method(pemWrite,       x509_crl_object_pem_write,              METH_NOARGS),
  Define_Method(derWrite,       x509_crl_object_der_write,              METH_NOARGS),
  Define_Method(pprint,         x509_crl_object_pprint,                 METH_NOARGS),
  {NULL}
};

static void
x509_crl_object_dealloc(x509_crl_object *self)
{
  X509_CRL_free(self->crl);
  self->ob_type->tp_free((PyObject*) self);
}

static char x509_crltype__doc__[] =
  "This class provides access to OpenSSL X509 CRL management facilities.\n"
  ;

static PyTypeObject x509_crltype = {
  PyObject_HEAD_INIT(0)
  0,                                     /* ob_size */
  "POW.X509Crl",                         /* tp_name */
  sizeof(x509_crl_object),               /* tp_basicsize */
  0,                                     /* tp_itemsize */
  (destructor)x509_crl_object_dealloc,   /* tp_dealloc */
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
  x509_crltype__doc__,                   /* tp_doc */
  0,                                     /* tp_traverse */
  0,                                     /* tp_clear */
  0,                                     /* tp_richcompare */
  0,                                     /* tp_weaklistoffset */
  0,                                     /* tp_iter */
  0,                                     /* tp_iternext */
  x509_crl_object_methods,               /* tp_methods */
  0,                                     /* tp_members */
  0,                                     /* tp_getset */
  0,                                     /* tp_base */
  0,                                     /* tp_dict */
  0,                                     /* tp_descr_get */
  0,                                     /* tp_descr_set */
  0,                                     /* tp_dictoffset */
  0,                                     /* tp_init */
  0,                                     /* tp_alloc */
  x509_crl_object_new,                   /* tp_new */
};

/*========== x509 crl Code ==========*/

/*========== asymmetric Object ==========*/

static PyObject *
asymmetric_object_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  asymmetric_object *self = NULL;

  if ((self = (asymmetric_object *) type->tp_alloc(type, 0)) == NULL)
    goto error;

  self->cipher = NULL;

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

  if (!PyArg_ParseTupleAndKeywords(args, kwds, "|ii", kwlist, &cipher_type, &key_size))
    goto error;

  if (cipher_type != RSA_CIPHER)
    lose("unsupported cipher");

  switch (self->cipher_type) {

  case RSA_CIPHER:
    RSA_free(self->cipher);
    break;
  }

  if ((self->cipher = RSA_generate_key(key_size, RSA_F4, NULL, NULL)) == NULL)
    lose("could not generate key");

  self->key_type = RSA_PRIVATE_KEY;
  self->cipher_type = RSA_CIPHER;

  return 0;

 error:
  return -1;
}

static asymmetric_object *
asymmetric_object_pem_read(int key_type, BIO *in, char *pass)
{
  asymmetric_object *self = NULL;

  if ((self = (asymmetric_object *) asymmetric_object_new(&asymmetrictype, NULL, NULL)) == NULL)
    goto error;

  switch (key_type) {

  case RSA_PUBLIC_KEY:
    if ((self->cipher = PEM_read_bio_RSA_PUBKEY(in, NULL, NULL, NULL)) == NULL)
      lose_openssl_error("Couldn't load public key");
    self->key_type = RSA_PUBLIC_KEY;
    self->cipher_type = RSA_CIPHER;
    break;

  case RSA_PRIVATE_KEY:
    if ((self->cipher = PEM_read_bio_RSAPrivateKey(in, NULL, NULL, pass)) == NULL)
      lose_openssl_error("Couldn't load private key");
    self->key_type = RSA_PRIVATE_KEY;
    self->cipher_type = RSA_CIPHER;
    break;

  default:
    lose("Unknown key type");
  }

  return self;

 error:
  Py_XDECREF(self);
  return NULL;
}

static asymmetric_object *
asymmetric_object_der_read(int key_type, unsigned char *src, int len)
{
  asymmetric_object *self = NULL;

  if ((self = (asymmetric_object *) asymmetric_object_new(&asymmetrictype, NULL, NULL)) == NULL)
    goto error;

  switch (key_type) {
  case RSA_PUBLIC_KEY:

    if ((self->cipher = d2i_RSA_PUBKEY(NULL, (const unsigned char **) &src, len)) == NULL)
      lose_openssl_error("Couldn't load public key");

    self->key_type = RSA_PUBLIC_KEY;
    self->cipher_type = RSA_CIPHER;
    break;

  case RSA_PRIVATE_KEY:

    if ((self->cipher = d2i_RSAPrivateKey(NULL, (const unsigned char **) &src, len)) == NULL)
      lose_openssl_error("Couldn't load private key");

    self->key_type = RSA_PRIVATE_KEY;
    self->cipher_type = RSA_CIPHER;
    break;

  default:
    lose("Unknown key type");
  }

  return self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static char asymmetric_object_pem_write__doc__[] =
  "This method is used to write \"Asymmetric objects out as strings.\n"
  "\n"
  "The \"keytype\" argument should be one of:\n"
  "\n"
  "  * RSA_PUBLIC_KEY\n"
  "  * RSA_PRIVATE_KEY\n"
  "\n"
  "Private keys are often saved in encrypted files to offer extra\n"
  "security above access control mechanisms.  If the keytype parameter is\n"
  "RSA_PRIVATE_KEY, a \"passphrase\" parameter can also be specified, in\n"
  "which case the private key will be encrypted with AES-256-CBC using\n"
  "the given passphrase.\n"
  ;

#warning This probably ought to be separate methods for private and public keys.

static PyObject *
asymmetric_object_pem_write(asymmetric_object *self, PyObject *args)
{
  PyObject *result = NULL;
  char *passphrase = NULL;
  const EVP_CIPHER *evp_method = NULL;
  int key_type = 0;
  BIO *bio = NULL;

  if (!PyArg_ParseTuple(args, "|is", &key_type, &passphrase))
    goto error;

  if (key_type == 0)
    key_type = self->key_type;

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  switch(key_type) {

  case RSA_PRIVATE_KEY:

    if (passphrase)
      evp_method = EVP_aes_256_cbc();

    if (!PEM_write_bio_RSAPrivateKey(bio, self->cipher, evp_method, NULL, 0, NULL, passphrase))
      lose_openssl_error("Unable to write key");

    break;

  case RSA_PUBLIC_KEY:

    if (passphrase)
      lose("Public keys should not encrypted");

    if (!PEM_write_bio_RSA_PUBKEY(bio, self->cipher))
      lose_openssl_error("Unable to write key");

    break;

  default:
    lose("Unsupported key type");
  }

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static char asymmetric_object_der_write__doc__[] =
  "This method is used to write Asymmetric objects out as strings.\n"
  "\n"
  "The \"keytype\" parameter should be one of:\n"
  "\n"
  "  * RSA_PUBLIC_KEY\n"
  "  * RSA_PRIVATE_KEY\n"
  ;

static PyObject *
asymmetric_object_der_write(asymmetric_object *self, PyObject *args)
{
  PyObject *result = NULL;
  BIO *bio = NULL;
  int key_type = 0;

  if (!PyArg_ParseTuple(args, "|i", &key_type))
    goto error;

  if (key_type == 0)
    key_type = self->key_type;

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  switch (key_type) {

  case RSA_PRIVATE_KEY:
    if (!i2d_RSAPrivateKey_bio(bio, self->cipher))
      lose_openssl_error("Unable to write private key");
    break;

  case RSA_PUBLIC_KEY:
    if (!i2d_RSA_PUBKEY_bio(bio, self->cipher))
      lose_openssl_error("Unable to write public key");
    break;

  default:
    lose("Unsupported key type");
  }

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
  unsigned int digest_type = 0, signed_len = 0, digest_len = 0;
  PyObject *result = NULL;

  if (!PyArg_ParseTuple(args, "s#i", &digest_text, &digest_len, &digest_type))
    goto error;

  if (self->key_type != RSA_PRIVATE_KEY)
    lose("Unsupported key type");

  if ((signed_text = malloc(RSA_size(self->cipher))) == NULL)
    lose_no_memory();

  if (!RSA_sign(evp_digest_nid(digest_type),
                digest_text, digest_len,
                signed_text, &signed_len, self->cipher))
    lose_openssl_error("Couldn't sign digest");

  result = Py_BuildValue("s#", signed_text, signed_len);

 error:                         /* Fall through */
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

  if (!PyArg_ParseTuple(args, "s#s#i",
                        &signed_text, &signed_len,
                        &digest_text, &digest_len,
                        &digest_type))
    goto error;

  return PyBool_FromLong(RSA_verify(evp_digest_nid(digest_type),
                                    digest_text, digest_len,
                                    signed_text, signed_len, self->cipher));

 error:

  return NULL;
}

static struct PyMethodDef asymmetric_object_methods[] = {
  Define_Method(pemWrite,       asymmetric_object_pem_write,            METH_VARARGS),
  Define_Method(derWrite,       asymmetric_object_der_write,            METH_VARARGS),
  Define_Method(sign,           asymmetric_object_sign,                 METH_VARARGS),
  Define_Method(verify,         asymmetric_object_verify,               METH_VARARGS),
  {NULL}
};

static void
asymmetric_object_dealloc(asymmetric_object *self)
{
  switch (self->cipher_type) {
  case RSA_CIPHER:
    RSA_free(self->cipher);
    break;
  }
  self->ob_type->tp_free((PyObject*) self);
}

static char asymmetrictype__doc__[] =
  "This class provides basic access to RSA signature and verification.\n"
  "\n"
  LAME_DISCLAIMER_IN_ALL_CLASS_DOCUMENTATION
  ;

static PyTypeObject asymmetrictype = {
  PyObject_HEAD_INIT(0)
  0,                                     /* ob_size */
  "POW.Asymmetric",                      /* tp_name */
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
  asymmetrictype__doc__,                 /* tp_doc */
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

/*========== asymmetric Code ==========*/

/*========== digest Code ==========*/

static PyObject *
digest_object_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  digest_object *self = NULL;

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

  if ((new = (digest_object *) digest_object_new(&digesttype, NULL, NULL)) == NULL)
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

static void
digest_object_dealloc(digest_object *self)
{
  EVP_MD_CTX_cleanup(&self->digest_ctx);
  self->ob_type->tp_free((PyObject*) self);
}

static char digesttype__doc__[] =
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

static PyTypeObject digesttype = {
  PyObject_HEAD_INIT(0)
  0,                                  /* ob_size */
  "POW.Digest",                       /* tp_name */
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
  digesttype__doc__,                  /* tp_doc */
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

/*========== digest Code ==========*/

/*========== CMS code ==========*/

static PyObject *
cms_object_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
  cms_object *self;

  if ((self = (cms_object *) type->tp_alloc(type, 0)) != NULL)
    return (PyObject *) self;
 
  Py_XDECREF(self);
  return NULL;
}

static cms_object *
cms_object_pem_read(BIO *in)
{
  cms_object *self;

  if ((self = (cms_object *) cms_object_new(&cmstype, NULL, NULL)) == NULL)
    goto error;

  if ((self->cms = PEM_read_bio_CMS(in, NULL, NULL, NULL)) == NULL)
    lose_openssl_error("Couldn't load PEM encoded CMS message");

  return self;

 error:
  Py_XDECREF(self);
  return NULL;
}

static cms_object *
cms_object_der_read(char *src, int len)
{
  cms_object *self;
  BIO *bio = NULL;

  if ((self = (cms_object *) cms_object_new(&cmstype, NULL, NULL)) == NULL)
    goto error;

  if ((self->cms = CMS_ContentInfo_new()) == NULL ||
      (bio = BIO_new_mem_buf(src, len)) == NULL)
    lose_no_memory();

  if (!d2i_CMS_bio(bio, &self->cms))
    lose_openssl_error("Couldn't load DER encoded CMS message");

  BIO_free(bio);

  return self;

 error:
  BIO_free(bio);
  Py_XDECREF(self);
  return NULL;
}

static PyObject *
cms_object_write_helper(cms_object *self, int format)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  switch (format) {

  case DER_FORMAT:
    if (!i2d_CMS_bio(bio, self->cms))
      lose_openssl_error("Unable to write CMS object");
    break;

  case PEM_FORMAT:
    if (!PEM_write_bio_CMS(bio, self->cms))
      lose_openssl_error("Unable to write CMS object");
    break;

  default:
    lose("Internal error, unknown output format");
  }

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static char cms_object_pem_write__doc__[] =
  "This method returns a PEM encoded CMS message as a string.\n"
  ;

static PyObject *
cms_object_pem_write(cms_object *self)
{
  return cms_object_write_helper(self, PEM_FORMAT);
}

static char cms_object_der_write__doc__[] =
  "This method returns a DER encoded CMS message as a string.\n"
  ;

static PyObject *
cms_object_der_write(cms_object *self)
{
  return cms_object_write_helper(self, DER_FORMAT);
}

static char cms_object_sign__doc__[] =
  "This method signs a message with a private key.\n"
  "\n"
  "the \"signcert\" parameter should be the certificate against which the\n"
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
  x509_crl_object *crlobj = NULL;
  PyObject *x509_sequence = Py_None;
  PyObject *crl_sequence = Py_None;
  PyObject *result = NULL;
  STACK_OF(X509) *x509_stack = NULL;
  EVP_PKEY *pkey = NULL;
  char *buf = NULL, *oid = NULL;
  int i, n, len;
  unsigned flags = 0;
  BIO *bio = NULL;
  CMS_ContentInfo *cms = NULL;
  ASN1_OBJECT *econtent_type = NULL;

  if (!PyArg_ParseTuple(args, "O!O!s#|OOsI",
                        &x509type, &signcert,
                        &asymmetrictype, &signkey,
                        &buf, &len,
                        &x509_sequence,
                        &crl_sequence,
                        &oid,
                        &flags))
    goto error;

  assert_no_unhandled_openssl_errors();

  flags &= CMS_NOCERTS | CMS_NOATTR;
  flags |= CMS_BINARY | CMS_NOSMIMECAP | CMS_PARTIAL | CMS_USE_KEYID;

  if (signkey->key_type != RSA_PRIVATE_KEY)
    lose("Unsupported key type");

  if ((x509_stack = x509_helper_sequence_to_stack(x509_sequence)) == NULL)
    goto error;

  assert_no_unhandled_openssl_errors();

  if ((pkey = EVP_PKEY_new()) == NULL)
    lose_no_memory();

  assert_no_unhandled_openssl_errors();

  if (!EVP_PKEY_assign_RSA(pkey, signkey->cipher))
    lose_openssl_error("EVP_PKEY assignment error");

  assert_no_unhandled_openssl_errors();

  if ((bio = BIO_new_mem_buf(buf, len)) == NULL)
    lose_no_memory();

  assert_no_unhandled_openssl_errors();

  if (oid && (econtent_type = OBJ_txt2obj(oid, 0)) == NULL)
    lose_openssl_error("Couldn't parse OID");

  assert_no_unhandled_openssl_errors();

  if ((cms = CMS_sign(NULL, NULL, x509_stack, bio, flags)) == NULL)
    lose_openssl_error("Couldn't create CMS message");

  assert_no_unhandled_openssl_errors();

  if (econtent_type)
    CMS_set1_eContentType(cms, econtent_type);

  assert_no_unhandled_openssl_errors();

  if (!CMS_add1_signer(cms, signcert->x509, pkey, EVP_sha256(), flags))
    lose_openssl_error("Couldn't sign CMS message");

  pkey = NULL;                 /* CMS_add1_signer() now owns pkey */

  assert_no_unhandled_openssl_errors();

  if (crl_sequence != Py_None) {

    if (!PySequence_Check(crl_sequence))
      lose_type_error("Inapropriate type");

    n = PySequence_Size(crl_sequence);

    for (i = 0; i < n; i++) {

      if ((crlobj = (x509_crl_object *) PySequence_GetItem(crl_sequence, i)) == NULL)
        goto error;

      if (!POW_X509_CRL_Check(crlobj))
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

  result = Py_BuildValue("");

 error:                          /* fall through */

  assert_no_unhandled_openssl_errors();

  CMS_ContentInfo_free(cms);
  BIO_free(bio);
  sk_X509_free(x509_stack);
  EVP_PKEY_free(pkey);
  ASN1_OBJECT_free(econtent_type);
  Py_XDECREF(crlobj);

  return result;
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
cms_object_verify(cms_object *self, PyObject *args)
{
  x509_store_object *store = NULL;
  PyObject *result = NULL, *certs_sequence = Py_None;
  STACK_OF(X509) *certs_stack = NULL;
  unsigned flags = 0;
  BIO *bio = NULL;

  if (!PyArg_ParseTuple(args, "O!|OI", &x509_storetype, &store, &certs_sequence, &flags))
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

  result = BIO_to_PyString_helper(bio);

 error:                          /* fall through */

  assert_no_unhandled_openssl_errors();

  sk_X509_free(certs_stack);
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
  char buf[512];

  if ((oid = CMS_get0_eContentType(self->cms)) == NULL)
    lose_openssl_error("Couldn't extract eContentType from CMS message");

  if (OBJ_obj2txt(buf, sizeof(buf), oid, 1) <= 0)
    lose("Couldn't translate OID");

  result = Py_BuildValue("s", buf);

 error:

  assert_no_unhandled_openssl_errors();

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

  assert_no_unhandled_openssl_errors();

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

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose_no_memory();

  if (!CMS_ContentInfo_print_ctx(bio, self->cms, 0, NULL))
    lose_openssl_error("Unable to pretty-print CMS object");

  result = BIO_to_PyString_helper(bio);

 error:                          /* fall through */
  assert_no_unhandled_openssl_errors();
  BIO_free(bio);
  return result;
}

static PyObject *
cms_object_helper_get_cert(void *cert)
{
  x509_object *obj = (x509_object *) x509_object_new(&x509type, NULL, NULL);

  if (obj) {
    X509_free(obj->x509);
    obj->x509 = cert;
  }

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
  x509_crl_object *obj = (x509_crl_object *) x509_crl_object_new(&x509_crltype, NULL, NULL);

  if (obj) {
    X509_CRL_free(obj->crl);
    obj->crl = crl;
  }

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
  Define_Method(pemWrite,       cms_object_pem_write,           METH_NOARGS),
  Define_Method(derWrite,       cms_object_der_write,           METH_NOARGS),
  Define_Method(sign,           cms_object_sign,                METH_VARARGS),
  Define_Method(verify,         cms_object_verify,              METH_VARARGS),
  Define_Method(eContentType,   cms_object_eContentType,        METH_NOARGS),
  Define_Method(signingTime,    cms_object_signingTime,         METH_NOARGS),
  Define_Method(pprint,         cms_object_pprint,              METH_NOARGS),
  Define_Method(certs,          cms_object_certs,               METH_NOARGS),
  Define_Method(crls,           cms_object_crls,                METH_NOARGS),
  {NULL}
};

static void
cms_object_dealloc(cms_object *self)
{
  CMS_ContentInfo_free(self->cms);
  self->ob_type->tp_free((PyObject*) self);
}

static char cmstype__doc__[] =
  "This class provides basic access OpenSSL's CMS functionality.\n"
  "At present this only handes signed objects, as those are the\n"
  "only kind of CMS objects used in RPKI.\n"
  ;

static PyTypeObject cmstype = {
  PyObject_HEAD_INIT(0)
  0,                                  /* ob_size */
  "POW.CMS",                          /* tp_name */
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
  cmstype__doc__,                     /* tp_doc */
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

/*========== CMS Code ==========*/

/*========== module functions ==========*/

static char pow_module_pem_read__doc__[] =
  "This function should be replaced by class methods for the several\n"
  "kinds of objects this function currently returns.\n"
  "\n"
  "For now, here is the old documentation for this function.\n"
  "\n"
  "<modulefunction>\n"
  "   <header>\n"
  "      <name>pemRead</name>\n"
  "      <parameter>type</parameter>\n"
  "      <parameter>string</parameter>\n"
  "      <parameter>pass = None</parameter>\n"
  "   </header>\n"
  "   <body>\n"
  "      <para>\n"
  "         This function attempts to parse the <parameter>string</parameter> according to the PEM\n"
  "         type passed. <parameter>type</parameter> should be one of the\n"
  "         following:\n"
  "      </para>\n"
  "      <simplelist>\n"
  "         <member><constant>RSA_PUBLIC_KEY</constant></member>\n"
  "         <member><constant>RSA_PRIVATE_KEY</constant></member>\n"
  "         <member><constant>X509_CERTIFICATE</constant></member>\n"
  "         <member><constant>X509_CRL</constant></member>\n"
  "         <member><constant>CMS_MESSAGE</constant></member>\n"
  "      </simplelist>\n"
  "      <para>\n"
  "         <parameter>pass</parameter> should only be provided if an encrypted\n"
  "         <classname>Asymmetric</classname> is being loaded.  If the password\n"
  "         is incorrect an exception will be raised, if no password is provided\n"
  "         and the PEM file is encrypted the user will be prompted.  If this is\n"
  "         not desirable, always supply a password.  The object returned will be\n"
  "         and instance of <classname>Asymmetric</classname>,\n"
  "         <classname>X509</classname>, <classname>X509Crl</classname>,\n"
  "         or <classname>CMS</classname>.\n"
  "      </para>\n"
  "   </body>\n"
  "</modulefunction>\n"
  ;

static PyObject *
pow_module_pem_read (PyObject *self, PyObject *args)
{
  BIO *in = NULL;
  PyObject *obj = NULL;
  int object_type = 0, len = 0;
  char *pass = NULL, *src = NULL;

  if (!PyArg_ParseTuple(args, "is#|s", &object_type, &src, &len, &pass))
    goto error;

  if ((in = BIO_new_mem_buf(src, len)) == NULL)
    lose_no_memory();

  switch(object_type) {
  case RSA_PRIVATE_KEY:
    obj = (PyObject *) asymmetric_object_pem_read(object_type, in, pass);
    break;
  case RSA_PUBLIC_KEY:
    obj = (PyObject *) asymmetric_object_pem_read(object_type, in, pass);
    break;
  case X509_CERTIFICATE:
    obj = (PyObject *) x509_object_pem_read(in);
    break;
  case X_X509_CRL:
    obj = (PyObject *) x509_crl_object_pem_read(in);
    break;
  case CMS_MESSAGE:
    obj = (PyObject *) cms_object_pem_read(in);
    break;
  default:
    lose("Unknown PEM encoding");
  }

  BIO_free(in);

  if (obj)
    return obj;

 error:

  return NULL;
}

static char pow_module_der_read__doc__[] =
  "This function should be replaced by class methods for the several\n"
  "kinds of objects this function currently returns.\n"
  "\n"
  "For now, here is the old documentation for this function.\n"
  "\n"
  "<modulefunction>\n"
  "   <header>\n"
  "      <name>derRead</name>\n"
  "      <parameter>type</parameter>\n"
  "      <parameter>string</parameter>\n"
  "   </header>\n"
  "   <body>\n"
  "      <para>\n"
  "         This function attempts to parse the <parameter>string</parameter> according to the PEM\n"
  "         type passed. <parameter>type</parameter> should be one of the\n"
  "         following:\n"
  "      </para>\n"
  "      <simplelist>\n"
  "         <member><constant>RSA_PUBLIC_KEY</constant></member>\n"
  "         <member><constant>RSA_PRIVATE_KEY</constant></member>\n"
  "         <member><constant>X509_CERTIFICATE</constant></member>\n"
  "         <member><constant>X509_CRL</constant></member>\n"
  "         <member><constant>CMS_MESSAGE</constant></member>\n"
  "      </simplelist>\n"
  "      <para>\n"
  "         As with the PEM operations, the object returned will be and instance\n"
  "         of <classname>Asymmetric</classname>, <classname>X509</classname>,\n"
  "         <classname>X509Crl</classname>, or <classname>CMS</classname>.\n"
  "      </para>\n"
  "   </body>\n"
  "</modulefunction>\n"
  ;

static PyObject *
pow_module_der_read (PyObject *self, PyObject *args)
{
  PyObject *obj = NULL;
  int object_type = 0, len = 0;
  unsigned char *src = NULL;

  if (!PyArg_ParseTuple(args, "is#", &object_type, &src, &len))
    goto error;

  switch(object_type) {
  case RSA_PRIVATE_KEY:
    obj = (PyObject *) asymmetric_object_der_read(object_type, src, len);
    break;
  case RSA_PUBLIC_KEY:
    obj = (PyObject *) asymmetric_object_der_read(object_type, src, len);
    break;
  case X509_CERTIFICATE:
    obj = (PyObject *) x509_object_der_read(src, len);
    break;
  case X_X509_CRL:
    obj = (PyObject *) x509_crl_object_der_read(src, len);
    break;
  case CMS_MESSAGE:
    obj = (PyObject *) cms_object_der_read((char *) src, len);
    break;
  default:
    lose("Unknown DER encoding");
  }

  if (obj)
    return obj;

 error:

  return NULL;
}

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

  if (!error)
    Py_RETURN_NONE;

  ERR_error_string_n(error, buf, sizeof(buf));
  return Py_BuildValue("s", buf);

 error:
  return NULL;
}

static char pow_module_clear_error__doc__[] =
  "Remove all errors from OpenSSL's global error stack.\n"
  ;

static PyObject *
pow_module_clear_error(PyObject *self)
{
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

  if (!PyArg_ParseTuple(args, "s|i", &file, &len))
    goto error;

  if (!RAND_load_file(file, len))
    lose("Couldn't load random file");

  Py_RETURN_NONE;

 error:

  return NULL;
}

static struct PyMethodDef pow_module_methods[] = {
  Define_Method(pemRead,        pow_module_pem_read,            METH_VARARGS),
  Define_Method(derRead,        pow_module_der_read,            METH_VARARGS),
  Define_Method(getError,       pow_module_get_error,           METH_NOARGS),
  Define_Method(clearError,     pow_module_clear_error,         METH_NOARGS),
  Define_Method(seed,           pow_module_seed,                METH_VARARGS),
  Define_Method(add,            pow_module_add,                 METH_VARARGS),
  Define_Method(readRandomFile, pow_module_read_random_file,    METH_VARARGS),
  Define_Method(writeRandomFile, pow_module_write_random_file,  METH_VARARGS),
  Define_Method(addObject,      pow_module_add_object,          METH_VARARGS),
  {NULL}
};

/*========== module functions ==========*/

/*==========================================================================*/

void
init_POW(void)
{
  PyObject *m = Py_InitModule3("_POW", pow_module_methods, pow_module__doc__);

#define Define_Class(__type__)                                          \
  do {                                                                  \
    char *__name__ = strchr(__type__.tp_name, '.');                     \
    if (PyType_Ready(&__type__) == 0 && __name__ != NULL) {             \
      Py_INCREF(&__type__);                                             \
      PyModule_AddObject(m, __name__+1, (PyObject *) &__type__);        \
    }                                                                   \
  } while (0)

  Define_Class(x509type);
  Define_Class(x509_storetype);
  Define_Class(x509_crltype);
  Define_Class(asymmetrictype);
  Define_Class(digesttype);
  Define_Class(cmstype);
  Define_Class(ipaddresstype);

#undef Define_Class

#define Define_Exception(__name__, __parent__)                  \
  PyModule_AddObject(m, #__name__, ((__name__##Object)          \
    = PyErr_NewException("POW." #__name__, __parent__, NULL)))

  Define_Exception(Error,	  NULL);
  Define_Exception(OpenSSLError,  ErrorObject);
  Define_Exception(POWError,	  ErrorObject);

#undef Define_Exception

#define Define_Integer_Constant(__name__) \
  PyModule_AddIntConstant(m, #__name__, __name__)

  /* Object format types */
  Define_Integer_Constant(LONGNAME_FORMAT);
  Define_Integer_Constant(SHORTNAME_FORMAT);
  Define_Integer_Constant(OIDNAME_FORMAT);

  /* PEM encoded types */
#ifndef OPENSSL_NO_RSA
  Define_Integer_Constant(RSA_PUBLIC_KEY);
  Define_Integer_Constant(RSA_PRIVATE_KEY);
#endif
#ifndef OPENSSL_NO_DSA
  Define_Integer_Constant(DSA_PUBLIC_KEY);
  Define_Integer_Constant(DSA_PRIVATE_KEY);
#endif
#ifndef OPENSSL_NO_DH
  Define_Integer_Constant(DH_PUBLIC_KEY);
  Define_Integer_Constant(DH_PRIVATE_KEY);
#endif
  Define_Integer_Constant(X509_CERTIFICATE);
  PyModule_AddIntConstant(m, "X509_CRL", X_X509_CRL);
  Define_Integer_Constant(CMS_MESSAGE);

  /* Asymmetric ciphers */
#ifndef OPENSSL_NO_RSA
  Define_Integer_Constant(RSA_CIPHER);
#endif
#ifndef OPENSSL_NO_DSA
  Define_Integer_Constant(DSA_CIPHER);
#endif
#ifndef OPENSSL_NO_DH
  Define_Integer_Constant(DH_CIPHER);
#endif

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

  if (PyErr_Occurred())
    Py_FatalError("Can't initialize module POW");
}

/*==========================================================================*/

/*
 * Local Variables:
 * indent-tabs-mode: nil
 * End:
 */
