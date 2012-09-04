/*****************************************************************************/
/*                                                                           */
/*  Copyright (c) 2001, 2002, Peter Shannon                                  */
/*  All rights reserved.                                                     */
/*                                                                           */
/*  Redistribution and use in source and binary forms, with or without       */
/*  modification, are permitted provided that the following conditions       */
/*  are met:                                                                 */
/*                                                                           */
/*      * Redistributions of source code must retain the above               */
/*        copyright notice, this list of conditions and the following        */
/*        disclaimer.                                                        */
/*                                                                           */
/*      * Redistributions in binary form must reproduce the above            */
/*        copyright notice, this list of conditions and the following        */
/*        disclaimer in the documentation and/or other materials             */
/*        provided with the distribution.                                    */
/*                                                                           */
/*      * The name of the contributors may be used to endorse or promote     */
/*        products derived from this software without specific prior         */
/*        written permission.                                                */
/*                                                                           */
/*  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS      */
/*  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT        */
/*  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS        */
/*  FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS   */
/*  OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,          */
/*  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT         */
/*  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,    */
/*  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY    */
/*  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT      */
/*  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE    */
/*  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.     */
/*                                                                           */
/*****************************************************************************/

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

// Symmetric ciphers
#define DES_ECB               1
#define DES_EDE               2
#define DES_EDE3              3
#define DES_CFB               4
#define DES_EDE_CFB           5
#define DES_EDE3_CFB          6
#define DES_OFB               7
#define DES_EDE_OFB           8
#define DES_EDE3_OFB          9
#define DES_CBC               10
#define DES_EDE_CBC           11
#define DES_EDE3_CBC          12
#define DESX_CBC              13
#define RC4                   14
#define RC4_40                15
#define IDEA_ECB              16
#define IDEA_CFB              17
#define IDEA_OFB              18
#define IDEA_CBC              19
#define RC2_ECB               20
#define RC2_CBC               21
#define RC2_40_CBC            22
#define RC2_CFB               23
#define RC2_OFB               24
#define BF_ECB                25
#define BF_CBC                26
#define BF_CFB                27
#define BF_OFB                28
#define CAST5_ECB             29
#define CAST5_CBC             30
#define CAST5_CFB             31
#define CAST5_OFB             32
#define RC5_32_12_16_CBC      33
#define RC5_32_12_16_CFB      34
#define RC5_32_12_16_ECB      35
#define RC5_32_12_16_OFB      36

// PEM encoded data types
#define RSA_PUBLIC_KEY        1
#define RSA_PRIVATE_KEY       2
#define DSA_PUBLIC_KEY        3
#define DSA_PRIVATE_KEY       4
#define DH_PUBLIC_KEY         5
#define DH_PRIVATE_KEY        6
#define X509_CERTIFICATE      7
#define X_X509_CRL            8     // X509_CRL already used by OpenSSL library
#define CMS_MESSAGE           9

// Asymmetric ciphers
#define RSA_CIPHER            1
#define DSA_CIPHER            2
#define DH_CIPHER             3

// Digests
#define MD5_DIGEST            2
#define SHA_DIGEST            3
#define SHA1_DIGEST           4
#define SHA256_DIGEST         6
#define SHA384_DIGEST         7
#define SHA512_DIGEST         8

// Object format
#define SHORTNAME_FORMAT      1
#define LONGNAME_FORMAT       2
#define	OIDNAME_FORMAT        3

// Output format
#define PEM_FORMAT            1
#define DER_FORMAT            2

// Object check functions
#define X_X509_Check(op)         ((op)->ob_type == &x509type)
#define X_X509_store_Check(op)   ((op)->ob_type == &x509_storetype)
#define X_X509_crl_Check(op)     ((op)->ob_type == &x509_crltype)
#define X_X509_revoked_Check(op) ((op)->ob_type == &x509_revokedtype)
#define X_asymmetric_Check(op)   ((op)->ob_type == &asymmetrictype)
#define X_digest_Check(op)       ((op)->ob_type == &digesttype)
#define X_cms_Check(op)          ((op)->ob_type == &cmstype)

static char pow_module__doc__ [] =
"<moduleDescription>\n"
"   <header>\n"
"      <name>POW</name>\n"
"      <author>Peter Shannon</author>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This third major release of POW addresses the most critical missing\n"
"         parts of functionality, X509v3 support.  Initially I thought adding\n"
"         support via the OpenSSL code would be the easiest option but this\n"
"         proved to be incorrect mainly due to the way I have chosen to handle\n"
"         the complex data such as <classname>directoryNames</classname> and\n"
"         <classname>generalNames</classname>.  It is easier in python to\n"
"         construct complex sets of data using lists and dictionaries than\n"
"         coordinate large numbers of objects and method calls.  This is no\n"
"         criticism, it is just extremely easy.  Coding complex data such as the\n"
"         <classname>certificatePolicies</classname> coding coding routines in C\n"
"         to handle the data proved laborous and ultimately error prone.\n"
"      </para>\n"
"      <para>\n"
"         PKIX structures are supported by a few operations on the relevant POW\n"
"         objects and through a Python library which is modelled on the DER\n"
"         encoding rules.  Modeling DER does expose some of the complexities of\n"
"         the ASN1 specifications but avoids coding many assumptions into the\n"
"         data structures and the interface for the objects.  For an example of\n"
"         overly complex definitions take a look at the\n"
"         <classname>Name</classname> object in RFC3280.  It is equally\n"
"         important that modeling DER in the way leads to a library which is\n"
"         trivial to extend to support new objects - simple objects are one\n"
"         liners and complex objects only require the definition of a new\n"
"         constructor.\n"
"      </para>\n"
"      <para>\n"
"         functionality have been plugged.  The <classname>Ssl</classname> class has received\n"
"         several new features relating to security.  Other areas have been\n"
"         improved: PRNG support, certificate and CRL signing, certificate chain\n"
"         and client verification.  Many bugs have been fixed, and certain\n"
"         parts of code re-written where necessary.  I hope you enjoy using POW\n"
"         and please feel free to send me feature requests and bug reports.\n"
"      </para>\n"
"   </body>\n"
"</moduleDescription>\n"
;

/*========== Pre-definitions ==========*/
static PyObject
  *ErrorObject,
  *POWErrorObject,
  *POWSyscallErrorObject,
  *POWErrorSSLErrorObject,
  *POWSyscallSSLErrorObject,
  *POWUnexpectedEOFErrorObject,
  *POWOtherErrorObject;

static PyTypeObject
  x509type,
  x509_storetype,
  x509_crltype,
  x509_revokedtype,
  asymmetrictype,
  digesttype,
  cmstype;
/*========== Pre-definitions ==========*/

/*========== C structs ==========*/
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
  X509_REVOKED *revoked;
} x509_revoked_object;

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
    PyErr_SetString(ErrorObject, (_msg_));                              \
    goto error;                                                         \
  } while (0)

#define lose_type_error(_msg_)                                          \
  do {                                                                  \
    PyErr_SetString(PyExc_TypeError, (_msg_));                          \
    goto error;                                                         \
  } while (0)

#define lose_openssl_error(_msg_)                                       \
  do {                                                                  \
    set_openssl_exception(ErrorObject, (_msg_));                        \
    goto error;                                                         \
  } while (0)

#define lose_ssl_error(_self_, _code_)                                  \
  do {                                                                  \
    set_openssl_ssl_exception(_self_, _code_);                          \
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

static int
docset_helper_add(PyObject *set, char *v)
{
  PyObject *value = NULL;

  if ((value = PyString_FromString(v)) == NULL)
    lose("could not allocate memory");

  if (PyList_Append(set, value) != 0)
    goto error;

  Py_XDECREF(value);
  return 1;

 error:

  Py_XDECREF(value);
  return 0;
}

/*
 * Generate an encrypion envelope.  Saves a lot of space having this case
 * statement in one place.
 */
static const EVP_CIPHER *
evp_cipher_factory(int cipher_type)
{
  switch(cipher_type) {
#ifndef OPENSSL_NO_DES
  case DES_ECB:           return EVP_des_ecb();
  case DES_EDE:           return EVP_des_ede();
  case DES_EDE3:          return EVP_des_ede3();
  case DES_CFB:           return EVP_des_cfb();
  case DES_EDE_CFB:       return EVP_des_ede_cfb();
  case DES_EDE3_CFB:      return EVP_des_ede3_cfb();
  case DES_OFB:           return EVP_des_ofb();
  case DES_EDE_OFB:       return EVP_des_ede_ofb();
  case DES_EDE3_OFB:      return EVP_des_ede3_ofb();
  case DES_CBC:           return EVP_des_cbc();
  case DES_EDE_CBC:       return EVP_des_ede_cbc();
  case DES_EDE3_CBC:      return EVP_des_ede3_cbc();
  case DESX_CBC:          return EVP_desx_cbc();
#endif
#ifndef OPENSSL_NO_RC4
  case RC4:               return EVP_rc4();
  case RC4_40:            return EVP_rc4_40();
#endif
#ifndef OPENSSL_NO_IDEA
  case IDEA_ECB:          return EVP_idea_ecb();
  case IDEA_CFB:          return EVP_idea_cfb();
  case IDEA_OFB:          return EVP_idea_ofb();
  case IDEA_CBC:          return EVP_idea_cbc();
#endif
#ifndef OPENSSL_NO_RC2
  case RC2_ECB:           return EVP_rc2_ecb();
  case RC2_CBC:           return EVP_rc2_cbc();
  case RC2_40_CBC:        return EVP_rc2_40_cbc();
  case RC2_CFB:           return EVP_rc2_cfb();
  case RC2_OFB:           return EVP_rc2_ofb();
#endif
#ifndef OPENSSL_NO_BF
  case BF_ECB:            return EVP_bf_ecb();
  case BF_CBC:            return EVP_bf_cbc();
  case BF_CFB:            return EVP_bf_cfb();
  case BF_OFB:            return EVP_bf_ofb();
#endif
#ifndef OPENSSL_NO_CAST5
  case CAST5_ECB:         return EVP_cast5_ecb();
  case CAST5_CBC:         return EVP_cast5_cbc();
  case CAST5_CFB:         return EVP_cast5_cfb();
  case CAST5_OFB:         return EVP_cast5_ofb();
#endif
#ifndef OPENSSL_NO_RC5
  case RC5_32_12_16_CBC:  return EVP_rc5_32_12_16_cbc();
  case RC5_32_12_16_CFB:  return EVP_rc5_32_12_16_cfb();
  case RC5_32_12_16_ECB:  return EVP_rc5_32_12_16_ecb();
  case RC5_32_12_16_OFB:  return EVP_rc5_32_12_16_ofb();
#endif
  default:                return NULL;
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

static PyObject *
X509_object_helper_set_name(X509_NAME *name, PyObject *dn_obj)
{
  PyObject *rdn_obj = NULL;
  PyObject *pair_obj = NULL;
  PyObject *type_obj = NULL;
  PyObject *value_obj = NULL;
  char *type_str, *value_str;
  int asn1_type, i, j;

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

      if ((type_obj = PySequence_GetItem(pair_obj, 0)) == NULL ||
          (type_str = PyString_AsString(type_obj)) == NULL || 
          (value_obj = PySequence_GetItem(pair_obj, 1)) == NULL ||
          (value_str = PyString_AsString(value_obj)) == NULL)
        goto error;

      if ((asn1_type = ASN1_PRINTABLE_type(value_str, -1)) != V_ASN1_PRINTABLESTRING)
        asn1_type = V_ASN1_UTF8STRING;

      if (!X509_NAME_add_entry_by_txt(name, type_str, asn1_type,
                                      value_str, strlen(value_str),
                                      -1, (j ? -1 : 0)))
        lose("unable to add name entry");

      Py_XDECREF(pair_obj);
      Py_XDECREF(type_obj);
      Py_XDECREF(value_obj);
      pair_obj = type_obj = value_obj = NULL;
    }

    Py_XDECREF(rdn_obj);
    rdn_obj = NULL;
  }

  Py_RETURN_NONE;

 error:
  Py_XDECREF(rdn_obj);
  Py_XDECREF(pair_obj);
  Py_XDECREF(type_obj);
  Py_XDECREF(value_obj);
  return NULL;
}

static PyObject *
X509_object_helper_get_name(X509_NAME *name, int format)
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
    lose("could not allocate memory");

  for (i = 0; i < X509_NAME_entry_count(name); i++) {

    if ((entry = X509_NAME_get_entry(name, i)) == NULL)
      lose("could not get certificate name");

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
      lose("unknown name format");
    }

    if (oid == NULL) {
      if (OBJ_obj2txt(oidbuf, sizeof(oidbuf), entry->object, 1) <= 0)
        lose("could not translate OID");
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
      lose("impossible set count for DN, something went horribly wrong");
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

  if (x509_sequence != Py_None && !PyTuple_Check(x509_sequence) && !PyList_Check(x509_sequence))
    lose_type_error("Inapropriate type");

  if ((x509_stack = sk_X509_new_null()) == NULL)
    lose("Couldn't create new X509 stack");

  if (x509_sequence != Py_None) {
    size = PySequence_Size(x509_sequence);

    for (i = 0; i < size; i++) {
      if ((x509obj = (x509_object*) PySequence_GetItem(x509_sequence, i)) == NULL)
        goto error;

      if (!X_X509_Check(x509obj))
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

static PyObject *
stack_to_tuple_helper(_STACK *sk, PyObject *(*handler)(void *))
{
  PyObject *result_list = NULL, *result_tuple = NULL, *obj = NULL;

  if ((result_list = PyList_New(0)) == NULL)
    lose("could not allocate memory");

  while (sk_num(sk)) {

    if ((obj = handler(sk_value(sk, 0))) == NULL)
      lose("could not allocate memory");

    sk_shift(sk);

    if (PyList_Append(result_list, obj) != 0)
      goto error;

    Py_XDECREF(obj);
    obj = NULL;
  }

  result_tuple = PyList_AsTuple(result_list);
  Py_XDECREF(result_list);

  return result_tuple;

 error:

  Py_XDECREF(obj);
  Py_XDECREF(result_list);
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

static int
python_ASN1_TIME_set_string(ASN1_TIME *t, const char *s)
{
  if (t == NULL || s == NULL || strlen(s) < 10)
    return 0;
  if ((s[0] == '1' && s[1] == '9' && s[2] > '4') ||
      (s[0] == '2' && s[1] == '0' && s[2] < '5'))
    return ASN1_UTCTIME_set_string(t, s + 2);
  else
    return ASN1_GENERALIZEDTIME_set_string(t, s);
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
    lose("unable to get BIO data");

  return Py_BuildValue("s#", ptr, len);

 error:
  return NULL;
}

/*========== helper functions ==========*/

/*========== X509 code ==========*/
static x509_object *
X509_object_new(void)
{
  x509_object *self;

  self = PyObject_New(x509_object, &x509type);
  if (self == NULL)
    goto error;

  self->x509 = X509_new();
  return self;

 error:

  Py_XDECREF(self);
  return NULL;
}

/*
 * This function is pretty dumb.  Most of the work is done by the module
 * function pow_module_pem_read().
 */
static x509_object *
X509_object_pem_read(BIO *in)
{
  x509_object *self;

  if ((self = PyObject_New(x509_object, &x509type)) == NULL)
    goto error;

  if ((self->x509 = PEM_read_bio_X509(in, NULL, NULL, NULL)) == NULL)
    lose("could not load PEM encoded certificate");

  return self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static x509_object *
X509_object_der_read(unsigned char *src, int len)
{
  x509_object *self;
  unsigned char *ptr = src;

  if ((self = PyObject_New(x509_object, &x509type)) == NULL)
    goto error;

  self->x509 = X509_new();

  if(!d2i_X509(&self->x509, (const unsigned char **) &ptr, len))
    lose("could not load PEM encoded certificate");

  return self;

 error:

  Py_XDECREF(self);
  return NULL;
}

/*
 * Unlike the previous function this creates the BIO itself.  The BIO_s_mem
 * is used as a buffer which the certificate is read into, from this buffer
 * it is read into a char[] and returned as a string.
 */
static PyObject *
X509_object_write_helper(x509_object *self, PyObject *args, int format)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  if (!PyArg_ParseTuple(args, ""))
    return NULL;

  bio = BIO_new(BIO_s_mem());

  switch (format) {

  case DER_FORMAT:
    if (!i2d_X509_bio(bio, self->x509))
      lose("unable to write certificate");
    break;

  case PEM_FORMAT:
    if (!PEM_write_bio_X509(bio, self->x509))
      lose("unable to write certificate");
    break;

  default:
    lose("internal error, unknown output format");
  }

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static char X509_object_pem_write__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509</memberof>\n"
"      <name>pemWrite</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns a PEM encoded certificate as a\n"
"         string.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
X509_object_pem_write(x509_object *self, PyObject *args)
{
  return X509_object_write_helper(self, args, PEM_FORMAT);
}

static char X509_object_der_write__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509</memberof>\n"
"      <name>derWrite</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns a DER encoded certificate as a\n"
"         string.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
X509_object_der_write(x509_object *self, PyObject *args)
{
  return X509_object_write_helper(self, args, DER_FORMAT);
}

/*
 * Currently this function only supports RSA keys.
 */
static char X509_object_set_public_key__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509</memberof>\n"
"      <name>setPublicKey</name>\n"
"      <parameter>key</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method sets the public key for this certificate object.  The\n"
"         parameter <parameter>key</parameter> should be an instance of\n"
"         <classname>Asymmetric</classname> containing a public key.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;


static PyObject *
X509_object_set_public_key(x509_object *self, PyObject *args)
{
  EVP_PKEY *pkey = NULL;
  asymmetric_object *asym;

  if (!PyArg_ParseTuple(args, "O!", &asymmetrictype, &asym))
    goto error;

  if ((pkey = EVP_PKEY_new()) == NULL)
    lose("could not allocate memory");

  if (!EVP_PKEY_assign_RSA(pkey, asym->cipher))
    lose("EVP_PKEY assignment error");

  if (!X509_set_pubkey(self->x509,pkey))
    lose("could not set certificate's public key");

  Py_RETURN_NONE;

 error:
  EVP_PKEY_free(pkey);
  return NULL;
}

static char X509_object_sign__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509</memberof>\n"
"      <name>sign</name>\n"
"      <parameter>key</parameter>\n"
"      <optional><parameter>digest = MD5_DIGEST</parameter></optional>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method signs a certificate with a private key.  See the\n"
"         example for the methods which should be invoked before signing a\n"
"         certificate.  <parameter>key</parameter> should be an instance of\n"
"         <classname>Asymmetric</classname> containing a private key.\n"
"         The optional parameter <parameter>digest</parameter> indicates\n"
"         which digest function should be used to compute the hash to be\n"
"         signed, it should be one of the following:\n"
"      </para>\n"
"      <simplelist>\n"
"         <member><constant>MD5_DIGEST</constant></member>\n"
"         <member><constant>SHA_DIGEST</constant></member>\n"
"         <member><constant>SHA1_DIGEST</constant></member>\n"
"         <member><constant>SHA256_DIGEST</constant></member>\n"
"         <member><constant>SHA384_DIGEST</constant></member>\n"
"         <member><constant>SHA512_DIGEST</constant></member>\n"
"     </simplelist>\n"
"   </body>\n"
"</method>\n"
;


static PyObject *
X509_object_sign(x509_object *self, PyObject *args)
{
  EVP_PKEY *pkey = NULL;
  asymmetric_object *asym;
  int digest = MD5_DIGEST;

  if (!PyArg_ParseTuple(args, "O!|i", &asymmetrictype, &asym, &digest))
    goto error;

  if ((pkey = EVP_PKEY_new()) == NULL)
    lose("could not allocate memory");

  if (asym->key_type != RSA_PRIVATE_KEY)
    lose("cannot use this type of key");

  if (!EVP_PKEY_assign_RSA(pkey, asym->cipher))
    lose("EVP_PKEY assignment error");

  switch (digest) {
  case MD5_DIGEST:
    if (!X509_sign(self->x509, pkey, EVP_md5()))
      lose("could not sign certificate");
    break;

  case SHA_DIGEST:
    if (!X509_sign(self->x509, pkey, EVP_sha()))
      lose("could not sign certificate");
    break;

  case SHA1_DIGEST:
    if (!X509_sign(self->x509, pkey, EVP_sha1()))
      lose("could not sign certificate");
    break;

  case SHA256_DIGEST:
    if (!X509_sign(self->x509, pkey, EVP_sha256()))
      lose("could not sign certificate");
    break;

  case SHA384_DIGEST:
    if (!X509_sign(self->x509, pkey, EVP_sha384()))
      lose("could not sign certificate");
    break;

  case SHA512_DIGEST:
    if (!X509_sign(self->x509, pkey, EVP_sha512()))
      lose("could not sign certificate");
    break;
  }

  Py_RETURN_NONE;

 error:
  EVP_PKEY_free(pkey);
  return NULL;
}

static char X509_object_get_version__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509</memberof>\n"
"      <name>getVersion</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns the version number from the version field of\n"
"         this certificate.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;


static PyObject *
X509_object_get_version(x509_object *self, PyObject *args)
{
  long version = 0;

  if (!PyArg_ParseTuple(args, ""))
    goto error;

  version = X509_get_version(self->x509);

  return Py_BuildValue("l", version);

 error:

  return NULL;
}

static char X509_object_set_version__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509</memberof>\n"
"      <name>setVersion</name>\n"
"      <parameter>version</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method sets the version number in the version field of\n"
"         this certificate.  <parameter>version</parameter> should be an\n"
"         integer.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
X509_object_set_version(x509_object *self, PyObject *args)
{
  long version = 0;

  if (!PyArg_ParseTuple(args, "l", &version))
    goto error;

  if (!X509_set_version(self->x509, version))
    lose("could not set certificate version");

  Py_RETURN_NONE;

 error:

  return NULL;
}

static char X509_object_get_serial__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509</memberof>\n"
"      <name>getSerial</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method get the serial number in the serial field of\n"
"         this certificate.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
X509_object_get_serial(x509_object *self, PyObject *args)
{
  long serial = 0;
  ASN1_INTEGER *asn1i = NULL;

  if (!PyArg_ParseTuple(args, ""))
    goto error;

  if ((asn1i = X509_get_serialNumber(self->x509)) == NULL)
    lose("could not get serial number");

  if ((serial = ASN1_INTEGER_get(asn1i)) == -1)
    lose("could not convert ASN1 Integer to long");

  return Py_BuildValue("l", serial);

 error:

  return NULL;
}

static char X509_object_set_serial__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509</memberof>\n"
"      <name>setSerial</name>\n"
"      <parameter>serial</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method sets the serial number in the serial field of\n"
"         this certificate.  <parameter>serial</parameter> should ba an\n"
"         integer.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
X509_object_set_serial(x509_object *self, PyObject *args)
{
  long serial = 0;
  ASN1_INTEGER *asn1i = NULL;

  if (!PyArg_ParseTuple(args, "l", &serial))
    goto error;

  if ((asn1i = ASN1_INTEGER_new()) == NULL)
    lose("could not allocate memory");

  if (!ASN1_INTEGER_set(asn1i, serial))
    lose("could not set ASN1 integer");

  if (!X509_set_serialNumber(self->x509, asn1i))
    lose("could not set certificate serial");

  ASN1_INTEGER_free(asn1i);

  Py_RETURN_NONE;

 error:
  ASN1_INTEGER_free(asn1i);
  return NULL;
}

static char X509_object_get_issuer__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509</memberof>\n"
"      <name>getIssuer</name>\n"
"      <parameter>format = OIDNAME_FORMAT</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns a tuple containing the issuers name.  Each\n"
"         element of the tuple is a tuple with 2 elements.  The first tuple\n"
"         is an object name and the second is it's value.  Both issuer and\n"
"         subject are names distinguished normally composed of a small\n"
"         number of objects:\n"
"      </para>\n"
"      <simplelist>\n"
"         <member><constant>c</constant> or <constant>countryName</constant></member>\n"
"         <member><constant>st</constant> or <constant>stateOrProvinceName</constant></member>\n"
"         <member><constant>o</constant> or <constant>organizationName</constant></member>\n"
"         <member><constant>l</constant> or <constant>localityName</constant></member>\n"
"         <member><constant>ou</constant> or <constant>organizationalUnitName</constant></member>\n"
"         <member><constant>cn</constant> or <constant>commonName</constant></member>\n"
"      </simplelist>\n"
"      <para>\n"
"         The data type varies from one object to another, however, all the\n"
"         common objects are strings.  It would be possible to specify any\n"
"         kind of object but that would certainly adversely effect\n"
"         portability and is not recommended.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
X509_object_get_issuer(x509_object *self, PyObject *args)
{
  PyObject *result_list = NULL;
  X509_NAME *name = NULL;
  int format = OIDNAME_FORMAT;

  if (!PyArg_ParseTuple(args, "|i", &format))
    goto error;

  if ((name = X509_get_issuer_name(self->x509)) == NULL)
    lose("could not get issuers name");

  if ((result_list = X509_object_helper_get_name(name, format)) == NULL)
    lose("failed to produce name list");

  return result_list;

 error:

  return NULL;
}

static char X509_object_get_subject__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509</memberof>\n"
"      <name>getSubject</name>\n"
"      <parameter>format = OIDNAME_FORMAT</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns a tuple containing the subjects name.  See\n"
"         <function>getIssuer</function> for a description of the returned\n"
"         object's format.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
X509_object_get_subject(x509_object *self, PyObject *args)
{
  PyObject *result_list = NULL;
  X509_NAME *name = NULL;
  int format = OIDNAME_FORMAT;

  if (!PyArg_ParseTuple(args, "|i", &format))
    goto error;

  if ((name = X509_get_subject_name(self->x509)) == NULL)
    lose("could not get issuers name");

  if ((result_list = X509_object_helper_get_name(name, format)) == NULL)
    lose("failed to produce name list");

  return result_list;

 error:

  return NULL;
}

static char X509_object_set_subject__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509</memberof>\n"
"      <name>setSubject</name>\n"
"      <parameter>name</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method is used to set the subjects name.\n"
"         <parameter>name</parameter> can be comprised of lists or tuples in\n"
"         the format described in the <function>getIssuer</function> method.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
X509_object_set_subject(x509_object *self, PyObject *args)
{
  PyObject *name_sequence = NULL;
  X509_NAME *name = NULL;

  if (!PyArg_ParseTuple(args, "O", &name_sequence))
    goto error;

  if (!PyTuple_Check(name_sequence) && !PyList_Check(name_sequence))
    lose_type_error("Inapropriate type");

  if ((name = X509_NAME_new()) == NULL)
    lose("could not allocate memory");

  if (!X509_object_helper_set_name(name, name_sequence))
    goto error;

  if (!X509_set_subject_name(self->x509, name))
    lose("unable to set name");

  X509_NAME_free(name);

  Py_RETURN_NONE;

 error:
  X509_NAME_free(name);
  return NULL;
}

static char X509_object_set_issuer__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509</memberof>\n"
"      <name>setIssuer</name>\n"
"      <parameter>name</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method is used to set the issuers name.\n"
"         <parameter>name</parameter> can be comprised of lists or tuples in\n"
"         the format described in the <function>getissuer</function> method.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
X509_object_set_issuer(x509_object *self, PyObject *args)
{
  PyObject *name_sequence = NULL;
  X509_NAME *name = NULL;

  if (!PyArg_ParseTuple(args, "O", &name_sequence))
    goto error;

  if (!PyTuple_Check(name_sequence) && !PyList_Check(name_sequence))
    lose_type_error("Inapropriate type");

  if ((name = X509_NAME_new()) == NULL)
    lose("could not allocate memory");

  if (!X509_object_helper_set_name(name, name_sequence))
    goto error;

  if (!X509_set_issuer_name(self->x509,name))
    lose("unable to set name");

  X509_NAME_free(name);

  Py_RETURN_NONE;

 error:
  X509_NAME_free(name);
  return  NULL;
}

static char X509_object_get_not_before__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509</memberof>\n"
"      <name>getNotBefore</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         In a change from previous releases, for reasons of portability\n"
"         and to avoid hard to fix issues with problems in unreliable time\n"
"         functions, this function returns a UTCTime string.  You\n"
"         can use the function <function>time2utc</function> to convert to a\n"
"         string if you like and <function>utc2time</function> to back.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"

;

static PyObject *
X509_object_get_not_before (x509_object *self, PyObject *args)
{
  if (!PyArg_ParseTuple(args, ""))
    goto error;

  return ASN1_TIME_to_Python(self->x509->cert_info->validity->notBefore);

 error:

  return NULL;
}

static char X509_object_get_not_after__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509</memberof>\n"
"      <name>getNotAfter</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         In a change from previous releases, for reasons of portability\n"
"         and to avoid hard to fix issues with problems in unreliable time\n"
"         functions, this function returns a UTCTime string.  You\n"
"         can use the function <function>time2utc</function> to convert to a\n"
"         string if you like and <function>utc2time</function> to back.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
X509_object_get_not_after (x509_object *self, PyObject *args)
{
  if (!PyArg_ParseTuple(args, ""))
    goto error;

  return ASN1_TIME_to_Python(self->x509->cert_info->validity->notAfter);

 error:

  return NULL;
}

static char X509_object_set_not_after__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509</memberof>\n"
"      <name>setNotAfter</name>\n"
"      <parameter>time</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         In a change from previous releases, for reasons of portability\n"
"         and to avoid hard to fix issues with problems in unreliable time\n"
"         functions, this accepts one parameter, a UTCTime string.  You\n"
"         can use the function <function>time2utc</function> to convert to a\n"
"         string if you like and <function>utc2time</function> to back.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
X509_object_set_not_after (x509_object *self, PyObject *args)
{
  char *new_time = NULL;

  if (!PyArg_ParseTuple(args, "s", &new_time))
    goto error;

  if (!python_ASN1_TIME_set_string(self->x509->cert_info->validity->notAfter, new_time))
    lose("Could not set notAfter");

  Py_RETURN_NONE;

 error:

  return NULL;
}

static char X509_object_set_not_before__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509</memberof>\n"
"      <name>setNotBefore</name>\n"
"      <parameter>time</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         In a change from previous releases, for reasons of portability\n"
"         and to avoid hard to fix issues with problems in unreliable time\n"
"         functions, this accepts one parameter, a UTCTime string.  You\n"
"         can use the function <function>time2utc</function> to convert to a\n"
"         string if you like and <function>utc2time</function> to back.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
X509_object_set_not_before (x509_object *self, PyObject *args)
{
  char *new_time = NULL;

  if (!PyArg_ParseTuple(args, "s", &new_time))
    goto error;

  if (!python_ASN1_TIME_set_string(self->x509->cert_info->validity->notBefore, new_time))
    lose("Could not set notBefore");

  Py_RETURN_NONE;

 error:

  return NULL;
}

static char X509_object_add_extension__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509</memberof>\n"
"      <name>addExtension</name>\n"
"      <parameter>extensionName</parameter>\n"
"      <parameter>critical</parameter>\n"
"      <parameter>extensionValue</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method adds an extension to this certificate.\n"
"         <parameter>extensionName</parameter> should be the of the\n"
"         extension.  <parameter>critical</parameter> should an integer, 1\n"
"         for true and 0 for false.  <parameter>extensionValue</parameter>\n"
"         should be a string, DER encoded value of the extension.  The name\n"
"         of the extension must be correct according to OpenSSL and can be\n"
"         checked in the <constant>objects.h</constant> header file, part of\n"
"         the OpenSSL source distribution.  In the majority of cases they\n"
"         are the same as those defined in <constant>POW._oids</constant>\n"
"         but if you do encounter problems is may be worth checking.\n"
"      </para>\n"
"      <example>\n"
"         <title><function>addExtension</function> method usage</title>\n"
"         <programlisting>\n"
"      basic = POW.pkix.BasicConstraints()\n"
"      basic.set([1,5])\n"
"      serverCert.addExtension('basicConstraints', 0, basic.toString())\n"
"         </programlisting>\n"
"      </example>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
X509_object_add_extension(x509_object *self, PyObject *args)
{
  int critical = 0, nid = 0, len = 0;
  char *name = NULL;
  unsigned char *buf = NULL;
  ASN1_OCTET_STRING *octetString = NULL;
  X509_EXTENSION *extn = NULL;

  if (!PyArg_ParseTuple(args, "sis#", &name, &critical, &buf, &len))
    goto error;

  if ((octetString = M_ASN1_OCTET_STRING_new()) == NULL)
    lose("could not allocate memory");

  if (!ASN1_OCTET_STRING_set(octetString, buf, len))
    lose("could not set ASN1 Octect string");

  if ((nid = OBJ_txt2nid(name)) == NID_undef)
    lose("extension has unknown object identifier");

  if ((extn = X509_EXTENSION_create_by_NID(NULL, nid, critical, octetString)) == NULL)
    lose("unable to create ASN1 X509 Extension object");

  if (!self->x509->cert_info->extensions &&
      (self->x509->cert_info->extensions = sk_X509_EXTENSION_new_null()) == NULL)
    lose("unable to allocate memory");

  if (!sk_X509_EXTENSION_push(self->x509->cert_info->extensions, extn))
    lose("unable to add extension");

  Py_RETURN_NONE;

 error:
  X509_EXTENSION_free(extn);
  return NULL;
}

static char X509_object_clear_extensions__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509</memberof>\n"
"      <name>clearExtensions</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method clears the structure which holds the extension for\n"
"         this certificate.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
X509_object_clear_extensions(x509_object *self, PyObject *args)
{
  if (!PyArg_ParseTuple(args, ""))
    goto error;

  if (self->x509->cert_info->extensions) {
    sk_X509_EXTENSION_free(self->x509->cert_info->extensions);
    self->x509->cert_info->extensions = NULL;
  }

  Py_RETURN_NONE;

 error:

  return NULL;
}

static char X509_object_count_extensions__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509</memberof>\n"
"      <name>countExtensions</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns the size of the structure which holds the\n"
"         extension for this certificate.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
X509_object_count_extensions(x509_object *self, PyObject *args)
{
  int num = 0;

  if (!PyArg_ParseTuple(args, ""))
    goto error;

  if (self->x509->cert_info->extensions)
    num = sk_X509_EXTENSION_num(self->x509->cert_info->extensions);

  return Py_BuildValue("i", num);

 error:

  return NULL;
}

static char X509_object_get_extension__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509</memberof>\n"
"      <name>getExtension</name>\n"
"      <parameter>index</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns a tuple equivalent the parameters of\n"
"         <function>addExtension</function>.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
X509_object_get_extension(x509_object *self, PyObject *args)
{
  int num = 0, index = 0, ext_nid = 0;
  char const *ext_ln = NULL;
  char unknown_ext [] = "unknown";
  X509_EXTENSION *ext;

  if (!PyArg_ParseTuple(args, "i", &index))
    goto error;

  if (self->x509->cert_info->extensions)
    num = sk_X509_EXTENSION_num(self->x509->cert_info->extensions);

  if (index >= num)
    lose("certificate does not have that many extensions");

  if ((ext = sk_X509_EXTENSION_value(self->x509->cert_info->extensions, index)) == NULL)
    lose("could not get extension");

  if ((ext_nid = OBJ_obj2nid(ext->object)) == NID_undef)
    lose("extension has unknown object identifier");

  if ((ext_ln = OBJ_nid2sn(ext_nid)) == NULL)
    ext_ln = unknown_ext;

  return Py_BuildValue("sis#", ext_ln, ext->critical, ext->value->data, ext->value->length);

 error:

  return NULL;
}

static PyObject *
X509_object_get_ski(x509_object *self, PyObject *args)
{
  /*
   * Called for side-effect (calls x509v3_cache_extensions() for us).
   */
  (void) X509_check_ca(self->x509);

  if (self->x509->skid == NULL)
    Py_RETURN_NONE;
  else
    return Py_BuildValue("s#", self->x509->skid->data, self->x509->skid->length);
}

static char x509_object_pprint__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509</memberof>\n"
"      <name>pprint</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns a formatted string showing the information\n"
"         held in the certificate.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
x509_object_pprint(x509_object *self, PyObject *args)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  if (!PyArg_ParseTuple(args, ""))
    goto error;

  bio = BIO_new(BIO_s_mem());

  if (!X509_print(bio, self->x509))
    lose("unable to write CRL");

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static struct PyMethodDef X509_object_methods[] = {
  {"pemWrite",          (PyCFunction)X509_object_pem_write,        METH_VARARGS,  NULL},
  {"derWrite",          (PyCFunction)X509_object_der_write,        METH_VARARGS,  NULL},
  {"sign",              (PyCFunction)X509_object_sign,             METH_VARARGS,  NULL},
  {"setPublicKey",      (PyCFunction)X509_object_set_public_key,   METH_VARARGS,  NULL},
  {"getVersion",        (PyCFunction)X509_object_get_version,      METH_VARARGS,  NULL},
  {"setVersion",        (PyCFunction)X509_object_set_version,      METH_VARARGS,  NULL},
  {"getSerial",         (PyCFunction)X509_object_get_serial,       METH_VARARGS,  NULL},
  {"setSerial",         (PyCFunction)X509_object_set_serial,       METH_VARARGS,  NULL},
  {"getIssuer",         (PyCFunction)X509_object_get_issuer,       METH_VARARGS,  NULL},
  {"setIssuer",         (PyCFunction)X509_object_set_issuer,       METH_VARARGS,  NULL},
  {"getSubject",        (PyCFunction)X509_object_get_subject,      METH_VARARGS,  NULL},
  {"setSubject",        (PyCFunction)X509_object_set_subject,      METH_VARARGS,  NULL},
  {"getNotBefore",      (PyCFunction)X509_object_get_not_before,   METH_VARARGS,  NULL},
  {"getNotAfter",       (PyCFunction)X509_object_get_not_after,    METH_VARARGS,  NULL},
  {"setNotAfter",       (PyCFunction)X509_object_set_not_after,    METH_VARARGS,  NULL},
  {"setNotBefore",      (PyCFunction)X509_object_set_not_before,   METH_VARARGS,  NULL},
  {"addExtension",      (PyCFunction)X509_object_add_extension,    METH_VARARGS,  NULL},
  {"clearExtensions",   (PyCFunction)X509_object_clear_extensions, METH_VARARGS,  NULL},
  {"countExtensions",   (PyCFunction)X509_object_count_extensions, METH_VARARGS,  NULL},
  {"getExtension",      (PyCFunction)X509_object_get_extension,    METH_VARARGS,  NULL},
  {"pprint",            (PyCFunction)x509_object_pprint,           METH_VARARGS,  NULL},
  {"getSKI",            (PyCFunction)X509_object_get_ski,          METH_NOARGS,   NULL},
  {NULL}    /* sentinel */
};

static PyObject *
X509_object_getattr(x509_object *self, char *name)
{
  return Py_FindMethod(X509_object_methods, (PyObject *)self, name);
}

static void
X509_object_dealloc(x509_object *self, char *name)
{
  X509_free(self->x509);
  PyObject_Del(self);
}

static char x509type__doc__[] =
"<class>\n"
"   <header>\n"
"      <name>X509</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This class provides access to a significant proportion of X509\n"
"         functionality of OpenSSL.\n"
"      </para>\n"
"\n"
"      <example>\n"
"         <title><classname>x509</classname> class usage</title>\n"
"         <programlisting>\n"
"      privateFile = open('test/private.key', 'r')\n"
"      publicFile = open('test/public.key', 'r')\n"
"      certFile = open('test/cacert.pem', 'w')\n"
"\n"
"      publicKey = POW.pemRead(POW.RSA_PUBLIC_KEY, publicFile.read())\n"
"      privateKey = POW.pemRead(POW.RSA_PRIVATE_KEY, privateFile.read(), 'pass')\n"
"\n"
"      c = POW.X509()\n"
"\n"
"      name = [  ['C', 'GB'], ['ST', 'Hertfordshire'],\n"
"                ['O','The House'], ['CN', 'Peter Shannon'] ]\n"
"\n"
"      c.setIssuer(name)\n"
"      c.setSubject(name)\n"
"      c.setSerial(0)\n"
"      t1 = POW.pkix.time2utc(time.time())\n"
"      t2 = POW.pkix.time2utc(time.time() + 60*60*24*365)\n"
"      c.setNotBefore(t1)\n"
"      c.setNotAfter(t2)\n"
"      c.setPublicKey(publicKey)\n"
"      c.sign(privateKey)\n"
"\n"
"      certFile.write(c.pemWrite())\n"
"\n"
"      privateFile.close()\n"
"      publicFile.close()\n"
"      certFile.close()\n"
"         </programlisting>\n"
"      </example>\n"
"\n"
"   </body>\n"
"</class>\n"
;

static PyTypeObject x509type = {
   PyObject_HEAD_INIT(0)
   0,                                  /*ob_size*/
   "X509",                             /*tp_name*/
   sizeof(x509_object),                /*tp_basicsize*/
   0,                                  /*tp_itemsize*/
   (destructor)X509_object_dealloc,    /*tp_dealloc*/
   (printfunc)0,                       /*tp_print*/
   (getattrfunc)X509_object_getattr,   /*tp_getattr*/
   (setattrfunc)0,                     /*tp_setattr*/
   (cmpfunc)0,                         /*tp_compare*/
   (reprfunc)0,                        /*tp_repr*/
   0,                                  /*tp_as_number*/
   0,                                  /*tp_as_sequence*/
   0,                                  /*tp_as_mapping*/
   (hashfunc)0,                        /*tp_hash*/
   (ternaryfunc)0,                     /*tp_call*/
   (reprfunc)0,                        /*tp_str*/
   0,
   0,
   0,
   0,
   x509type__doc__                     /* Documentation string */
};
/*========== X509 Code ==========*/

/*========== x509 store Code ==========*/
static x509_store_object *
x509_store_object_new(void)
{
  x509_store_object *self = NULL;

  if ((self = PyObject_New(x509_store_object, &x509_storetype)) == NULL)
    goto error;

  self->store = X509_STORE_new();

  return self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static char x509_store_object_verify__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Store</memberof>\n"
"      <name>verify</name>\n"
"      <parameter>certificate</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         The <classname>X509Store</classname> method\n"
"         <function>verify</function> is based on the\n"
"         <function>X509_verify_cert</function>.  It handles certain aspects\n"
"         of verification but not others.  The certificate will be verified\n"
"         against <constant>notBefore</constant>,\n"
"         <constant>notAfter</constant> and trusted certificates.\n"
"         It crucially will not handle checking the certificate against\n"
"         CRLs.  This functionality will probably make it into OpenSSL\n"
"         0.9.7.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
x509_store_object_verify(x509_store_object *self, PyObject *args)
{
  X509_STORE_CTX csc;
  x509_object *x509 = NULL;
  int ok;

  if (!PyArg_ParseTuple(args, "O!", &x509type, &x509))
    goto error;

  X509_STORE_CTX_init(&csc, self->store, x509->x509, NULL);
  ok = X509_verify_cert(&csc) == 1;
  X509_STORE_CTX_cleanup(&csc);

  return PyBool_FromLong(ok);

 error:

  return NULL;
}

static char x509_store_object_verify_chain__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Store</memberof>\n"
"      <name>verifyChain</name>\n"
"      <parameter>certificate</parameter>\n"
"      <parameter>chain</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         The <classname>X509Store</classname> method <function>verifyChain</function>\n"
"         is based on the <function>X509_verify_cert</function> but is initialised\n"
"         with a <classname>X509</classname> object to verify and list of\n"
"         <classname>X509</classname> objects which form a chain to a trusted\n"
"         certificate.  Certain aspects of the verification are handled but not others.\n"
"         The certificates will be verified against <constant>notBefore</constant>,\n"
"         <constant>notAfter</constant> and trusted certificates.  It crucially will\n"
"         not handle checking the certificate against CRLs.  This functionality will\n"
"         probably make it into OpenSSL 0.9.7.\n"
"      </para>\n"
"      <para>\n"
"         This may all sound quite straight forward but determining the\n"
"         certificate associated with the signature on another certificate\n"
"         can be very time consuming.  The management aspects of\n"
"         certificates are addressed by various V3 extensions which are not\n"
"         currently supported.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
x509_store_object_verify_chain(x509_store_object *self, PyObject *args)
{
  PyObject *x509_sequence = NULL;
  X509_STORE_CTX csc;
  x509_object *x509 = NULL;
  STACK_OF(X509) *x509_stack = NULL;
  int ok;

  if (!PyArg_ParseTuple(args, "O!O", &x509type, &x509, &x509_sequence))
    goto error;

  if ((x509_stack = x509_helper_sequence_to_stack(x509_sequence)) == NULL)
    goto error;

  X509_STORE_CTX_init(&csc, self->store, x509->x509, x509_stack);

  ok = X509_verify_cert(&csc) == 1;

  X509_STORE_CTX_cleanup(&csc);
  sk_X509_free(x509_stack);

  return PyBool_FromLong(ok);

 error:
  sk_X509_free(x509_stack);
  return NULL;
}

static char x509_store_object_verify_detailed__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Store</memberof>\n"
"      <name>verifyDetailed</name>\n"
"      <parameter>certificate</parameter>\n"
"      <optional>\n"
"        <parameter>chain</parameter>\n"
"      </optional>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         The <classname>X509Store</classname> method <function>verifyDetailed</function>\n"
"         is based on the <function>X509_verify_cert</function> but is initialised\n"
"         with a <classname>X509</classname> object to verify and list of\n"
"         <classname>X509</classname> objects which form a chain to a trusted\n"
"         certificate.  Certain aspects of the verification are handled but not others.\n"
"         The certificates will be verified against <constant>notBefore</constant>,\n"
"         <constant>notAfter</constant> and trusted certificates.  It crucially will\n"
"         not handle checking the certificate against CRLs.  This functionality will\n"
"         probably make it into OpenSSL 0.9.7.\n"
"      </para>\n"
"      <para>\n"
"         This may all sound quite straight forward but determining the\n"
"         certificate associated with the signature on another certificate\n"
"         can be very time consuming.  The management aspects of\n"
"         certificates are addressed by various V3 extensions which are not\n"
"         currently supported.\n"
"      </para>\n"
"      <para>\n"
"         Unlike the <function>verify</function> and <function>verifyChain</function>\n"
"         methods, <function>verifyDetailed</function> returns some information about\n"
"         what went wrong when verification fails.  The return value is currently a 3-tuple:\n"
"         the first value is the return value from X509_verify_cert(), the second and third\n"
"         are the error and error_depth values from the X509_STORE_CTX.\n"
"         Other values may added to this tuple later.\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
x509_store_object_verify_detailed(x509_store_object *self, PyObject *args)
{
  PyObject *x509_sequence = Py_None;
  X509_STORE_CTX csc;
  x509_object *x509 = NULL;
  STACK_OF(X509) *x509_stack = NULL;
  PyObject *result = NULL;
  int ok;

  if (!PyArg_ParseTuple(args, "O!|O", &x509type, &x509, &x509_sequence))
    goto error;

  if (x509_sequence && !(x509_stack = x509_helper_sequence_to_stack(x509_sequence)))
    goto error;

  X509_STORE_CTX_init(&csc, self->store, x509->x509, x509_stack);

  ok = X509_verify_cert(&csc) == 1;

  result = Py_BuildValue("(iii)", ok, csc.error, csc.error_depth);

  X509_STORE_CTX_cleanup(&csc);

 error:                          /* fall through */
  sk_X509_free(x509_stack);
  return result;
}

static char x509_store_object_add_trust__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Store</memberof>\n"
"      <name>addTrust</name>\n"
"      <parameter>cert</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method adds a new certificate to the store to be used in the\n"
"         verification process.  <parameter>cert</parameter> should be an\n"
"         instance of <classname>X509</classname>.  Using trusted certificates to manage\n"
"         verification is relatively primitive, more sophisticated systems\n"
"         can be constructed at an application level by by constructing\n"
"         certificate chains to verify.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
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
"<method>\n"
"   <header>\n"
"      <memberof>X509Store</memberof>\n"
"      <name>addCrl</name>\n"
"      <parameter>crl</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method adds a CRL to a store to be used for verification.\n"
"         <parameter>crl</parameter> should be an instance of\n"
"         <classname>X509Crl</classname>.\n"
"         Unfortunately, the current stable release of OpenSSL does not\n"
"         support CRL checking for certificate verification.\n"
"         This functionality will probably make it into OpenSSL 0.9.7, until\n"
"         it does this function is useless and CRL verification must be\n"
"         implemented by the application.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

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
  {"verify",         (PyCFunction)x509_store_object_verify,          METH_VARARGS,  NULL},
  {"verifyChain",    (PyCFunction)x509_store_object_verify_chain,    METH_VARARGS,  NULL},
  {"verifyDetailed", (PyCFunction)x509_store_object_verify_detailed, METH_VARARGS,  NULL},
  {"addTrust",       (PyCFunction)x509_store_object_add_trust,       METH_VARARGS,  NULL},
  {"addCrl",         (PyCFunction)x509_store_object_add_crl,         METH_VARARGS,  NULL},

  {NULL}    /* sentinel */
};

static PyObject *
x509_store_object_getattr(x509_store_object *self, char *name)
{
  return Py_FindMethod(x509_store_object_methods, (PyObject *)self, name);
}

static void
x509_store_object_dealloc(x509_store_object *self, char *name)
{
  X509_STORE_free(self->store);
  PyObject_Del(self);
}

static char x509_storetype__doc__[] =
"<class>\n"
"   <header>\n"
"      <name>X509Store</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This class provides preliminary access to OpenSSL X509 verification\n"
"         facilities.\n"
"      </para>\n"
"\n"
"      <example>\n"
"         <title><classname>x509_store</classname> class usage</title>\n"
"         <programlisting>\n"
"      store = POW.X509Store()\n"
"\n"
"      caFile = open('test/cacert.pem', 'r')\n"
"      ca = POW.pemRead(POW.X509_CERTIFICATE, caFile.read())\n"
"      caFile.close()\n"
"\n"
"      store.addTrust(ca)\n"
"\n"
"      certFile = open('test/foocom.cert', 'r')\n"
"      x509 = POW.pemRead(POW.X509_CERTIFICATE, certFile.read())\n"
"      certFile.close()\n"
"\n"
"      print x509.pprint()\n"
"\n"
"      if store.verify(x509):\n"
"         print 'Verified certificate!.'\n"
"      else:\n"
"         print 'Failed to verify certificate!.'\n"
"         </programlisting>\n"
"      </example>\n"
"   </body>\n"
"</class>\n"
;

static PyTypeObject x509_storetype = {
   PyObject_HEAD_INIT(0)
   0,                                        /*ob_size*/
   "X509Store",                              /*tp_name*/
   sizeof(x509_store_object),                /*tp_basicsize*/
   0,                                        /*tp_itemsize*/
   (destructor)x509_store_object_dealloc,    /*tp_dealloc*/
   (printfunc)0,                             /*tp_print*/
   (getattrfunc)x509_store_object_getattr,   /*tp_getattr*/
   (setattrfunc)0,                           /*tp_setattr*/
   (cmpfunc)0,                               /*tp_compare*/
   (reprfunc)0,                              /*tp_repr*/
   0,                                        /*tp_as_number*/
   0,                                        /*tp_as_sequence*/
   0,                                        /*tp_as_mapping*/
   (hashfunc)0,                              /*tp_hash*/
   (ternaryfunc)0,                           /*tp_call*/
   (reprfunc)0,                              /*tp_str*/
   0,
   0,
   0,
   0,
   x509_storetype__doc__                    /* Documentation string */
};
/*========== x509 store Code ==========*/

/*========== x509 crl Code ==========*/
static x509_crl_object *
x509_crl_object_new(void)
{
  x509_crl_object *self = NULL;

  self = PyObject_New(x509_crl_object, &x509_crltype);
  if (self == NULL)
    goto error;

  self->crl = X509_CRL_new();

  return self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static x509_crl_object *
x509_crl_object_pem_read(BIO *in)
{
  x509_crl_object *self;

  if ((self = PyObject_New(x509_crl_object, &x509_crltype)) == NULL)
    goto error;

  if ((self->crl = PEM_read_bio_X509_CRL(in, NULL, NULL, NULL)) == NULL)
    lose("could not load certificate");

  return self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static x509_crl_object *
x509_crl_object_der_read(unsigned char *src, int len)
{
  x509_crl_object *self;
  unsigned char* ptr = src;

  if ((self = PyObject_New(x509_crl_object, &x509_crltype)) == NULL)
    goto error;

  self->crl = X509_CRL_new();

  if (!d2i_X509_CRL(&self->crl, (const unsigned char **) &ptr, len))
    lose("could not load PEM encoded CRL");

  return self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static char x509_crl_object_get_version__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Crl</memberof>\n"
"      <name>getVersion</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns the version number from the version field of\n"
"         this CRL.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
x509_crl_object_get_version(x509_crl_object *self, PyObject *args)
{
  long version = 0;

  if (!PyArg_ParseTuple(args, ""))
    goto error;

  if ((version = ASN1_INTEGER_get(self->crl->crl->version)) == -1)
    lose("could not get crl version");

  return Py_BuildValue("l", version);

 error:

  return NULL;
}

static char x509_crl_object_set_version__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Crl</memberof>\n"
"      <name>setVersion</name>\n"
"      <parameter>version</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method sets the version number in the version field of\n"
"         this CRL.  <parameter>version</parameter> should be an\n"
"         integer.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
x509_crl_object_set_version(x509_crl_object *self, PyObject *args)
{
  long version = 0;
  ASN1_INTEGER *asn1_version = NULL;

  if (!PyArg_ParseTuple(args, "i", &version))
    goto error;

  if ((asn1_version = ASN1_INTEGER_new()) == NULL)
    lose("could not allocate memory");

  if (!ASN1_INTEGER_set(asn1_version, version))
    lose("could not get set version");

  self->crl->crl->version = asn1_version;

  Py_RETURN_NONE;

 error:
  ASN1_INTEGER_free(asn1_version);
  return NULL;
}

static char x509_crl_object_get_issuer__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Crl</memberof>\n"
"      <name>getIssuer</name>\n"
"      <parameter>format = OIDNAME_FORMAT</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns a tuple containing the issuers name.  See the\n"
"         <function>getIssuer</function> method of\n"
"         <classname>X509</classname> for more details.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
x509_crl_object_get_issuer(x509_crl_object *self, PyObject *args)
{
  PyObject *result_list = NULL;
  int format = OIDNAME_FORMAT;

  if (!PyArg_ParseTuple(args, "|i", &format))
    goto error;

  if ((result_list = X509_object_helper_get_name(self->crl->crl->issuer, format)) == NULL)
    lose("failed to produce name list");

  return result_list;

 error:

  return NULL;
}

static char x509_crl_object_set_issuer__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Crl</memberof>\n"
"      <name>setIssuer</name>\n"
"      <parameter>name</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method is used to set the issuers name.\n"
"         <parameter>name</parameter> can be comprised of lists or tuples in\n"
"         the format described in the <function>getIssuer</function> method\n"
"         of <classname>X509</classname>.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
x509_crl_object_set_issuer(x509_crl_object *self, PyObject *args)
{
  PyObject *name_sequence = NULL;
  X509_NAME *name = NULL;

  if (!PyArg_ParseTuple(args, "O", &name_sequence))
    goto error;

  if (!PyTuple_Check(name_sequence) && !PyList_Check(name_sequence))
    lose_type_error("Inapropriate type");

  if ((name = X509_NAME_new()) == NULL)
    lose("could not allocate memory");

  if (!X509_object_helper_set_name(name, name_sequence))
    goto error;

  if (!X509_NAME_set(&self->crl->crl->issuer, name))
    lose("unable to set name");

  X509_NAME_free(name);

  Py_RETURN_NONE;

 error:
  X509_NAME_free(name);
  return NULL;
}

static char x509_crl_object_set_this_update__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Crl</memberof>\n"
"      <name>setThisUpdate</name>\n"
"      <parameter>time</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         In a change from previous releases, for reasons of portability\n"
"         and to avoid hard to fix issues with problems in unreliable time\n"
"         functions, this accepts one parameter, a UTCTime string.  You\n"
"         can use the function <function>time2utc</function> to convert to a\n"
"         string if you like and <function>utc2time</function> to back.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
x509_crl_object_set_this_update (x509_crl_object *self, PyObject *args)
{
  char *new_time = NULL;

  if (!PyArg_ParseTuple(args, "s", &new_time))
    goto error;

  if (!python_ASN1_TIME_set_string(self->crl->crl->lastUpdate, new_time))
    lose("Could not set lastUpdate");

  Py_RETURN_NONE;

 error:

  return NULL;
}

static char x509_crl_object_get_this_update__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Crl</memberof>\n"
"      <name>getThisUpdate</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         In a change from previous releases, for reasons of portability\n"
"         and to avoid hard to fix issues with problems in unreliable time\n"
"         functions, this function returns a UTCTime string.  You\n"
"         can use the function <function>time2utc</function> to convert to a\n"
"         string if you like and <function>utc2time</function> to back.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
x509_crl_object_get_this_update (x509_crl_object *self, PyObject *args)
{
  if (!PyArg_ParseTuple(args, ""))
    goto error;

  return ASN1_TIME_to_Python(self->crl->crl->lastUpdate);

 error:

  return NULL;
}

static char x509_crl_object_set_next_update__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Crl</memberof>\n"
"      <name>setNextUpdate</name>\n"
"      <parameter>time</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         In a change from previous releases, for reasons of portability\n"
"         and to avoid hard to fix issues with problems in unreliable time\n"
"         functions, this accepts one parameter, a UTCTime string.  You\n"
"         can use the function <function>time2utc</function> to convert to a\n"
"         string if you like and <function>utc2time</function> to back.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
x509_crl_object_set_next_update (x509_crl_object *self, PyObject *args)
{
  char *new_time = NULL;
  ASN1_UTCTIME *time = NULL;

  if (!PyArg_ParseTuple(args, "s", &new_time))
    goto error;

  if (self->crl->crl->nextUpdate == NULL && (time = ASN1_UTCTIME_new()) == NULL)
    lose("could not allocate memory");

  self->crl->crl->nextUpdate = time;

  if (!python_ASN1_TIME_set_string(time, new_time))
    lose("Could not set nextUpdate");

  Py_RETURN_NONE;

 error:

  return NULL;
}

static char x509_crl_object_get_next_update__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Crl</memberof>\n"
"      <name>getNextUpdate</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         In a change from previous releases, for reasons of portability\n"
"         and to avoid hard to fix issues with problems in unreliable time\n"
"         functions, this function returns a UTCTime string.  You\n"
"         can use the function <function>time2utc</function> to convert to a\n"
"         string if you like and <function>utc2time</function> to back.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
x509_crl_object_get_next_update (x509_crl_object *self, PyObject *args)
{
  if (!PyArg_ParseTuple(args, ""))
    goto error;

  return ASN1_TIME_to_Python(self->crl->crl->nextUpdate);

 error:

  return NULL;
}

static char x509_crl_object_set_revoked__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Crl</memberof>\n"
"      <name>setRevoked</name>\n"
"      <parameter>revoked</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method sets the sequence of revoked certificates in this CRL.\n"
"         <parameter>revoked</parameter> should be a list or tuple of\n"
"         <classname>X509Revoked</classname>.\n"
"      </para>\n"
"      <example>\n"
"         <title><function>setRevoked</function> function usage</title>\n"
"         <programlisting>\n"
"      privateFile = open('test/private.key', 'r')\n"
"      publicFile = open('test/public.key', 'r')\n"
"      crlFile = open('test/crl.pem', 'w')\n"
"\n"
"      publicKey = POW.pemRead(POW.RSA_PUBLIC_KEY, publicFile.read())\n"
"      privateKey = POW.pemRead(POW.RSA_PRIVATE_KEY, privateFile.read(), 'pass')\n"
"\n"
"      crl = POW.X509Crl()\n"
"\n"
"      name = [  ['C', 'GB'], ['ST', 'Hertfordshire'],\n"
"                ['O','The House'], ['CN', 'Peter Shannon'] ]\n"
"\n"
"      t1 = POW.pkix.time2utc(time.time())\n"
"      t2 = POW.pkix.time2utc(time.time() + 60*60*24*365)\n"
"      crl.setIssuer(name)\n"
"      rev = [  POW.X509Revoked(3, t1),\n"
"               POW.X509Revoked(4, t1),\n"
"               POW.X509Revoked(5, t1)    ]\n"
"\n"
"      crl.setRevoked(rev)\n"
"      crl.setThisUpdate(t1)\n"
"      crl.setNextUpdate(t2)\n"
"      crl.sign(privateKey)\n"
"\n"
"      crlFile.write(crl.pemWrite())\n"
"\n"
"      privateFile.close()\n"
"      publicFile.close()\n"
"      crlFile.close()\n"
"         </programlisting>\n"
"      </example>\n"
"\n"
"   </body>\n"
"</method>\n"
;

// added because we don't already have one!
static X509_REVOKED *
X509_REVOKED_dup(X509_REVOKED *rev)
{
  return((X509_REVOKED *)ASN1_dup((i2d_of_void *) i2d_X509_REVOKED,
                                  (d2i_of_void *) d2i_X509_REVOKED,
                                  (char *) rev));
}

static PyObject *
x509_crl_object_set_revoked(x509_crl_object *self, PyObject *args)
{
  PyObject *revoked_sequence = NULL;
  x509_revoked_object *revoked = NULL;
  X509_REVOKED *tmp_revoked = NULL;
  int i = 0,size = 0;

  if (!PyArg_ParseTuple(args, "O", &revoked_sequence))
    goto error;

  if (!PyTuple_Check(revoked_sequence) && !PyList_Check(revoked_sequence))
    lose_type_error("inapropriate type");

  size = PySequence_Size(revoked_sequence);
  for (i = 0; i < size; i++) {
    if ((revoked = (x509_revoked_object*) PySequence_GetItem(revoked_sequence, i)) == NULL)
      goto error;

    if (!X_X509_revoked_Check(revoked))
      lose_type_error("inapropriate type");

    if ((tmp_revoked = X509_REVOKED_dup(revoked->revoked)) == NULL)
      lose("could not allocate memory");

    if (!X509_CRL_add0_revoked(self->crl, tmp_revoked))
      lose("could not add revokation to stack");

    Py_XDECREF(revoked);
    revoked = NULL;
  }

  Py_RETURN_NONE;

 error:

  Py_XDECREF(revoked);

  return  NULL;
}

static PyObject *
x509_crl_object_helper_get_revoked(STACK_OF(X509_REVOKED) *revoked)
{
  int no_entries = 0, i = 0;
  x509_revoked_object *revoke_obj = NULL;
  PyObject *result_list = NULL, *result_tuple = NULL;

  no_entries = sk_X509_REVOKED_num(revoked);

  if ((result_list = PyList_New(0)) == NULL)
    lose("could not allocate memory");

  for (i = 0; i < no_entries; i++) {
    if ((revoke_obj = PyObject_New(x509_revoked_object, &x509_revokedtype)) == NULL)
      lose("could not allocate memory");

    if ((revoke_obj->revoked = X509_REVOKED_dup(sk_X509_REVOKED_value(revoked, i))) == NULL)
      lose("could not get revocation");

    if (PyList_Append(result_list, (PyObject*) revoke_obj) != 0)
      goto error;

    Py_XDECREF(revoke_obj);
    revoke_obj = NULL;
  }

  result_tuple = PyList_AsTuple(result_list);
  Py_XDECREF(result_list);

  return result_tuple;

 error:

  Py_XDECREF(revoke_obj);
  Py_XDECREF(result_list);
  return NULL;
}

static char x509_crl_object_get_revoked__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Crl</memberof>\n"
"      <name>getRevoked</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns a tuple of <classname>X509Revoked</classname>\n"
"         objects described in the CRL.\n"
"      </para>\n"
"      <example>\n"
"         <title><function>getRevoked</function> function usage</title>\n"
"         <programlisting>\n"
"      publicFile = open('test/public.key', 'r')\n"
"      crlFile = open('test/crl.pem', 'r')\n"
"\n"
"      publicKey = POW.pemRead(POW.RSA_PUBLIC_KEY, publicFile.read())\n"
"\n"
"      crl = POW.pemRead(POW.X509_CRL, crlFile.read())\n"
"\n"
"      print crl.pprint()\n"
"      if crl.verify(publicKey):\n"
"         print 'signature ok!'\n"
"      else:\n"
"         print 'signature not ok!'\n"
"\n"
"      revocations = crl.getRevoked()\n"
"      for revoked in revocations:\n"
"         print 'serial number:', revoked.getSerial()\n"
"         print 'date:', time.ctime(revoked.getDate()[0])\n"
"\n"
"      publicFile.close()\n"
"      crlFile.close()\n"
"         </programlisting>\n"
"      </example>\n"
"\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
x509_crl_object_get_revoked(x509_crl_object *self, PyObject *args)
{
  if (!PyArg_ParseTuple(args, ""))
    goto error;

  return x509_crl_object_helper_get_revoked(X509_CRL_get_REVOKED(self->crl));

 error:

  return NULL;
}

static char X509_crl_object_add_extension__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Crl</memberof>\n"
"      <name>addExtension</name>\n"
"      <parameter>extensionName</parameter>\n"
"      <parameter>critical</parameter>\n"
"      <parameter>extensionValue</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method adds an extension to this CRL.\n"
"         <parameter>extensionName</parameter> should be the of the\n"
"         extension.  <parameter>critical</parameter> should an integer, 1\n"
"         for true and 0 for clase.  <parameter>extensionValue</parameter>\n"
"         should be a string, DER encoded value of the extension.  The name\n"
"         of the extension must be correct according to OpenSSL and can be\n"
"         checkd in the <constant>objects.h</constant> header file, part of\n"
"         the OpenSSL source distrobution.  In the majority of cases they\n"
"         are the same as those defined in <constant>POW._oids</constant>\n"
"         but if you do encounter problems is may be worth checking.\n"
"      </para>\n"
"      <example>\n"
"         <title><function>addExtension</function> method usage</title>\n"
"         <programlisting>\n"
"      oids = POW.pkix.OidData()\n"
"      o2i = oids.obj2oid\n"
"\n"
"      n1 = ('directoryName',  (((o2i('countryName'), ('printableString', 'UK')),),\n"
"                               ((o2i('stateOrProvinceName'), ('printableString', 'Herts')),),\n"
"                               ((o2i('organizationName'), ('printableString', 'The House')),),\n"
"                               ((o2i('commonName'), ('printableString', 'Shannon Works')),)))\n"
"\n"
"      n2 = ('rfc822Name', 'peter_shannon@yahoo.com')\n"
"      n3 = ('uri', 'http://www.p-s.org.uk')\n"
"      n4 = ('iPAddress', (192,168,100,51))\n"
"\n"
"      issuer = POW.pkix.IssuerAltName()\n"
"      issuer.set([n1,n2,n3,n4])\n"
"      crl.addExtension('issuerAltName', 0, issuer.toString())\n"
"         </programlisting>\n"
"      </example>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
X509_crl_object_add_extension(x509_crl_object *self, PyObject *args)
{
  int critical = 0, nid = 0, len = 0;
  char *name = NULL;
  unsigned char *buf = NULL;
  ASN1_OCTET_STRING *octetString = NULL;
  X509_EXTENSION *extn = NULL;

  if (!PyArg_ParseTuple(args, "sis#", &name, &critical, &buf, &len))
    goto error;

  if ((octetString = M_ASN1_OCTET_STRING_new()) == NULL)
    lose("could not allocate memory");

  if (!ASN1_OCTET_STRING_set(octetString, buf, len))
    lose("could not set ASN1 Octect string");

  if ((nid = OBJ_txt2nid(name)) == NID_undef)
    lose("extension has unknown object identifier");

  if ((extn = X509_EXTENSION_create_by_NID(NULL, nid, critical, octetString)) == NULL)
    lose("unable to create ASN1 X509 Extension object");

  if (!self->crl->crl->extensions &&
      (self->crl->crl->extensions = sk_X509_EXTENSION_new_null()) == NULL)
    lose("unable to allocate memory");

  if (!sk_X509_EXTENSION_push(self->crl->crl->extensions, extn))
    lose("unable to add extension");

  Py_RETURN_NONE;

 error:
  X509_EXTENSION_free(extn);
  return NULL;
}

static char X509_crl_object_clear_extensions__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Crl</memberof>\n"
"      <name>clearExtensions</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method clears the structure which holds the extension for\n"
"         this CRL.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
X509_crl_object_clear_extensions(x509_crl_object *self, PyObject *args)
{
  if (!PyArg_ParseTuple(args, ""))
    goto error;

  if (self->crl->crl->extensions) {
    sk_X509_EXTENSION_free(self->crl->crl->extensions);
    self->crl->crl->extensions = NULL;
  }

  Py_RETURN_NONE;

 error:
  return NULL;
}

static char X509_crl_object_count_extensions__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Crl</memberof>\n"
"      <name>countExtensions</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns the size of the structure which holds the\n"
"         extension for this CRL.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
X509_crl_object_count_extensions(x509_crl_object *self, PyObject *args)
{
  int num = 0;

  if (!PyArg_ParseTuple(args, ""))
    goto error;

  if (self->crl->crl->extensions)
    num = sk_X509_EXTENSION_num(self->crl->crl->extensions);

  return Py_BuildValue("i", num);

 error:

  return NULL;
}

static char X509_crl_object_get_extension__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Crl</memberof>\n"
"      <name>getExtension</name>\n"
"      <parameter>index</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns a tuple equivalent the parameters of\n"
"         <function>addExtension</function>.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
X509_crl_object_get_extension(x509_crl_object *self, PyObject *args)
{
  int num = 0, index = 0, ext_nid = 0;
  char const *ext_ln = NULL;
  char unknown_ext [] = "unknown";
  X509_EXTENSION *ext;

  if (!PyArg_ParseTuple(args, "i", &index))
    goto error;

  if (self->crl->crl->extensions)
    num = sk_X509_EXTENSION_num(self->crl->crl->extensions);


  if (index >= num)
    lose("certificate does not have that many extensions");

  if ((ext = sk_X509_EXTENSION_value(self->crl->crl->extensions, index)) == NULL)
    lose("could not get extension");

  if ((ext_nid = OBJ_obj2nid(ext->object)) == NID_undef)
    lose("extension has unknown object identifier");

  if ((ext_ln = OBJ_nid2sn(ext_nid)) == NULL)
    ext_ln = unknown_ext;

  return Py_BuildValue("sis#", ext_ln, ext->critical, ext->value->data, ext->value->length);

 error:

  return NULL;
}

static char x509_crl_object_sign__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Crl</memberof>\n"
"      <name>sign</name>\n"
"      <parameter>key</parameter>\n"
"      <parameter>digest = MD5_DIGEST</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         <parameter>key</parameter> should be an instance of\n"
"         <classname>Asymmetric</classname> and contain a private key.\n"
"         <parameter>digest</parameter> indicates\n"
"         which digest function should be used to compute the hash to be\n"
"         signed, it should be one of the following:\n"
"      </para>\n"
"      <simplelist>\n"
"         <member><constant>MD5_DIGEST</constant></member>\n"
"         <member><constant>SHA_DIGEST</constant></member>\n"
"         <member><constant>SHA1_DIGEST</constant></member>\n"
"         <member><constant>SHA256_DIGEST</constant></member>\n"
"         <member><constant>SHA384_DIGEST</constant></member>\n"
"         <member><constant>SHA512_DIGEST</constant></member>\n"
"     </simplelist>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
x509_crl_object_sign(x509_crl_object *self, PyObject *args)
{
  EVP_PKEY *pkey = NULL;
  asymmetric_object *asym;
  int digest = MD5_DIGEST;

  if (!PyArg_ParseTuple(args, "O!|i", &asymmetrictype, &asym, &digest))
    goto error;

  if ((pkey = EVP_PKEY_new()) == NULL)
    lose("could not allocate memory");

  if (asym->key_type != RSA_PRIVATE_KEY)
    lose("cannot use this type of key");

  if (!EVP_PKEY_assign_RSA(pkey, asym->cipher))
    lose("EVP_PKEY assignment error");

  switch (digest) {
  case MD5_DIGEST:
    if (!X509_CRL_sign(self->crl, pkey, EVP_md5()))
      lose("could not sign CRL");
    break;

  case SHA_DIGEST:
    if (!X509_CRL_sign(self->crl, pkey, EVP_sha()))
      lose("could not sign CRL");
    break;

  case SHA1_DIGEST:
    if (!X509_CRL_sign(self->crl, pkey, EVP_sha1()))
      lose("could not sign CRL");
    break;

  case SHA256_DIGEST:
    if (!X509_CRL_sign(self->crl, pkey, EVP_sha256()))
      lose("could not sign CRL");
    break;

  case SHA384_DIGEST:
    if (!X509_CRL_sign(self->crl, pkey, EVP_sha384()))
      lose("could not sign CRL");
    break;

  case SHA512_DIGEST:
    if (!X509_CRL_sign(self->crl, pkey, EVP_sha512()))
      lose("could not sign CRL");
    break;
  }

  Py_RETURN_NONE;

 error:
  EVP_PKEY_free(pkey);
  return NULL;
}

static char x509_crl_object_verify__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Crl</memberof>\n"
"      <name>verify</name>\n"
"      <parameter>key</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         The <classname>X509Crl</classname> method\n"
"         <function>verify</function> is based on the\n"
"         <function>X509_CRL_verify</function> function.  Unlike the\n"
"         <classname>X509</classname> function of the same name, this\n"
"         function simply checks the CRL was signed with the private key\n"
"         which corresponds the parameter <parameter>key</parameter>.\n"
"         <parameter>key</parameter> should be an instance of\n"
"         <classname>Asymmetric</classname> and contain a public key.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
x509_crl_object_verify(x509_crl_object *self, PyObject *args)
{
  EVP_PKEY *pkey = NULL;
  asymmetric_object *asym;
  int ok;

  if (!PyArg_ParseTuple(args, "O!", &asymmetrictype, &asym))
    goto error;

  if ((pkey = EVP_PKEY_new()) == NULL)
    lose("could not allocate memory");

  if (!EVP_PKEY_assign_RSA(pkey, asym->cipher))
    lose("EVP_PKEY assignment error");

  ok = X509_CRL_verify(self->crl, pkey);

  return PyBool_FromLong(ok);

 error:
  EVP_PKEY_free(pkey);
  return NULL;
}

static PyObject *
x509_crl_object_write_helper(x509_crl_object *self, PyObject *args, int format)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  if (!PyArg_ParseTuple(args, ""))
    goto error;

  bio = BIO_new(BIO_s_mem());

  switch (format) {

  case DER_FORMAT:
    if (!i2d_X509_CRL_bio(bio, self->crl))
      lose("unable to write certificate");
    break;

  case PEM_FORMAT:
    if (!PEM_write_bio_X509_CRL(bio, self->crl))
      lose("unable to write certificate");

  default:
    lose("internal error, unknown output format");
  }

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static char x509_crl_object_pem_write__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Crl</memberof>\n"
"      <name>pemWrite</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns a PEM encoded CRL as a\n"
"         string.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
x509_crl_object_pem_write(x509_crl_object *self, PyObject *args)
{
  return x509_crl_object_write_helper(self, args, PEM_FORMAT);
}

static char x509_crl_object_der_write__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Crl</memberof>\n"
"      <name>derWrite</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns a DER encoded CRL as a string.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
x509_crl_object_der_write(x509_crl_object *self, PyObject *args)
{
  return x509_crl_object_write_helper(self, args, DER_FORMAT);
}

static char x509_crl_object_pprint__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Crl</memberof>\n"
"      <name>pprint</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns a formatted string showing the information\n"
"         held in the CRL.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
x509_crl_object_pprint(x509_crl_object *self, PyObject *args)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  if (!PyArg_ParseTuple(args, ""))
    goto error;

  bio = BIO_new(BIO_s_mem());

  if (!X509_CRL_print(bio, self->crl))
    lose("unable to pretty-print CRL");

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static struct PyMethodDef x509_crl_object_methods[] = {
  {"sign",             (PyCFunction)x509_crl_object_sign,              METH_VARARGS,  NULL},
  {"verify",           (PyCFunction)x509_crl_object_verify,            METH_VARARGS,  NULL},
  {"getVersion",       (PyCFunction)x509_crl_object_get_version,       METH_VARARGS,  NULL},
  {"setVersion",       (PyCFunction)x509_crl_object_set_version,       METH_VARARGS,  NULL},
  {"getIssuer",        (PyCFunction)x509_crl_object_get_issuer,        METH_VARARGS,  NULL},
  {"setIssuer",        (PyCFunction)x509_crl_object_set_issuer,        METH_VARARGS,  NULL},
  {"getThisUpdate",    (PyCFunction)x509_crl_object_get_this_update,   METH_VARARGS,  NULL},
  {"setThisUpdate",    (PyCFunction)x509_crl_object_set_this_update,   METH_VARARGS,  NULL},
  {"getNextUpdate",    (PyCFunction)x509_crl_object_get_next_update,   METH_VARARGS,  NULL},
  {"setNextUpdate",    (PyCFunction)x509_crl_object_set_next_update,   METH_VARARGS,  NULL},
  {"setRevoked",       (PyCFunction)x509_crl_object_set_revoked,       METH_VARARGS,  NULL},
  {"getRevoked",       (PyCFunction)x509_crl_object_get_revoked,       METH_VARARGS,  NULL},
  {"addExtension",     (PyCFunction)X509_crl_object_add_extension,     METH_VARARGS,  NULL},
  {"clearExtensions",  (PyCFunction)X509_crl_object_clear_extensions,  METH_VARARGS,  NULL},
  {"countExtensions",  (PyCFunction)X509_crl_object_count_extensions,  METH_VARARGS,  NULL},
  {"getExtension",     (PyCFunction)X509_crl_object_get_extension,     METH_VARARGS,  NULL},
  {"pemWrite",         (PyCFunction)x509_crl_object_pem_write,         METH_VARARGS,  NULL},
  {"derWrite",         (PyCFunction)x509_crl_object_der_write,         METH_VARARGS,  NULL},
  {"pprint",           (PyCFunction)x509_crl_object_pprint,            METH_VARARGS,  NULL},

  {NULL}    /* sentinel */
};

static PyObject *
x509_crl_object_getattr(x509_crl_object *self, char *name)
{
  return Py_FindMethod(x509_crl_object_methods, (PyObject *)self, name);
}

static void
x509_crl_object_dealloc(x509_crl_object *self, char *name)
{
  X509_CRL_free(self->crl);
  PyObject_Del(self);
}

static char x509_crltype__doc__[] =
"<class>\n"
"   <header>\n"
"      <name>X509Crl</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This class provides access to OpenSSL X509 CRL management\n"
"         facilities.\n"
"      </para>\n"
"   </body>\n"
"</class>\n"
;

static PyTypeObject x509_crltype = {
  PyObject_HEAD_INIT(0)
  0,                                     /*ob_size*/
  "X509Crl",                             /*tp_name*/
  sizeof(x509_crl_object),               /*tp_basicsize*/
  0,                                     /*tp_itemsize*/
  (destructor)x509_crl_object_dealloc,   /*tp_dealloc*/
  (printfunc)0,                          /*tp_print*/
  (getattrfunc)x509_crl_object_getattr,  /*tp_getattr*/
  (setattrfunc)0,                        /*tp_setattr*/
  (cmpfunc)0,                            /*tp_compare*/
  (reprfunc)0,                           /*tp_repr*/
  0,                                     /*tp_as_number*/
  0,                                     /*tp_as_sequence*/
  0,                                     /*tp_as_mapping*/
  (hashfunc)0,                           /*tp_hash*/
  (ternaryfunc)0,                        /*tp_call*/
  (reprfunc)0,                           /*tp_str*/
  0,
  0,
  0,
  0,
  x509_crltype__doc__                   /* Documentation string */
};
/*========== x509 crl Code ==========*/

/*========== revoked Code ==========*/
static x509_revoked_object* x509_revoked_object_new(void)
{
  x509_revoked_object *self = NULL;

  if ((self = PyObject_New(x509_revoked_object, &x509_revokedtype)) == NULL)
    goto error;

  self->revoked = X509_REVOKED_new();

  return self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static char x509_revoked_object_set_serial__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Revoked</memberof>\n"
"      <name>setSerial</name>\n"
"      <parameter>serial</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method sets the serial number in the serial field of\n"
"         this object.  <parameter>serial</parameter> should be an\n"
"         integer.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
x509_revoked_object_set_serial(x509_revoked_object *self, PyObject *args)
{
  int serial = 0;

  if (!PyArg_ParseTuple(args, "i", &serial))
    goto error;

  if (!ASN1_INTEGER_set(self->revoked->serialNumber, serial))
    lose("unable to set serial number");

  Py_RETURN_NONE;

 error:

  return NULL;
}

static char x509_revoked_object_get_serial__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Revoked</memberof>\n"
"      <name>getSerial</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method gets the serial number in the serial field of\n"
"         this object.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
x509_revoked_object_get_serial(x509_revoked_object *self, PyObject *args)
{
  int serial = 0;

  if (!PyArg_ParseTuple(args, ""))
    goto error;

  if ((serial = ASN1_INTEGER_get(self->revoked->serialNumber)) == -1)
    lose("unable to get serial number");

  return Py_BuildValue("i", serial);

 error:

  return NULL;
}

static char x509_revoked_object_get_date__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Revoked</memberof>\n"
"      <name>getDate</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         In a change from previous releases, for reasons of portability\n"
"         and to avoid hard to fix issues with problems in unreliable time\n"
"         functions, this function returns a UTCTime string.  You\n"
"         can use the function <function>time2utc</function> to convert to a\n"
"         string if you like and <function>utc2time</function> to back.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
x509_revoked_object_get_date(x509_revoked_object *self, PyObject *args)
{
  if (!PyArg_ParseTuple(args, ""))
    goto error;

  return ASN1_TIME_to_Python(self->revoked->revocationDate);

 error:

  return NULL;
}

static char x509_revoked_object_set_date__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Revoked</memberof>\n"
"      <name>setDate</name>\n"
"      <parameter>time</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         In a change from previous releases, for reasons of portability\n"
"         and to avoid hard to fix issues with problems in unreliable time\n"
"         functions, this accepts one parameter, a UTCTime string.  You\n"
"         can use the function <function>time2utc</function> to convert to a\n"
"         string if you like and <function>utc2time</function> to back.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
x509_revoked_object_set_date(x509_revoked_object *self, PyObject *args)
{
  char *time = NULL;

  if (!PyArg_ParseTuple(args, "s", &time))
    goto error;

  if (!python_ASN1_TIME_set_string(self->revoked->revocationDate, time))
    lose_type_error("Could not set revocationDate");

  Py_RETURN_NONE;

 error:

  return NULL;
}

static char X509_revoked_object_add_extension__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Revoked</memberof>\n"
"      <name>addExtension</name>\n"
"      <parameter>extensionName</parameter>\n"
"      <parameter>critical</parameter>\n"
"      <parameter>extensionValue</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method adds an extension to this revocation.\n"
"         <parameter>extensionName</parameter> should be the of the\n"
"         extension.  <parameter>critical</parameter> should an integer, 1\n"
"         for true and 0 for clase.  <parameter>extensionValue</parameter>\n"
"         should be a string, DER encoded value of the extension.  The name\n"
"         of the extension must be correct according to OpenSSL and can be\n"
"         checkd in the <constant>objects.h</constant> header file, part of\n"
"         the OpenSSL source distrobution.  In the majority of cases they\n"
"         are the same as those defined in <constant>POW._oids</constant>\n"
"         but if you do encounter problems is may be worth checking.\n"
"      </para>\n"
"      <example>\n"
"         <title><function>addExtension</function> method usage</title>\n"
"         <programlisting>\n"
"      reason = POW.pkix.CrlReason()\n"
"      reason.set(1)\n"
"      revocation.addExtension('CRLReason', 0, reason.toString())\n"
"         </programlisting>\n"
"      </example>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
X509_revoked_object_add_extension(x509_revoked_object *self, PyObject *args)
{
  int critical = 0, nid = 0, len = 0;
  char *name = NULL;
  unsigned char *buf = NULL;
  ASN1_OCTET_STRING *octetString = NULL;
  X509_EXTENSION *extn = NULL;

  if (!PyArg_ParseTuple(args, "sis#", &name, &critical, &buf, &len))
    goto error;

  if ((octetString = M_ASN1_OCTET_STRING_new()) == NULL)
    lose("could not allocate memory");

  if (!ASN1_OCTET_STRING_set(octetString, buf, strlen((char *) buf)))
    lose("could not set ASN1 Octect string");

  if ((nid = OBJ_txt2nid(name)) == NID_undef)
    lose("extension has unknown object identifier");

  if ((extn = X509_EXTENSION_create_by_NID(NULL, nid, critical, octetString)) == NULL)
    lose("unable to create ASN1 X509 Extension object");

  if (!self->revoked->extensions && (self->revoked->extensions = sk_X509_EXTENSION_new_null()) == NULL)
    lose("unable to allocate memory");

  if (!sk_X509_EXTENSION_push(self->revoked->extensions, extn))
    lose("unable to add extension");

  Py_RETURN_NONE;

 error:
  X509_EXTENSION_free(extn);
  return NULL;
}

static char X509_revoked_object_clear_extensions__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Revoked</memberof>\n"
"      <name>clearExtensions</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method clears the structure which holds the extension for\n"
"         this revocation.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
X509_revoked_object_clear_extensions(x509_revoked_object *self, PyObject *args)
{
  if (!PyArg_ParseTuple(args, ""))
    goto error;

  if (self->revoked->extensions) {
    sk_X509_EXTENSION_free(self->revoked->extensions);
    self->revoked->extensions = NULL;
  }

  Py_RETURN_NONE;

 error:
  return NULL;
}

static char X509_revoked_object_count_extensions__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Revoked</memberof>\n"
"      <name>countExtensions</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns the size of the structure which holds the\n"
"         extension for this revocation.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
X509_revoked_object_count_extensions(x509_revoked_object *self, PyObject *args)
{
  int num = 0;

  if (!PyArg_ParseTuple(args, ""))
    goto error;

  if (self->revoked->extensions)
    num = sk_X509_EXTENSION_num(self->revoked->extensions);

  return Py_BuildValue("i", num);

 error:

  return NULL;
}

static char X509_revoked_object_get_extension__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>X509Revoked</memberof>\n"
"      <name>getExtension</name>\n"
"      <parameter>index</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns a tuple equivalent the parameters of\n"
"         <function>addExtension</function>.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
X509_revoked_object_get_extension(x509_revoked_object *self, PyObject *args)
{
  int num = 0, index = 0, ext_nid = 0;
  char const *ext_ln = NULL;
  char unknown_ext [] = "unknown";
  X509_EXTENSION *ext;

  if (!PyArg_ParseTuple(args, "i", &index))
    goto error;

  if (self->revoked->extensions)
    num = sk_X509_EXTENSION_num(self->revoked->extensions);

  if (index >= num)
    lose("certificate does not have that many extensions");

  if ((ext = sk_X509_EXTENSION_value(self->revoked->extensions, index)) == NULL)
    lose("could not get extension");

  if ((ext_nid = OBJ_obj2nid(ext->object)) == NID_undef)
    lose("extension has unknown object identifier");

  if ((ext_ln = OBJ_nid2sn(ext_nid)) == NULL)
    ext_ln = unknown_ext;

  return Py_BuildValue("sis#", ext_ln, ext->critical, ext->value->data, ext->value->length);

 error:

  return NULL;
}

static struct PyMethodDef x509_revoked_object_methods[] = {
  {"getSerial",         (PyCFunction)x509_revoked_object_get_serial,       METH_VARARGS,  NULL},
  {"setSerial",         (PyCFunction)x509_revoked_object_set_serial,       METH_VARARGS,  NULL},
  {"getDate",           (PyCFunction)x509_revoked_object_get_date,         METH_VARARGS,  NULL},
  {"setDate",           (PyCFunction)x509_revoked_object_set_date,         METH_VARARGS,  NULL},
  {"addExtension",      (PyCFunction)X509_revoked_object_add_extension,    METH_VARARGS,  NULL},
  {"clearExtensions",   (PyCFunction)X509_revoked_object_clear_extensions, METH_VARARGS,  NULL},
  {"countExtensions",   (PyCFunction)X509_revoked_object_count_extensions, METH_VARARGS,  NULL},
  {"getExtension",      (PyCFunction)X509_revoked_object_get_extension,    METH_VARARGS,  NULL},

  {NULL}    /* sentinel */
};

static PyObject *
x509_revoked_object_getattr(x509_revoked_object *self, char *name)
{
  return Py_FindMethod(x509_revoked_object_methods, (PyObject *) self, name);
}

static void
x509_revoked_object_dealloc(x509_revoked_object *self, char *name)
{
  X509_REVOKED_free(self->revoked);
  PyObject_Del(self);
}

static char x509_revokedtype__doc__[] =
"<class>\n"
"   <header>\n"
"      <name>X509Revoked</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This class provides a container for details of a revoked\n"
"         certificate.  It normally would only be used in association with\n"
"         a CRL, its not much use by itself.  Indeed the only reason this\n"
"         class exists is because in the future POW is likely to be extended\n"
"         to support extensions for certificates, CRLs and revocations.\n"
"         <classname>X509Revoked</classname> existing as an object in its\n"
"         own right will make adding this support easier, while avoiding\n"
"         backwards compatibility issues.\n"
"      </para>\n"
"   </body>\n"
"</class>\n"
;

static PyTypeObject x509_revokedtype = {
  PyObject_HEAD_INIT(0)
  0,                                        /*ob_size*/
  "X509Revoked",                            /*tp_name*/
  sizeof(x509_revoked_object),              /*tp_basicsize*/
  0,                                        /*tp_itemsize*/
  (destructor)x509_revoked_object_dealloc,  /*tp_dealloc*/
  (printfunc)0,                             /*tp_print*/
  (getattrfunc)x509_revoked_object_getattr, /*tp_getattr*/
  (setattrfunc)0,                           /*tp_setattr*/
  (cmpfunc)0,                               /*tp_compare*/
  (reprfunc)0,                              /*tp_repr*/
  0,                                        /*tp_as_number*/
  0,                                        /*tp_as_sequence*/
  0,                                        /*tp_as_mapping*/
  (hashfunc)0,                              /*tp_hash*/
  (ternaryfunc)0,                           /*tp_call*/
  (reprfunc)0,                              /*tp_str*/
  0,
  0,
  0,
  0,
  x509_revokedtype__doc__                  /* Documentation string */
};
/*========== x509 revoked Code ==========*/

/*========== asymmetric Object ==========*/
static asymmetric_object *
asymmetric_object_new(int cipher_type, int key_size)
{
  asymmetric_object *self = NULL;

  self = PyObject_New(asymmetric_object, &asymmetrictype);
  if (self == NULL)
    goto error;

  if (cipher_type != RSA_CIPHER)
    lose("unsupported cipher");

  if ((self->cipher = RSA_generate_key(key_size,RSA_F4,NULL,NULL)) == NULL)
    lose("could not generate key");

  self->key_type = RSA_PRIVATE_KEY;
  self->cipher_type = RSA_CIPHER;

  return self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static asymmetric_object *
asymmetric_object_pem_read(int key_type, BIO *in, char *pass)
{
  asymmetric_object *self = NULL;

  self = PyObject_New(asymmetric_object, &asymmetrictype);
  if (self == NULL)
    goto error;

  switch (key_type) {

  case RSA_PUBLIC_KEY:
    if ((self->cipher = PEM_read_bio_RSA_PUBKEY(in, NULL, NULL, NULL)) == NULL)
      lose("could not load public key");
    self->key_type = RSA_PUBLIC_KEY;
    self->cipher_type = RSA_CIPHER;
    break;

  case RSA_PRIVATE_KEY:
    if ((self->cipher = PEM_read_bio_RSAPrivateKey(in, NULL, NULL, pass)) == NULL)
      lose("could not load private key");
    self->key_type = RSA_PRIVATE_KEY;
    self->cipher_type = RSA_CIPHER;
    break;

  default:
    lose("unknown key type");
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
  unsigned char *ptr = src;

  self = PyObject_New(asymmetric_object, &asymmetrictype);
  if (self == NULL)
    goto error;

  switch (key_type) {
  case RSA_PUBLIC_KEY:

    if ((self->cipher = d2i_RSA_PUBKEY(NULL, (const unsigned char **) &ptr, len)) == NULL)
      lose("could not load public key");

    self->key_type = RSA_PUBLIC_KEY;
    self->cipher_type = RSA_CIPHER;
    break;

  case RSA_PRIVATE_KEY:

    if ((self->cipher = d2i_RSAPrivateKey(NULL, (const unsigned char **) &ptr, len)) == NULL)
      lose("could not load private key");

    self->key_type = RSA_PRIVATE_KEY;
    self->cipher_type = RSA_CIPHER;
    break;

  default:
    lose("unknown key type");
  }

  return self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static char asymmetric_object_pem_write__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>Asymmetric</memberof>\n"
"      <name>pemWrite</name>\n"
"      <parameter>keytype</parameter>\n"
"      <parameter>ciphertype = None</parameter>\n"
"      <parameter>passphrase = None</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method is used to write <classname>Asymmetric</classname>\n"
"         objects out as strings.  The first argument should be either\n"
"         <constant>RSA_PUBLIC_KEY</constant> or\n"
"         <constant>RSA_PRIVATE_KEY</constant>.  Private keys are often\n"
"         saved in encrypted files to offer extra security above access\n"
"         control mechanisms.  If the <parameter>keytype</parameter> is\n"
"         <constant>RSA_PRIVATE_KEY</constant> a\n"
"         <parameter>ciphertype</parameter> and\n"
"         <parameter>passphrase</parameter> can also be specified.  The\n"
"         <parameter>ciphertype</parameter> should be one of those listed in\n"
"         the <classname>Symmetric</classname> class section.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
asymmetric_object_pem_write(asymmetric_object *self, PyObject *args)
{
  PyObject *result = NULL;
  int key_type = 0, cipher = 0;
  char *kstr = NULL;
  BIO *bio = NULL;

  if (!PyArg_ParseTuple(args, "|iis", &key_type, &cipher, &kstr))
    goto error;

  if (key_type == 0)
    key_type = self->key_type;

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    lose("unable to create new BIO");

  if ((kstr && !cipher) || (cipher && !kstr))
    lose("cipher type and key string must both be supplied");

  switch(key_type) {

  case RSA_PRIVATE_KEY:
    if (kstr && cipher) {
      if (!PEM_write_bio_RSAPrivateKey(bio, self->cipher, evp_cipher_factory(cipher),
                                       NULL, 0, NULL, kstr))
        lose("unable to write key");
    }
    else {
      if (!PEM_write_bio_RSAPrivateKey(bio, self->cipher, NULL, NULL, 0, NULL, NULL))
        lose("unable to write key");
    }
    break;

  case RSA_PUBLIC_KEY:
    if (kstr && cipher)
      lose("public keys should not encrypted");
    else {
      if (!PEM_write_bio_RSA_PUBKEY(bio, self->cipher))
        lose("unable to write key");
    }
    break;

  default:
    lose("unsupported key type");
  }

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static char asymmetric_object_der_write__doc__[] =
"<method>"
"   <header>"
"      <memberof>Asymmetric</memberof>"
"      <name>derWrite</name>"
"      <parameter>keytype</parameter>"
"   </header>"
"   <body>"
"      <para>"
"         This method is used to write <classname>Asymmetric</classname>"
"         objects out as strings.  The first argument should be either"
"         <constant>RSA_PUBLIC_KEY</constant> or "
"         <constant>RSA_PRIVATE_KEY</constant>."
"      </para>"
"   </body>"
"</method>"
;

static PyObject *
asymmetric_object_der_write(asymmetric_object *self, PyObject *args)
{
  int len = 0, key_type = 0;
  unsigned char *buf = NULL, *p = NULL;
  PyObject *asymmetric = NULL;

  if (!PyArg_ParseTuple(args, "|i", &key_type))
    goto error;

  if (key_type == 0)
    key_type = self->key_type;

  switch(key_type) {

  case RSA_PRIVATE_KEY:
    len = i2d_RSAPrivateKey(self->cipher, NULL);
    if ((buf = malloc(len)) == NULL)
      lose("could not allocate memory");
    p = buf;
    if (!i2d_RSAPrivateKey(self->cipher, &buf))
      lose("unable to write key");
    break;

  case RSA_PUBLIC_KEY:
    len = i2d_RSA_PUBKEY(self->cipher, NULL);
    if ((buf = malloc(len)) == NULL)
      lose("could not allocate memory");
    p = buf;
    if (!i2d_RSA_PUBKEY(self->cipher, &buf))
      lose("unable to write key");
    break;

  default:
    lose("unsupported key type");
  }

  asymmetric = Py_BuildValue("s#", p, len);

  free(p);
  return asymmetric;

 error:

  if (p)
    free(p);

  return NULL;
}

static char asymmetric_object_public_encrypt__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>Asymmetric</memberof>\n"
"      <name>publicEncrypt</name>\n"
"      <parameter>plaintext</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method is used to encrypt the <parameter>plaintext</parameter>\n"
"         using a public key. It should be noted; in practice this\n"
"         function would be used almost exclusively to encrypt symmetric cipher\n"
"         keys and not data since asymmetric cipher operations are very slow.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
asymmetric_object_public_encrypt(asymmetric_object *self, PyObject *args)
{
  unsigned char *plain_text = NULL, *cipher_text = NULL;
  int len = 0, size = 0;
  PyObject *obj = NULL;

  if (self->cipher_type != RSA_CIPHER)
    lose("unsupported cipher type");

  if (!PyArg_ParseTuple(args, "s#", &plain_text, &len))
    goto error;

  size = RSA_size(self->cipher);
  if (len > size)
    lose("plain text is too long");

  if ((cipher_text = malloc(size + 16)) == NULL)
    lose("could not allocate memory");

  if ((len = RSA_public_encrypt(len, plain_text, cipher_text, self->cipher, RSA_PKCS1_PADDING)) < 0)
    lose("could not encrypt plain text");

  obj = Py_BuildValue("s#", cipher_text, len);
  free(cipher_text);
  return obj;

 error:

  if (cipher_text)
    free(cipher_text);

  return NULL;
}

static char asymmetric_object_private_encrypt__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>Asymmetric</memberof>\n"
"      <name>privateEncrypt</name>\n"
"      <parameter>plaintext</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method is used to encrypt the <parameter>plaintext</parameter>\n"
"         using a private key. It should be noted; in practice this\n"
"         function would be used almost exclusively to encrypt symmetric cipher\n"
"         keys and not data since asymmetric cipher operations are very slow.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
asymmetric_object_private_encrypt(asymmetric_object *self, PyObject *args)
{
  unsigned char *plain_text = NULL, *cipher_text = NULL;
  int len = 0, size = 0;
  PyObject *obj = NULL;

  if (self->key_type != RSA_PRIVATE_KEY)
    lose("cannot perform private encryption with this key");

  if (!PyArg_ParseTuple(args, "s#", &plain_text, &len))
    goto error;

  size = RSA_size(self->cipher);
  if (len > size)
    lose("plain text is too long");

  if ((cipher_text = malloc(size + 16)) == NULL)
    lose("could not allocate memory");

  if ((len = RSA_private_encrypt(len, plain_text, cipher_text, self->cipher, RSA_PKCS1_PADDING)) < 0)
    lose("could not encrypt plain text");

  obj = Py_BuildValue("s#", cipher_text, len);
  free(cipher_text);
  return obj;

 error:

  if (cipher_text)
    free(cipher_text);

  return NULL;
}

static char asymmetric_object_public_decrypt__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>Asymmetric</memberof>\n"
"      <name>publicDecrypt</name>\n"
"      <parameter>ciphertext</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method is used to decrypt the\n"
"         <parameter>ciphertext</parameter> which has been encrypted\n"
"         using the corresponding private key and the\n"
"         <function>privateEncrypt</function> function.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
asymmetric_object_public_decrypt(asymmetric_object *self, PyObject *args)
{
  unsigned char *plain_text = NULL, *cipher_text = NULL;
  int len = 0, size = 0;
  PyObject *obj = NULL;

  if (self->cipher_type != RSA_CIPHER)
    lose("unsupported cipher type");

  if (!PyArg_ParseTuple(args, "s#", &cipher_text, &len))
    goto error;

  size = RSA_size(self->cipher);
  if (len > size)
    lose("cipher text is too long");

  if ((plain_text = malloc(size + 16)) == NULL)
    lose("could not allocate memory");

  if ((len = RSA_public_decrypt(len, cipher_text, plain_text, self->cipher, RSA_PKCS1_PADDING)) < 0)
    lose("could not decrypt cipher text");

  obj = Py_BuildValue("s#", plain_text, len);
  free(plain_text);
  return obj;

 error:

  if (plain_text)
    free(plain_text);

  return NULL;
}

static char asymmetric_object_private_decrypt__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>Asymmetric</memberof>\n"
"      <name>privateDecrypt</name>\n"
"      <parameter>ciphertext</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method is used to decrypt ciphertext which has been encrypted\n"
"         using the corresponding public key and the\n"
"         <function>publicEncrypt</function> function.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
asymmetric_object_private_decrypt(asymmetric_object *self, PyObject *args)
{
  unsigned char *plain_text = NULL, *cipher_text = NULL;
  int len = 0, size = 0;
  PyObject *obj = NULL;

  if (self->key_type != RSA_PRIVATE_KEY)
    lose("cannot perform private decryption with this key");

  if (!PyArg_ParseTuple(args, "s#", &cipher_text, &len))
    goto error;

  size = RSA_size(self->cipher);
  if (len > size)
    lose("cipher text is too long");

  if ((plain_text = malloc(size + 16)) == NULL)
    lose("could not allocate memory");

  if ((len = RSA_private_decrypt(len, cipher_text, plain_text, self->cipher, RSA_PKCS1_PADDING)) < 0)
    lose("could not decrypt cipher text");

  obj = Py_BuildValue("s#", plain_text, len);
  free(plain_text);
  return obj;

 error:

  if (plain_text)
    free(plain_text);
  return NULL;
}

static char asymmetric_object_sign__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>Asymmetric</memberof>\n"
"      <name>sign</name>\n"
"      <parameter>digesttext</parameter>\n"
"      <parameter>digesttype</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method is used to produce a signed digest text.\n"
"         This instance of\n"
"         <classname>Asymmetric</classname> should be a private key used for\n"
"         signing.  The parameter\n"
"         <parameter>digesttext</parameter> should be a digest of the\n"
"         data to protect against alteration and\n"
"         finally <parameter>digesttype</parameter> should be one of the\n"
"         following:\n"
"      </para>\n"
"      <simplelist>\n"
"         <member><constant>MD5_DIGEST</constant></member>\n"
"         <member><constant>SHA_DIGEST</constant></member>\n"
"         <member><constant>SHA1_DIGEST</constant></member>\n"
"         <member><constant>SHA256_DIGEST</constant></member>\n"
"         <member><constant>SHA384_DIGEST</constant></member>\n"
"         <member><constant>SHA512_DIGEST</constant></member>\n"
"      </simplelist>\n"
"      <para>\n"
"         If the procedure was successful, a string containing the signed\n"
"         digest is returned.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
asymmetric_object_sign(asymmetric_object *self, PyObject *args)
{
  unsigned char *digest_text = NULL, *signed_text = NULL;
  unsigned int digest_len = 0, digest_type = 0, digest_nid = 0, signed_len = 0;
  PyObject *obj = NULL;

  if (!PyArg_ParseTuple(args, "s#i", &digest_text, &digest_len, &digest_type))
    goto error;

  if (self->key_type != RSA_PRIVATE_KEY)
    lose("unsupported key type");

  if ((signed_text = malloc(RSA_size(self->cipher))) == NULL)
    lose("could not allocate memory");

  switch(digest_type) {
  case MD5_DIGEST:
    digest_nid = NID_md5;
    digest_len = MD5_DIGEST_LENGTH;
    break;
  case SHA_DIGEST:
    digest_nid = NID_sha;
    digest_len = SHA_DIGEST_LENGTH;
    break;
  case SHA1_DIGEST:
    digest_nid = NID_sha1;
    digest_len = SHA_DIGEST_LENGTH;
    break;
  case SHA256_DIGEST:
    digest_nid = NID_sha256;
    digest_len = SHA256_DIGEST_LENGTH;
    break;
  case SHA384_DIGEST:
    digest_nid = NID_sha384;
    digest_len = SHA384_DIGEST_LENGTH;
    break;
  case SHA512_DIGEST:
    digest_nid = NID_sha512;
    digest_len = SHA512_DIGEST_LENGTH;
    break;
  default:
    lose("unsupported digest");
  }

  if (!RSA_sign(digest_nid, digest_text, digest_len, signed_text, &signed_len, self->cipher))
    lose("could not sign digest");

  obj = Py_BuildValue("s#", signed_text, signed_len);
  free(signed_text);
  return obj;

 error:

  if (signed_text)
    free(signed_text);

  return NULL;
}

static char asymmetric_object_verify__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>Asymmetric</memberof>\n"
"      <name>verify</name>\n"
"      <parameter>signedtext</parameter>\n"
"      <parameter>digesttext</parameter>\n"
"      <parameter>digesttype</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method is used to verify a signed digest text.\n"
"      </para>\n"
"       <example>\n"
"         <title><function>verify</function> method usage</title>\n"
"         <programlisting>\n"
"      plain_text = 'Hello World!'\n"
"      print '\tPlain text:', plain_text\n"
"      digest = POW.Digest(POW.RIPEMD160_DIGEST)\n"
"      digest.update(plain_text)\n"
"      print '\tDigest text:', digest.digest()\n"
"\n"
"      privateFile = open('test/private.key', 'r')\n"
"      privateKey = POW.pemRead(POW.RSA_PRIVATE_KEY, privateFile.read(), 'pass')\n"
"      privateFile.close()\n"
"      signed_text =  privateKey.sign(digest.digest(), POW.RIPEMD160_DIGEST)\n"
"      print '\tSigned text:', signed_text\n"
"\n"
"      digest2 = POW.Digest(POW.RIPEMD160_DIGEST)\n"
"      digest2.update(plain_text)\n"
"      publicFile = open('test/public.key', 'r')\n"
"      publicKey = POW.pemRead(POW.RSA_PUBLIC_KEY, publicFile.read())\n"
"      publicFile.close()\n"
"      if publicKey.verify(signed_text, digest2.digest(), POW.RIPEMD160_DIGEST):\n"
"         print 'Signing verified!'\n"
"      else:\n"
"         print 'Signing gone wrong!'\n"
"         </programlisting>\n"
"      </example>\n"
"      <para>\n"
"         The parameter <parameter>signedtext</parameter> should be a\n"
"         signed digest text.  This instance of\n"
"         <classname>Asymmetric</classname> should correspond to the private\n"
"         key used to sign the digest.  The parameter\n"
"         <parameter>digesttext</parameter> should be a digest of the same\n"
"         data used to produce the <parameter>signedtext</parameter> and\n"
"         finally <parameter>digesttype</parameter> should be one of the\n"
"         following:\n"
"      </para>\n"
"      <simplelist>\n"
"         <member><constant>MD5_DIGEST</constant></member>\n"
"         <member><constant>SHA_DIGEST</constant></member>\n"
"         <member><constant>SHA1_DIGEST</constant></member>\n"
"         <member><constant>SHA256_DIGEST</constant></member>\n"
"         <member><constant>SHA384_DIGEST</constant></member>\n"
"         <member><constant>SHA512_DIGEST</constant></member>\n"
"      </simplelist>\n"
"      <para>\n"
"         If the procedure was successful, 1 is returned, otherwise 0 is\n"
"         returned.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
asymmetric_object_verify(asymmetric_object *self, PyObject *args)
{
  unsigned char *digest_text = NULL, *signed_text = NULL;
  int digest_len = 0, digest_type = 0, digest_nid = 0, signed_len = 0;

  if (!PyArg_ParseTuple(args, "s#s#i", &signed_text, &signed_len, &digest_text, &digest_len, &digest_type))
    goto error;

  switch (digest_type) {
  case MD5_DIGEST:
    digest_len = MD5_DIGEST_LENGTH;
    digest_nid = NID_md5;
    break;
  case SHA_DIGEST:
    digest_len = SHA_DIGEST_LENGTH;
    digest_nid = NID_sha;
    break;
  case SHA1_DIGEST:
    digest_len = SHA_DIGEST_LENGTH;
    digest_nid = NID_sha1;
    break;
  case SHA256_DIGEST:
    digest_len = SHA256_DIGEST_LENGTH;
    digest_nid = NID_sha256;
    break;
  case SHA384_DIGEST:
    digest_len = SHA384_DIGEST_LENGTH;
    digest_nid = NID_sha384;
    break;
  case SHA512_DIGEST:
    digest_len = SHA512_DIGEST_LENGTH;
    digest_nid = NID_sha512;
    break;
  default:
    lose("unsupported digest");
  }

  return PyBool_FromLong(RSA_verify(digest_nid, digest_text, digest_len, signed_text, signed_len, self->cipher));

 error:

  return NULL;
}

static struct PyMethodDef asymmetric_object_methods[] = {
  {"pemWrite",          (PyCFunction)asymmetric_object_pem_write,       METH_VARARGS,  NULL},
  {"derWrite",          (PyCFunction)asymmetric_object_der_write,       METH_VARARGS,  NULL},
  {"publicEncrypt",     (PyCFunction)asymmetric_object_public_encrypt,  METH_VARARGS,  NULL},
  {"privateEncrypt",    (PyCFunction)asymmetric_object_private_encrypt, METH_VARARGS,  NULL},
  {"privateDecrypt",    (PyCFunction)asymmetric_object_private_decrypt, METH_VARARGS,  NULL},
  {"publicDecrypt",     (PyCFunction)asymmetric_object_public_decrypt,  METH_VARARGS,  NULL},
  {"sign",              (PyCFunction)asymmetric_object_sign,            METH_VARARGS,  NULL},
  {"verify",            (PyCFunction)asymmetric_object_verify,          METH_VARARGS,  NULL},

  {NULL}    /* sentinel */
};

static PyObject *
asymmetric_object_getattr(asymmetric_object *self, char *name)
{
  return Py_FindMethod(asymmetric_object_methods, (PyObject *)self, name);
}

static void
asymmetric_object_dealloc(asymmetric_object *self, char *name)
{
  switch(self->cipher_type) {
  case RSA_CIPHER:
    RSA_free(self->cipher);
    break;
  }
  PyObject_Del(self);
}

static char asymmetrictype__doc__[] =
"<class>\n"
"   <header>\n"
"      <name>Asymmetric</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This class provides access to RSA asymmetric ciphers in OpenSSL.\n"
"         Other ciphers will probably be supported in the future but this is\n"
"         not a priority.\n"
"      </para>\n"
"   </body>\n"
"</class>\n"
;

static PyTypeObject asymmetrictype = {
   PyObject_HEAD_INIT(0)
   0,                                     /*ob_size*/
   "Asymmetric",                          /*tp_name*/
   sizeof(asymmetric_object),             /*tp_basicsize*/
   0,                                     /*tp_itemsize*/
   (destructor)asymmetric_object_dealloc, /*tp_dealloc*/
   (printfunc)0,                          /*tp_print*/
   (getattrfunc)asymmetric_object_getattr,   /*tp_getattr*/
   (setattrfunc)0,                        /*tp_setattr*/
   (cmpfunc)0,                            /*tp_compare*/
   (reprfunc)0,                           /*tp_repr*/
   0,                                     /*tp_as_number*/
   0,                                     /*tp_as_sequence*/
   0,                                     /*tp_as_mapping*/
   (hashfunc)0,                           /*tp_hash*/
   (ternaryfunc)0,                        /*tp_call*/
   (reprfunc)0,                           /*tp_str*/
   0,
   0,
   0,
   0,
   asymmetrictype__doc__                   /* Documentation string */
};
/*========== asymmetric Code ==========*/

/*========== digest Code ==========*/
static digest_object *
digest_object_new(int digest_type)
{
  digest_object *self = NULL;

  if ((self = PyObject_New(digest_object, &digesttype)) == NULL)
    goto error;

  switch(digest_type) {
  case MD5_DIGEST:
    self->digest_type = MD5_DIGEST;
    EVP_DigestInit(&self->digest_ctx, EVP_md5());
    break;
  case SHA_DIGEST:
    self->digest_type = SHA_DIGEST;
    EVP_DigestInit(&self->digest_ctx, EVP_sha());
    break;
  case SHA1_DIGEST:
    self->digest_type = SHA1_DIGEST;
    EVP_DigestInit(&self->digest_ctx, EVP_sha1());
    break;
  case SHA256_DIGEST:
    self->digest_type = SHA256_DIGEST;
    EVP_DigestInit(&self->digest_ctx, EVP_sha256());
    break;
  case SHA384_DIGEST:
    self->digest_type = SHA384_DIGEST;
    EVP_DigestInit(&self->digest_ctx, EVP_sha384());
    break;
  case SHA512_DIGEST:
    self->digest_type = SHA512_DIGEST;
    EVP_DigestInit(&self->digest_ctx, EVP_sha512());
    break;
  default:
    lose("unsupported digest");
  }

  return self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static char digest_object_update__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>Digest</memberof>\n"
"      <name>update</name>\n"
"      <parameter>data</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method updates the internal structures of the\n"
"         <classname>Digest</classname> object with <parameter>data</parameter>.\n"
"         <parameter>data</parameter> should be a string.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
digest_object_update(digest_object *self, PyObject *args)
{
  char *data = NULL;
  int len = 0;

  if (!PyArg_ParseTuple(args, "s#", &data, &len))
    goto error;

  EVP_DigestUpdate(&self->digest_ctx, data, len);

  Py_RETURN_NONE;

 error:

  return NULL;
}

static char digest_object_copy__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>Digest</memberof>\n"
"      <name>copy</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns a copy of the <classname>Digest</classname>\n"
"         object.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
digest_object_copy(digest_object *self, PyObject *args)
{
  digest_object *new = NULL;

  if ((new = PyObject_New(digest_object, &digesttype)) == NULL)
    lose("could not allocate memory");

  new->digest_type = self->digest_type;
  if (!EVP_MD_CTX_copy(&new->digest_ctx, &self->digest_ctx))
    lose("could not copy digest");

  return (PyObject*)new;

 error:

  Py_XDECREF(new);
  return NULL;
}

static char digest_object_digest__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>Digest</memberof>\n"
"      <name>digest</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns the digest of all the data which has been\n"
"         processed.  This function can be called at any time and will not\n"
"         effect the internal structure of the <classname>digest</classname>\n"
"         object.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
digest_object_digest(digest_object *self, PyObject *args)
{
  unsigned char digest_text[EVP_MAX_MD_SIZE];
  void *md_copy = NULL;
  unsigned digest_len = 0;

  if (!PyArg_ParseTuple(args, ""))
    goto error;

  if ((md_copy = malloc(sizeof(EVP_MD_CTX))) == NULL)
    lose("could not allocate memory");

  if (!EVP_MD_CTX_copy(md_copy, &self->digest_ctx))
    lose("could not copy digest");

  EVP_DigestFinal(md_copy, digest_text, &digest_len);

  free(md_copy);

  return Py_BuildValue("s#", digest_text, digest_len);

 error:

  if (md_copy)
    free(md_copy);

  return NULL;
}

static struct PyMethodDef digest_object_methods[] = {
  {"update",           (PyCFunction)digest_object_update,  METH_VARARGS, NULL},
  {"digest",           (PyCFunction)digest_object_digest,  METH_VARARGS, NULL},
  {"copy",             (PyCFunction)digest_object_copy,    METH_VARARGS, NULL},

  {NULL}    /* sentinel */
};

static PyObject *
digest_object_getattr(digest_object *self, char *name)
{
  return Py_FindMethod(digest_object_methods, (PyObject *)self, name);
}

static void
digest_object_dealloc(digest_object *self, char *name)
{
  EVP_MD_CTX_cleanup(&self->digest_ctx);
  PyObject_Del(self);
}

static char digesttype__doc__[] =
"<class>\n"
"   <header>\n"
"      <name>Digest</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This class provides access to the digest functionality of OpenSSL.\n"
"         It emulates the digest modules in the Python Standard Library but\n"
"         does not currently support the <function>hexdigest</function>\n"
"         function.\n"
"      </para>\n"
"      <example>\n"
"         <title><classname>digest</classname> class usage</title>\n"
"         <programlisting>\n"
"      plain_text = 'Hello World!'\n"
"      sha1 = POW.Digest(POW.SHA1_DIGEST)\n"
"      sha1.update(plain_text)\n"
"      print '\tPlain text: Hello World! =>', sha1.digest()\n"
"         </programlisting>\n"
"      </example>\n"
"   </body>\n"
"</class>\n"
;

static PyTypeObject digesttype = {
  PyObject_HEAD_INIT(0)
  0,                                  /*ob_size*/
  "Digest",                           /*tp_name*/
  sizeof(digest_object),              /*tp_basicsize*/
  0,                                  /*tp_itemsize*/
  (destructor)digest_object_dealloc,  /*tp_dealloc*/
  (printfunc)0,                       /*tp_print*/
  (getattrfunc)digest_object_getattr, /*tp_getattr*/
  (setattrfunc)0,                     /*tp_setattr*/
  (cmpfunc)0,                         /*tp_compare*/
  (reprfunc)0,                        /*tp_repr*/
  0,                                  /*tp_as_number*/
  0,                                  /*tp_as_sequence*/
  0,                                  /*tp_as_mapping*/
  (hashfunc)0,                        /*tp_hash*/
  (ternaryfunc)0,                     /*tp_call*/
  (reprfunc)0,                        /*tp_str*/
  0,
  0,
  0,
  0,
  digesttype__doc__                   /* Documentation string */
};
/*========== digest Code ==========*/

/*========== CMS code ==========*/
static cms_object *
CMS_object_new(void)
{
  cms_object *self;

  if ((self = PyObject_New(cms_object, &cmstype)) == NULL)
    goto error;

  self->cms = NULL;
  return self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static cms_object *
CMS_object_pem_read(BIO *in)
{
  cms_object *self;

  if ((self = PyObject_New(cms_object, &cmstype)) == NULL)
    goto error;

  if ((self->cms = PEM_read_bio_CMS(in, NULL, NULL, NULL)) == NULL)
    lose("could not load PEM encoded CMS message");

  return self;

 error:

  Py_XDECREF(self);
  return NULL;
}

static cms_object *
CMS_object_der_read(char *src, int len)
{
  cms_object *self;
  BIO *bio = NULL;

  if ((self = PyObject_New(cms_object, &cmstype)) == NULL)
    goto error;

  self->cms = CMS_ContentInfo_new();

  if ((bio = BIO_new_mem_buf(src, len)) == NULL)
    goto error;

  if (!d2i_CMS_bio(bio, &self->cms))
    lose("could not load DER encoded CMS message");

  BIO_free(bio);

  return self;

 error:
  BIO_free(bio);
  Py_XDECREF(self);
  return NULL;
}

static PyObject *
CMS_object_write_helper(cms_object *self, PyObject *args, int format)
{
  PyObject *result = NULL;
  BIO *bio = NULL;

  if (!PyArg_ParseTuple(args, ""))
    return NULL;

  bio = BIO_new(BIO_s_mem());

  switch (format) {

  case DER_FORMAT:
    if (!i2d_CMS_bio(bio, self->cms))
      lose("unable to write certificate");
    break;

  case PEM_FORMAT:
    if (!PEM_write_bio_CMS(bio, self->cms))
      lose("unable to write certificate");
    break;

  default:
    lose("internal error, unknown output format");
  }

  result = BIO_to_PyString_helper(bio);

 error:                         /* Fall through */
  BIO_free(bio);
  return result;
}

static char CMS_object_pem_write__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>CMS</memberof>\n"
"      <name>pemWrite</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns a PEM encoded CMS message as a\n"
"         string.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
CMS_object_pem_write(cms_object *self, PyObject *args)
{
  return CMS_object_write_helper(self, args, PEM_FORMAT);
}

static char CMS_object_der_write__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>CMS</memberof>\n"
"      <name>derWrite</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns a DER encoded CMS message as a\n"
"         string.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
CMS_object_der_write(cms_object *self, PyObject *args)
{
  return CMS_object_write_helper(self, args, DER_FORMAT);
}

static char CMS_object_sign__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>CMS</memberof>\n"
"      <name>sign</name>\n"
"      <parameter>signcert</parameter>\n"
"      <parameter>key</parameter>\n"
"      <parameter>data</parameter>\n"
"      <optional>\n"
"        <parameter>certs</parameter>\n"
"        <parameter>crls</parameter>\n"
"        <parameter>eContentType</parameter>\n"
"        <parameter>flags</parameter>\n"
"      </optional>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method signs a message with a private key.\n"
"         Supported flags: CMS_NOCERTS, CMS_NOATTR.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
CMS_object_sign(cms_object *self, PyObject *args)
{
  asymmetric_object *signkey = NULL;
  x509_object *signcert = NULL;
  x509_crl_object *crlobj = NULL;
  PyObject *x509_sequence = Py_None, *crl_sequence = Py_None, *result = NULL;
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
    lose("unsupported key type");

  if ((x509_stack = x509_helper_sequence_to_stack(x509_sequence)) == NULL)
    goto error;

  assert_no_unhandled_openssl_errors();

  if ((pkey = EVP_PKEY_new()) == NULL)
    lose_openssl_error("Could not allocate memory");

  assert_no_unhandled_openssl_errors();

  if (!EVP_PKEY_assign_RSA(pkey, signkey->cipher))
    lose_openssl_error("EVP_PKEY assignment error");

  assert_no_unhandled_openssl_errors();

  if ((bio = BIO_new_mem_buf(buf, len)) == NULL)
    goto error;

  assert_no_unhandled_openssl_errors();

  if (oid && (econtent_type = OBJ_txt2obj(oid, 0)) == NULL)
    lose_openssl_error("Could not parse OID");

  assert_no_unhandled_openssl_errors();

  if ((cms = CMS_sign(NULL, NULL, x509_stack, bio, flags)) == NULL)
    lose_openssl_error("Could not create CMS message");

  assert_no_unhandled_openssl_errors();

  if (econtent_type)
    CMS_set1_eContentType(cms, econtent_type);

  assert_no_unhandled_openssl_errors();

  if (!CMS_add1_signer(cms, signcert->x509, pkey, EVP_sha256(), flags))
    lose_openssl_error("Could not sign CMS message");

  pkey = NULL;                 /* CMS_add1_signer() now owns pkey */

  assert_no_unhandled_openssl_errors();

  if (crl_sequence != Py_None) {

    if (!PyTuple_Check(crl_sequence) && !PyList_Check(crl_sequence))
      lose_type_error("inapropriate type");

    n = PySequence_Size(crl_sequence);

    for (i = 0; i < n; i++) {

      if ((crlobj = (x509_crl_object *) PySequence_GetItem(crl_sequence, i)) == NULL)
        goto error;

      if (!X_X509_crl_Check(crlobj))
        lose_type_error("inappropriate type");

      if (!crlobj->crl)
        lose("CRL object with null crl field!");

      if (!CMS_add1_crl(cms, crlobj->crl))
        lose_openssl_error("Could not add CRL to CMS");

      assert_no_unhandled_openssl_errors();

      Py_XDECREF(crlobj);
      crlobj = NULL;
    }
  }

  if (!CMS_final(cms, bio, NULL, flags))
    lose_openssl_error("Could not finalize CMS signatures");

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

static char CMS_object_verify__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>CMS</memberof>\n"
"      <name>verify</name>\n"
"      <parameter>store</parameter>\n"
"      <optional>\n"
"        <parameter>certs</parameter>\n"
"        <parameter>flags</parameter>\n"
"      </optional>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method verifies a message against a trusted store.\n"
"         The optional certs parameter is a set of certificates to search\n"
"         for the signer's certificate.\n"
"         Supported flags: CMS_NOINTERN, CMS_NOCRL,\n"
"         CMS_NO_SIGNER_CERT_VERIFY, CMS_NO_ATTR_VERIFY,\n"
"         CMS_NO_CONTENT_VERIFY.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
CMS_object_verify(cms_object *self, PyObject *args)
{
  x509_store_object *store = NULL;
  PyObject *result = NULL, *certs_sequence = Py_None;
  STACK_OF(X509) *certs_stack = NULL;
  unsigned flags = 0;
  BIO *bio = NULL;

  if (!PyArg_ParseTuple(args, "O!|OI", &x509_storetype, &store, &certs_sequence, &flags))
    goto error;

  if ((bio = BIO_new(BIO_s_mem())) == NULL)
    goto error;

  assert_no_unhandled_openssl_errors();

  flags &= (CMS_NOINTERN | CMS_NOCRL | CMS_NO_SIGNER_CERT_VERIFY |
            CMS_NO_ATTR_VERIFY | CMS_NO_CONTENT_VERIFY);

  if (certs_sequence != Py_None &&
      (certs_stack = x509_helper_sequence_to_stack(certs_sequence)) == NULL)
    goto error;

  assert_no_unhandled_openssl_errors();

  if (CMS_verify(self->cms, certs_stack, store->store, NULL, bio, flags) <= 0)
    lose_openssl_error("Could not verify CMS message");

  assert_no_unhandled_openssl_errors();

  result = BIO_to_PyString_helper(bio);

 error:                          /* fall through */

  assert_no_unhandled_openssl_errors();

  sk_X509_free(certs_stack);
  BIO_free(bio);

  return result;
}

static char CMS_object_eContentType__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>CMS</memberof>\n"
"      <name>get_eContentType</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns the eContentType of a CMS message.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
CMS_object_eContentType(cms_object *self, PyObject *args)
{
  const ASN1_OBJECT *oid = NULL;
  PyObject *result = NULL;
  char buf[512];

  if (!PyArg_ParseTuple(args, ""))
    return NULL;

  if ((oid = CMS_get0_eContentType(self->cms)) == NULL)
    lose_openssl_error("Could not extract eContentType from CMS message");

  if (OBJ_obj2txt(buf, sizeof(buf), oid, 1) <= 0)
    lose("could not translate OID");

  result = Py_BuildValue("s", buf);

 error:

  assert_no_unhandled_openssl_errors();

  return result;
}

static char CMS_object_signingTime__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>CMS</memberof>\n"
"      <name>get_signingTime</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns the signingTime of a CMS message.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
CMS_object_signingTime(cms_object *self, PyObject *args)
{
  PyObject *result = NULL;
  STACK_OF(CMS_SignerInfo) *sis = NULL;
  CMS_SignerInfo *si = NULL;
  X509_ATTRIBUTE *xa = NULL;
  ASN1_TYPE *so = NULL;
  int i;

  if (!PyArg_ParseTuple(args, ""))
    return NULL;

  if ((sis = CMS_get0_SignerInfos(self->cms)) == NULL)
    lose("Could not extract signerInfos from CMS message[1]");

  if (sk_CMS_SignerInfo_num(sis) != 1)
    lose("Could not extract signerInfos from CMS message[2]");

  si = sk_CMS_SignerInfo_value(sis, 0);

  if ((i = CMS_signed_get_attr_by_NID(si, NID_pkcs9_signingTime, -1)) < 0)
    lose("Could not extract signerInfos from CMS message[3]");

  if ((xa = CMS_signed_get_attr(si, i)) == NULL)
    lose("Could not extract signerInfos from CMS message[4]");

  if (xa->single)
    lose("Could not extract signerInfos from CMS message[5]");

  if (sk_ASN1_TYPE_num(xa->value.set) != 1)
    lose("Could not extract signerInfos from CMS message[6]");

  if ((so = sk_ASN1_TYPE_value(xa->value.set, 0)) == NULL)
    lose("Could not extract signerInfos from CMS message[7]");

  switch (so->type) {
  case V_ASN1_UTCTIME:
    result = ASN1_TIME_to_Python(so->value.utctime);
    break;
  case V_ASN1_GENERALIZEDTIME:
    result = ASN1_TIME_to_Python(so->value.generalizedtime);
    break;
  default:
    lose("Could not extract signerInfos from CMS message[8]");
  }

 error:

  assert_no_unhandled_openssl_errors();

  return result;
}

static char CMS_object_pprint__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>CMS</memberof>\n"
"      <name>pprint</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns a formatted string showing the information\n"
"         held in the certificate.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
CMS_object_pprint(cms_object *self, PyObject *args)
{
  BIO *bio = NULL;
  PyObject *result = NULL;

  if (!PyArg_ParseTuple(args, ""))
    goto error;

  bio = BIO_new(BIO_s_mem());

  if (!CMS_ContentInfo_print_ctx(bio, self->cms, 0, NULL))
    lose("unable to pprint CMS");

  result = BIO_to_PyString_helper(bio);

 error:                          /* fall through */

  assert_no_unhandled_openssl_errors();

  BIO_free(bio);

  return result;
}


static PyObject *
cms_object_helper_get_cert(void *cert)
{
  x509_object *obj = PyObject_New(x509_object, &x509type);

  if (obj)
    obj->x509 = cert;

  return (PyObject *) obj;
}

static char CMS_object_certs__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>CMS</memberof>\n"
"      <name>certs</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns any certs embedded in a CMS message.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
CMS_object_certs(cms_object *self, PyObject *args)
{
  STACK_OF(X509) *certs = NULL;
  PyObject *result = NULL;

  if (!PyArg_ParseTuple(args, ""))
    goto error;

  if ((certs = CMS_get1_certs(self->cms)) != NULL)
    result = stack_to_tuple_helper(CHECKED_PTR_OF(STACK_OF(X509), certs),
                                   cms_object_helper_get_cert);
  else if (!ERR_peek_error())
    result = Py_BuildValue("()");
  else
    lose_openssl_error("Could not extract certs from CMS message");

 error:                          /* fall through */
  sk_X509_pop_free(certs, X509_free);
  return result;
}

static PyObject *
cms_object_helper_get_crl(void *crl)
{
  x509_crl_object *obj = PyObject_New(x509_crl_object, &x509_crltype);

  if (obj)
    obj->crl = crl;

  return (PyObject *) obj;
}

static char CMS_object_crls__doc__[] =
"<method>\n"
"   <header>\n"
"      <memberof>CMS</memberof>\n"
"      <name>crls</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This method returns any CRLs embedded in a CMS message.\n"
"      </para>\n"
"   </body>\n"
"</method>\n"
;

static PyObject *
CMS_object_crls(cms_object *self, PyObject *args)
{
  STACK_OF(X509_CRL) *crls = NULL;
  PyObject *result = NULL;

  if (!PyArg_ParseTuple(args, ""))
    goto error;

  if ((crls = CMS_get1_crls(self->cms)) != NULL)
    result = stack_to_tuple_helper(CHECKED_PTR_OF(STACK_OF(X509_CRL), crls),
                                   cms_object_helper_get_crl);
  else if (!ERR_peek_error())
    result = Py_BuildValue("()");
  else
    lose_openssl_error("Could not extract CRLs from CMS message");

 error:                          /* fall through */
  sk_X509_CRL_pop_free(crls, X509_CRL_free);
  return result;
}

static struct PyMethodDef CMS_object_methods[] = {
  {"pemWrite",     (PyCFunction)CMS_object_pem_write,    METH_VARARGS,  NULL},
  {"derWrite",     (PyCFunction)CMS_object_der_write,    METH_VARARGS,  NULL},
  {"sign",         (PyCFunction)CMS_object_sign,         METH_VARARGS,  NULL},
  {"verify",       (PyCFunction)CMS_object_verify,       METH_VARARGS,  NULL},
  {"eContentType", (PyCFunction)CMS_object_eContentType, METH_VARARGS,  NULL},
  {"signingTime",  (PyCFunction)CMS_object_signingTime,  METH_VARARGS,  NULL},
  {"pprint",       (PyCFunction)CMS_object_pprint,       METH_VARARGS,  NULL},
  {"certs",        (PyCFunction)CMS_object_certs,        METH_VARARGS,  NULL},
  {"crls",         (PyCFunction)CMS_object_crls,         METH_VARARGS,  NULL},

  {NULL}    /* sentinel */
};

static PyObject *
CMS_object_getattr(cms_object *self, char *name)
{
  return Py_FindMethod(CMS_object_methods, (PyObject *)self, name);
}

static void
CMS_object_dealloc(cms_object *self, char *name)
{
  CMS_ContentInfo_free(self->cms);
  PyObject_Del(self);
}

static char cmstype__doc__[] =
"<class>\n"
"   <header>\n"
"      <name>CMS</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This class provides basic access OpenSSL's CMS functionality.\n"
"      </para>\n"
"   </body>\n"
"</class>\n"
;

static PyTypeObject cmstype = {
   PyObject_HEAD_INIT(0)
   0,                                  /*ob_size*/
   "CMS",                              /*tp_name*/
   sizeof(cms_object),                 /*tp_basicsize*/
   0,                                  /*tp_itemsize*/
   (destructor)CMS_object_dealloc,     /*tp_dealloc*/
   (printfunc)0,                       /*tp_print*/
   (getattrfunc)CMS_object_getattr,    /*tp_getattr*/
   (setattrfunc)0,                     /*tp_setattr*/
   (cmpfunc)0,                         /*tp_compare*/
   (reprfunc)0,                        /*tp_repr*/
   0,                                  /*tp_as_number*/
   0,                                  /*tp_as_sequence*/
   0,                                  /*tp_as_mapping*/
   (hashfunc)0,                        /*tp_hash*/
   (ternaryfunc)0,                     /*tp_call*/
   (reprfunc)0,                        /*tp_str*/
   0,
   0,
   0,
   0,
   cmstype__doc__                    /* Documentation string */
};
/*========== CMS Code ==========*/

/*========== module functions ==========*/

static char pow_module_new_x509__doc__[] =
"<constructor>\n"
"   <header>\n"
"      <memberof>X509</memberof>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This constructor creates a skeletal X509 certificate object.\n"
"         It won't be any use at all until several structures\n"
"         have been created using it's member functions.\n"
"      </para>\n"
"   </body>\n"
"</constructor>\n"
;

static PyObject *
pow_module_new_x509 (PyObject *self, PyObject *args)
{
  x509_object *x509 = NULL;

  if (!PyArg_ParseTuple(args, ""))
    goto error;

  if ((x509 = X509_object_new()) == NULL)
    lose("could not create new x509 object");

  return (PyObject*)x509;

 error:

  return NULL;
}

static char pow_module_new_asymmetric__doc__[] =
"<constructor>\n"
"   <header>\n"
"      <memberof>Asymmetric</memberof>\n"
"      <parameter>ciphertype = RSA_CIPHER</parameter>\n"
"      <parameter>keylength = 1024</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This constructor builds a new cipher object.  Only RSA ciphers\n"
"         are currently support, so the first argument should always be\n"
"         <constant>RSA_CIPHER</constant>.  The second argument,\n"
"         <parameter>keylength</parameter>,\n"
"         is normally 512, 768, 1024 or 2048.  Key lengths as short as 512\n"
"         bits are generally considered weak, and can be cracked by\n"
"         determined attackers without tremendous expense.\n"
"      </para>\n"
"      <example>\n"
"         <title><classname>asymmetric</classname> class usage</title>\n"
"         <programlisting>\n"
"      privateFile = open('test/private.key', 'w')\n"
"      publicFile = open('test/public.key', 'w')\n"
"\n"
"      passphrase = 'my silly passphrase'\n"
"      md5 = POW.Digest(POW.MD5_DIGEST)\n"
"      md5.update(passphrase)\n"
"      password = md5.digest()\n"
"\n"
"      rsa = POW.Asymmetric(POW.RSA_CIPHER, 1024)\n"
"      privateFile.write(rsa.pemWrite(\n"
"               POW.RSA_PRIVATE_KEY, POW.DES_EDE3_CFB, password))\n"
"      publicFile.write(rsa.pemWrite(POW.RSA_PUBLIC_KEY))\n"
"\n"
"      privateFile.close()\n"
"      publicFile.close()\n"
"         </programlisting>\n"
"      </example>\n"
"   </body>\n"
"</constructor>\n"
;

static PyObject *
pow_module_new_asymmetric (PyObject *self, PyObject *args)
{
  int cipher_type = RSA_CIPHER, key_size = 1024;

  if (!PyArg_ParseTuple(args, "|ii", &cipher_type, &key_size))
    goto error;

  return (PyObject*) asymmetric_object_new(cipher_type, key_size);

 error:

  return NULL;
}

static char pow_module_new_digest__doc__[] =
"<constructor>\n"
"   <header>\n"
"      <memberof>Digest</memberof>\n"
"      <parameter>type</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This constructor creates a new <classname>Digest</classname>\n"
"         object.  The parameter <parameter>type</parameter> specifies what kind\n"
"         of digest to create and should be one of the following:\n"
"      </para>\n"
"      <simplelist>\n"
"         <member><constant>MD5_DIGEST</constant></member>\n"
"         <member><constant>SHA_DIGEST</constant></member>\n"
"         <member><constant>SHA1_DIGEST</constant></member>\n"
"         <member><constant>SHA256_DIGEST</constant></member>\n"
"         <member><constant>SHA384_DIGEST</constant></member>\n"
"         <member><constant>SHA512_DIGEST</constant></member>\n"
"      </simplelist>\n"
"   </body>\n"
"</constructor>\n"
;

static PyObject *
pow_module_new_digest (PyObject *self, PyObject *args)
{
  int digest_type = 0;

  if (!PyArg_ParseTuple(args, "i", &digest_type))
    goto error;

  return (PyObject*) digest_object_new(digest_type);

 error:

  return NULL;
}

static char pow_module_new_hmac__doc__[] =
"<constructor>\n"
"   <header>\n"
"      <memberof>Hmac</memberof>\n"
"      <parameter>type</parameter>\n"
"      <parameter>key</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This constructor creates a new <classname>Hmac</classname>\n"
"         object.  The parameter <parameter>key</parameter> should be a\n"
"         string and <parameter>type</parameter> should be one of the following:\n"
"      </para>\n"
"      <simplelist>\n"
"         <member><constant>MD5_DIGEST</constant></member>\n"
"         <member><constant>SHA_DIGEST</constant></member>\n"
"         <member><constant>SHA1_DIGEST</constant></member>\n"
"         <member><constant>SHA256_DIGEST</constant></member>\n"
"         <member><constant>SHA384_DIGEST</constant></member>\n"
"         <member><constant>SHA512_DIGEST</constant></member>\n"
"      </simplelist>\n"
"   </body>\n"
"</constructor>\n"
;

static PyObject *
pow_module_new_hmac (PyObject *self, PyObject *args)
{
  int digest_type = 0, key_len = 0;
  char *key = NULL;

  if (!PyArg_ParseTuple(args, "is#", &digest_type, &key, &key_len))
    goto error;

  return (PyObject*) hmac_object_new(digest_type, key, key_len);

 error:

  return NULL;
}

static char pow_module_new_cms__doc__[] =
"<constructor>\n"
"   <header>\n"
"      <memberof>CMS</memberof>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This constructor creates a skeletal CMS object.\n"
"      </para>\n"
"   </body>\n"
"</constructor>\n"
;

static PyObject *
pow_module_new_cms (PyObject *self, PyObject *args)
{
  cms_object *cms = NULL;

  if (!PyArg_ParseTuple(args, ""))
    goto error;

  if ((cms = CMS_object_new()) == NULL)
    lose("could not create new CMS object");

  return (PyObject*)cms;

 error:

  return NULL;
}

static char pow_module_pem_read__doc__[] =
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
    lose("unable to create new BIO");

  switch(object_type) {
  case RSA_PRIVATE_KEY:
    obj = (PyObject*)asymmetric_object_pem_read(object_type, in, pass);
    break;
  case RSA_PUBLIC_KEY:
    obj = (PyObject*)asymmetric_object_pem_read(object_type, in, pass);
    break;
  case X509_CERTIFICATE:
    obj = (PyObject*)X509_object_pem_read(in);
    break;
  case X_X509_CRL:
    obj = (PyObject*)x509_crl_object_pem_read(in);
    break;
  case CMS_MESSAGE:
    obj = (PyObject*)CMS_object_pem_read(in);
    break;
  default:
    lose("unknown pem encoding");
  }

  BIO_free(in);

  if (obj)
    return obj;

 error:

  return NULL;
}


static char pow_module_der_read__doc__[] =
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
    obj = (PyObject*) asymmetric_object_der_read(object_type, src, len);
    break;
  case RSA_PUBLIC_KEY:
    obj = (PyObject*) asymmetric_object_der_read(object_type, src, len);
    break;
  case X509_CERTIFICATE:
    obj = (PyObject*)X509_object_der_read(src, len);
    break;
  case X_X509_CRL:
    obj = (PyObject*)x509_crl_object_der_read(src, len);
    break;
  case CMS_MESSAGE:
    obj = (PyObject*)CMS_object_der_read((char *) src, len);
    break;
  default:
    lose("unknown der encoding");
  }

  if (obj)
    return obj;

 error:

  return NULL;
}

static char pow_module_new_x509_store__doc__[] =
"<constructor>\n"
"   <header>\n"
"      <memberof>X509Store</memberof>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This constructor takes no arguments.  The\n"
"         <classname>X509Store</classname> returned cannot be used for\n"
"         verifying certificates until at least one trusted certificate has been\n"
"         added.\n"
"      </para>\n"
"   </body>\n"
"</constructor>\n"
;

static PyObject *
pow_module_new_x509_store (PyObject *self, PyObject *args)
{
  if (!PyArg_ParseTuple(args, ""))
    goto error;

  return (PyObject *) x509_store_object_new();

 error:

  return NULL;
}

static char pow_module_new_x509_crl__doc__[] =
"<constructor>\n"
"   <header>\n"
"      <memberof>x509_crl</memberof>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This constructor builds an empty CRL.\n"
"      </para>\n"
"   </body>\n"
"</constructor>\n"
;

static PyObject *
pow_module_new_x509_crl (PyObject *self, PyObject *args)
{
  if (!PyArg_ParseTuple(args, ""))
    goto error;

  return (PyObject *) x509_crl_object_new();

 error:

  return NULL;
}

static char pow_module_new_x509_revoked__doc__[] =
"<constructor>\n"
"   <header>\n"
"      <memberof>X509Revoked</memberof>\n"
"      <parameter>serial</parameter>\n"
"      <parameter>date</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This constructor builds a X509 Revoked structure.  <parameter>serial</parameter>\n"
"         should be an integer and <parameter>date</parameter> should be and\n"
"         UTCTime string.\n"
"      </para>\n"
"   </body>\n"
"</constructor>\n"
;

static PyObject *
pow_module_new_x509_revoked (PyObject *self, PyObject *args)
{
  int serial = -1;
  char *date = NULL;
  x509_revoked_object *revoke = NULL;

  if (!PyArg_ParseTuple(args, "|is", &serial, &date))
    goto error;

  revoke = x509_revoked_object_new();
  if (serial != -1 && !ASN1_INTEGER_set(revoke->revoked->serialNumber, serial))
    lose("unable to set serial number");

  if (date != NULL && !python_ASN1_TIME_set_string(revoke->revoked->revocationDate, date))
    lose_type_error("Could not set revocationDate");

  return (PyObject*) revoke;

 error:

  return NULL;
}

static char pow_module_add_object__doc__[] =
"<modulefunction>\n"
"   <header>\n"
"      <name>addObject</name>\n"
"      <parameter>oid</parameter>\n"
"      <parameter>shortName</parameter>\n"
"      <parameter>longName</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This function can be used to dynamically add new objects to\n"
"         OpenSSL.  The <parameter>oid</parameter> should be a string of space separated numbers\n"
"         and <parameter>shortName</parameter> and\n"
"         <parameter>longName</parameter> are the names of the object, ie\n"
"         'cn' and 'commonName'.\n"
"      </para>\n"
"   </body>\n"
"</modulefunction>\n"
;

static PyObject *
pow_module_add_object(PyObject *self, PyObject *args)
{
  char *oid = NULL, *sn = NULL, *ln = NULL;

  if (!PyArg_ParseTuple(args, "sss", &oid, &sn, &ln))
    goto error;

  if (!OBJ_create(oid, sn, ln))
    lose("unable to add object");

  Py_RETURN_NONE;

 error:

  return NULL;
}

static char pow_module_get_error__doc__[] =
"<modulefunction>\n"
"   <header>\n"
"      <name>getError</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         Pops an error off the global error stack and returns it as a string.\n"
"         Returns None if the global error stack is empty.\n"
"      </para>\n"
"   </body>\n"
"</modulefunction>\n"
;

static PyObject *
pow_module_get_error(PyObject *self, PyObject *args)
{
  unsigned long error;
  char buf[256];

  if (!PyArg_ParseTuple(args, ""))
    goto error;

  error = ERR_get_error();

  if (!error)
    Py_RETURN_NONE;

  ERR_error_string_n(error, buf, sizeof(buf));

  return Py_BuildValue("s", buf);

 error:

  return NULL;
}

static char pow_module_clear_error__doc__[] =
"<modulefunction>\n"
"   <header>\n"
"      <name>clearError</name>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         Removes all errors from the global error stack.\n"
"      </para>\n"
"   </body>\n"
"</modulefunction>\n"
;

static PyObject *
pow_module_clear_error(PyObject *self, PyObject *args)
{
  if (!PyArg_ParseTuple(args, ""))
    goto error;

  ERR_clear_error();

  Py_RETURN_NONE;

 error:

  return NULL;
}

static char pow_module_seed__doc__[] =
"<modulefunction>\n"
"   <header>\n"
"      <name>seed</name>\n"
"      <parameter>data</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         The <function>seed</function> function adds data to OpenSSLs PRNG\n"
"         state.  It is often said the hardest part of cryptography is\n"
"         getting good random data, after all if you don't have good random\n"
"         data, a 1024 bit key is no better than a 512 bit key and neither\n"
"         would provide protection from a targeted brute force attack.\n"
"         The <function>seed</function> and <function>add</function> are very\n"
"         similar, except the entropy of the data is assumed to be equal to\n"
"         the length for <function>seed</function>.  One final point to be aware\n"
"         of, only systems which support /dev/urandom are automatically seeded.\n"
"         If your system does not support /dev/urandom it is your responsibility\n"
"         to seed OpenSSL's PRNG.\n"
"      </para>\n"
"   </body>\n"
"</modulefunction>\n"
;

static PyObject *
pow_module_seed(PyObject *self, PyObject *args)
{
  char *in = NULL;
  int inl = 0;

  if (!PyArg_ParseTuple(args, "s#", &in, &inl))
    goto error;

  RAND_seed(in, inl);

  Py_RETURN_NONE;

 error:

  return NULL;
}

static char pow_module_add__doc__[] =
"<modulefunction>\n"
"   <header>\n"
"      <name>add</name>\n"
"      <parameter>data</parameter>\n"
"      <parameter>entropy</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         The <function>add</function> function adds data to OpenSSLs PRNG\n"
"         state.  <parameter>data</parameter> should be data obtained from a\n"
"         random source and <parameter>entropy</parameter> is an estimation of the number of random\n"
"         bytes in <parameter>data</parameter>.\n"
"      </para>\n"
"   </body>\n"
"</modulefunction>\n"
;

static PyObject *
pow_module_add(PyObject *self, PyObject *args)
{
  char *in = NULL;
  int inl = 0;
  double entropy = 0;

  if (!PyArg_ParseTuple(args, "s#d", &in, &inl, &entropy))
    goto error;

  RAND_add(in, inl, entropy);

  Py_RETURN_NONE;

 error:

  return NULL;
}

static char pow_module_write_random_file__doc__[] =
"<modulefunction>\n"
"   <header>\n"
"      <name>writeRandomFile</name>\n"
"      <parameter>filename</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This function writes the current random state to a file.  Clearly\n"
"         this function should be used in conjunction with\n"
"         <function>readRandomFile</function>.\n"
"      </para>\n"
"   </body>\n"
"</modulefunction>\n"
;

static PyObject *
pow_module_write_random_file(PyObject *self, PyObject *args)
{
  char *file = NULL;

  if (!PyArg_ParseTuple(args, "s", &file))
    goto error;

  if (RAND_write_file(file) == -1)
    lose("could not write random file");

  Py_RETURN_NONE;

 error:

  return NULL;
}

static char pow_module_read_random_file__doc__[] =
"<modulefunction>\n"
"   <header>\n"
"      <name>readRandomFile</name>\n"
"      <parameter>filename</parameter>\n"
"   </header>\n"
"   <body>\n"
"      <para>\n"
"         This function reads a previously saved random state.  It can be very\n"
"         useful to improve the quality of random data used by an application.\n"
"         The random data should be added to, using the\n"
"         <function>add</function> function, with data from other\n"
"         suitable random sources.\n"
"      </para>\n"
"   </body>\n"
"</modulefunction>\n"
;

static PyObject *
pow_module_read_random_file(PyObject *self, PyObject *args)
{
  char *file = NULL;
  int len = -1;

  if (!PyArg_ParseTuple(args, "s|i", &file, &len))
    goto error;

  if (!RAND_load_file(file, len))
    lose("could not load random file");

  Py_RETURN_NONE;

 error:

  return NULL;
}

static struct PyMethodDef pow_module_methods[] = {
  {"X509",              (PyCFunction)pow_module_new_x509,          METH_VARARGS,  NULL},
  {"pemRead",           (PyCFunction)pow_module_pem_read,          METH_VARARGS,  NULL},
  {"derRead",           (PyCFunction)pow_module_der_read,          METH_VARARGS,  NULL},
  {"Digest",            (PyCFunction)pow_module_new_digest,        METH_VARARGS,  NULL},
  {"CMS",               (PyCFunction)pow_module_new_cms,           METH_VARARGS,  NULL},
  {"Asymmetric",        (PyCFunction)pow_module_new_asymmetric,    METH_VARARGS,  NULL},
  {"X509Store",         (PyCFunction)pow_module_new_x509_store,    METH_VARARGS,  NULL},
  {"X509Crl",           (PyCFunction)pow_module_new_x509_crl,      METH_VARARGS,  NULL},
  {"X509Revoked",       (PyCFunction)pow_module_new_x509_revoked,  METH_VARARGS,  NULL},
  {"getError",          (PyCFunction)pow_module_get_error,         METH_VARARGS,  NULL},
  {"clearError",        (PyCFunction)pow_module_clear_error,       METH_VARARGS,  NULL},
  {"seed",              (PyCFunction)pow_module_seed,              METH_VARARGS,  NULL},
  {"add",               (PyCFunction)pow_module_add,               METH_VARARGS,  NULL},
  {"readRandomFile",    (PyCFunction)pow_module_read_random_file,  METH_VARARGS,  NULL},
  {"writeRandomFile",   (PyCFunction)pow_module_write_random_file, METH_VARARGS,  NULL},
  {"addObject",         (PyCFunction)pow_module_add_object,        METH_VARARGS,  NULL},

  {NULL}     /* sentinel */
};
/*========== module functions ==========*/


/*==========================================================================*/
void
init_POW(void)
{
  PyObject *m;

  x509type.ob_type         = &PyType_Type;
  x509_storetype.ob_type   = &PyType_Type;
  x509_crltype.ob_type     = &PyType_Type;
  x509_revokedtype.ob_type = &PyType_Type;
  asymmetrictype.ob_type   = &PyType_Type;
  digesttype.ob_type       = &PyType_Type;
  cmstype.ob_type          = &PyType_Type;

  m = Py_InitModule3("_POW", pow_module_methods, pow_module__doc__);

#define Define_Exception(__name__, __parent__)                  \
  PyModule_AddObject(m, #__name__, ((__name__##Object)          \
    = PyErr_NewException("POW." #__name__, __parent__, NULL)))

  Define_Exception(Error,                NULL);
  Define_Exception(POWError,             ErrorObject);
  Define_Exception(POWSyscallError,      POWErrorObject);
  Define_Exception(POWErrorSSLError,     POWErrorObject);
  Define_Exception(POWSyscallSSLError,   POWErrorObject);
  Define_Exception(POWUnexpectedEOFError,POWErrorObject);
  Define_Exception(POWOtherError,        POWErrorObject);

#undef Define_Exception

#define Define_Integer_Constant(__name__) \
  PyModule_AddIntConstant(m, #__name__, __name__)

  // object format types
  Define_Integer_Constant(LONGNAME_FORMAT);
  Define_Integer_Constant(SHORTNAME_FORMAT);
  Define_Integer_Constant(OIDNAME_FORMAT);

  // PEM encoded types
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

  // asymmetric ciphers
#ifndef OPENSSL_NO_RSA
  Define_Integer_Constant(RSA_CIPHER);
#endif
#ifndef OPENSSL_NO_DSA
  Define_Integer_Constant(DSA_CIPHER);
#endif
#ifndef OPENSSL_NO_DH
  Define_Integer_Constant(DH_CIPHER);
#endif

  // symmetric ciphers
#ifndef OPENSSL_NO_DES
  Define_Integer_Constant(DES_ECB);
  Define_Integer_Constant(DES_EDE);
  Define_Integer_Constant(DES_EDE3);
  Define_Integer_Constant(DES_CFB);
  Define_Integer_Constant(DES_EDE_CFB);
  Define_Integer_Constant(DES_EDE3_CFB);
  Define_Integer_Constant(DES_OFB);
  Define_Integer_Constant(DES_EDE_OFB);
  Define_Integer_Constant(DES_EDE3_OFB);
  Define_Integer_Constant(DES_CBC);
  Define_Integer_Constant(DES_EDE_CBC);
  Define_Integer_Constant(DES_EDE3_CBC);
  Define_Integer_Constant(DESX_CBC);
#endif
#ifndef OPENSSL_NO_RC4
  Define_Integer_Constant(RC4);
  Define_Integer_Constant(RC4_40);
#endif
#ifndef OPENSSL_NO_IDEA
  Define_Integer_Constant(IDEA_ECB);
  Define_Integer_Constant(IDEA_CFB);
  Define_Integer_Constant(IDEA_OFB);
  Define_Integer_Constant(IDEA_CBC);
#endif
#ifndef OPENSSL_NO_RC2
  Define_Integer_Constant(RC2_ECB);
  Define_Integer_Constant(RC2_CBC);
  Define_Integer_Constant(RC2_40_CBC);
  Define_Integer_Constant(RC2_CFB);
  Define_Integer_Constant(RC2_OFB);
#endif
#ifndef OPENSSL_NO_BF
  Define_Integer_Constant(BF_ECB);
  Define_Integer_Constant(BF_CBC);
  Define_Integer_Constant(BF_CFB);
  Define_Integer_Constant(BF_OFB);
#endif
  Define_Integer_Constant(CAST5_ECB);
  Define_Integer_Constant(CAST5_CBC);
  Define_Integer_Constant(CAST5_CFB);
  Define_Integer_Constant(CAST5_OFB);
#ifndef OPENSSL_NO_RC5
  Define_Integer_Constant(RC5_32_12_16_CBC);
  Define_Integer_Constant(RC5_32_12_16_CFB);
  Define_Integer_Constant(RC5_32_12_16_ECB);
  Define_Integer_Constant(RC5_32_12_16_OFB);
#endif

  // message digests
  Define_Integer_Constant(MD5_DIGEST);
  Define_Integer_Constant(SHA_DIGEST);
  Define_Integer_Constant(SHA1_DIGEST);
  Define_Integer_Constant(SHA256_DIGEST);
  Define_Integer_Constant(SHA384_DIGEST);
  Define_Integer_Constant(SHA512_DIGEST);

  // general name
  Define_Integer_Constant(GEN_OTHERNAME);
  Define_Integer_Constant(GEN_EMAIL);
  Define_Integer_Constant(GEN_DNS);
  Define_Integer_Constant(GEN_X400);
  Define_Integer_Constant(GEN_DIRNAME);
  Define_Integer_Constant(GEN_EDIPARTY);
  Define_Integer_Constant(GEN_URI);
  Define_Integer_Constant(GEN_IPADD);
  Define_Integer_Constant(GEN_RID);

  // CMS flags
  Define_Integer_Constant(CMS_NOCERTS);
  Define_Integer_Constant(CMS_NOATTR);
  Define_Integer_Constant(CMS_NOINTERN);
  Define_Integer_Constant(CMS_NOCRL);
  Define_Integer_Constant(CMS_NO_SIGNER_CERT_VERIFY);
  Define_Integer_Constant(CMS_NO_ATTR_VERIFY);
  Define_Integer_Constant(CMS_NO_CONTENT_VERIFY);

#undef Define_Integer_Constant

  // initialise library
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  OpenSSL_add_all_ciphers();
  OpenSSL_add_all_digests();

  // load error strings
  SSL_load_error_strings();

  if (PyErr_Occurred())
    Py_FatalError("Can't initialize module POW");
}
/*==========================================================================*/

/*
 * Local Variables:
 * indent-tabs-mode: nil
 * End:
 */
