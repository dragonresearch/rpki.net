# $Id$
#
# Copyright (C) 2013--2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2011--2012  Internet Systems Consortium ("ISC")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL AND ISC DISCLAIM ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL DRL OR
# ISC BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
# DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA
# OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
# TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
Common Django ORM field classes.

Many of these are complex ASN.1 DER objects stored as SQL BLOBs, since
the only sane text representation would just be the Base64 encoding of
the DER and thus would add no value.
"""

import logging

from django.db import models

import rpki.x509
import rpki.sundial

logger = logging.getLogger(__name__)


class EnumField(models.PositiveSmallIntegerField):
  """
  An enumeration type that uses strings in Python and small integers
  in SQL.
  """

  description = "An enumeration type"

  __metaclass__ = models.SubfieldBase

  def __init__(self, *args, **kwargs):
    if isinstance(kwargs.get("choices"), (tuple, list)) and isinstance(kwargs["choices"][0], (str, unicode)):
      kwargs["choices"] = tuple(enumerate(kwargs["choices"], 1))
    # Might need something here to handle string-valued default parameter
    models.PositiveSmallIntegerField.__init__(self, *args, **kwargs)
    self.enum_i2s = dict(self.flatchoices)
    self.enum_s2i = dict((v, k) for k, v in self.flatchoices)

  def to_python(self, value):
    return self.enum_i2s.get(value, value)

  def get_prep_value(self, value):
    return self.enum_s2i.get(value, value)


class SundialField(models.DateTimeField):
  """
  A field type for our customized datetime objects.
  """
  __metaclass__ = models.SubfieldBase

  description = "A datetime type using our customized datetime objects"

  def to_python(self, value):
    if isinstance(value, rpki.sundial.pydatetime.datetime):
      return rpki.sundial.datetime.from_datetime(
        models.DateTimeField.to_python(self, value))
    else:
      return value

  def get_prep_value(self, value):
    if isinstance(value, rpki.sundial.datetime):
      return value.to_datetime()
    else:
      return value


class BlobField(models.Field):
  """
  Basic BLOB field, no type conversion, just an opaque byte string.

  "BLOB" = "Binary Large OBject".  Most SQL implementations seem to
  have such a thing, but support appears to predate standardization,
  so they all do it slightly differently and we have to cope.

  In PostgreSQL, BLOBs are called "bytea".

  In MySQL, there are different sizes of BLOBs and one must pick the
  right one to avoid data truncation.  RPKI manifests and CRLs can be
  longer than 65535 octets, so in MySQL the only safe BLOB type for
  general use is "LONGBLOB".

  SQLite...is not like the other children: data types are more like
  guidelines than actual rules.  But "BLOB" works.

  For anything else, we just use "BLOB" and hope for the best.

  NB: This field type predates Django 1.6's BinaryField.  Probably
  this should be retired in favor of BinaryField, but I'd have to
  figure out what that does to field types that derive from this one.
  """

  __metaclass__ = models.SubfieldBase
  description   = "Raw BLOB type without ASN.1 encoding/decoding"

  def __init__(self, *args, **kwargs):
    self.blob_type = kwargs.pop("blob_type", None)
    kwargs["serialize"] = False
    kwargs["blank"] = True
    kwargs["default"] = None
    models.Field.__init__(self, *args, **kwargs)

  def db_type(self, connection):
    if self.blob_type is not None:
      return self.blob_type
    elif connection.settings_dict['ENGINE'] == "django.db.backends.mysql":
      return "LONGBLOB"
    elif connection.settings_dict['ENGINE'] == "django.db.backends.posgresql":
      return "bytea"
    else:
      return "BLOB"


# For reasons which now escape me, I had a few fields in the old
# hand-coded SQL which used MySQL type BINARY(20) to hold SKIs.
# Presumably this was so that I could then use those SKIs in indexes
# and searches, but apparently I never got around to that part.
#
# SKIs probably would be better stored as hex strings anyway, so not
# bothering with a separate binary type model for this.  Deal with
# this if and when it ever becomes an issue.


class DERField(BlobField):
  """
  Field class for DER objects.  These are derived from BLOBs, but with
  automatic translation between ASN.1 and Python types.

  DERField itself is an abstract class, concrete field classes are
  derived from it.
  """

  __metaclass__ = models.SubfieldBase

  def to_python(self, value):
    if value is not None and not isinstance(value, (self.rpki_type, str)):
      logger.warning("Why am I now seeing a %r instead of str or %r in the %r rpki.fields.DERField.to_python() method?",
                     type(value), self.rpki_type, type(self))
    assert value is None or isinstance(value, (self.rpki_type, str))
    if isinstance(value, str):
      return self.rpki_type(DER = value)
    else:
      return value

  def get_prep_value(self, value):
    assert value is None or isinstance(value, (self.rpki_type, str))
    if isinstance(value, self.rpki_type):
      return value.get_DER()
    else:
      return value

class CertificateField(DERField):
  description = "X.509 certificate"
  rpki_type   = rpki.x509.X509

class RSAPrivateKeyField(DERField):
  description = "RSA keypair"
  rpki_type   = rpki.x509.RSA

KeyField = RSAPrivateKeyField

class PublicKeyField(DERField):
  description = "RSA keypair"
  rpki_type   = rpki.x509.PublicKey

class CRLField(DERField):
  description = "Certificate Revocation List"
  rpki_type   = rpki.x509.CRL

class PKCS10Field(DERField):
  description = "PKCS #10 certificate request"
  rpki_type   = rpki.x509.PKCS10

class ManifestField(DERField):
  description = "RPKI Manifest"
  rpki_type   = rpki.x509.SignedManifest

class ROAField(DERField):
  description = "ROA"
  rpki_type   = rpki.x509.ROA

class GhostbusterField(DERField):
  description = "Ghostbuster Record"
  rpki_type   = rpki.x509.Ghostbuster
