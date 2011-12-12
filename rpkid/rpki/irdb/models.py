"""
IR Database, Django-style.

This is the back-end code's interface to the database.  It's intended
to be usable by command line programs and other scripts, not just
Django GUI code, so be careful.

$Id$

Copyright (C) 2011  Internet Systems Consortium ("ISC")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import django.db.models
import rpki.x509

###

class ChoiceMap(dict):
  """
  Map construct to simplify enumerated types in Django models.
  """

  def __init__(self, *tags):
    dict.__init__(self)
    for i, tag in enumerate(tags, 1):
      self[tag] = i 

  @property
  def choices(self):
    return tuple((y, x) for (x, y) in self.iteritems())

class HandleField(django.db.models.CharField):
  """
  A handle field type.
  """

  def __init__(self, *args, **kwargs):
    kwargs["max_length"] = 120
    django.db.models.CharField.__init__(self, *args, **kwargs)

class DERField(django.db.models.Field):
  """
  A field type for DER objects.

  This is an abstract class, subclasses need to define rpki_type.
  """

  description = "DER object"

  __metaclass__ = django.db.models.SubfieldBase

  def __init__(self, *args, **kwargs):
    kwargs["serialize"] = False
    kwargs["blank"] = True
    django.db.models.Field.__init__(self, *args, **kwargs)

  def db_type(self, connection):
    if connection.settings_dict['ENGINE'] == "django.db.backends.posgresql":
      return "bytea"
    else:
      return "BLOB"

  def to_python(self, value):
    if isinstance(value, self.rpki_type):
      return value
    else:
      assert isinstance(value, str)
      return self.rpki_type(DER = value)

  def get_prep_value(self, value):
    if isinstance(value, self.rpki_type):
      return value.get_DER()
    elif isinstance(value, str):
      return value
    else:
      import sys
      sys.stderr.write(
        "get_prep_value got %r, expected string or %r\n" % (type(value), self.rpki_type))
      assert isinstance(value, (self.rpki_type, str))

class CertificateField(DERField):
  description = "X.509 certificate"
  rpki_type = rpki.x509.X509

class RSAKeyField(DERField):
  description = "RSA keypair"
  rpki_type = rpki.x509.RSA

class PKCS10Field(DERField):
  description = "PKCS #10 certificate request"
  rpki_type = rpki.x509.PKCS10

class SignedReferralField(django.db.models.Field):
  description = "CMS signed object containing XML"

  # This should be another subclass of DERField, but we don't have a
  # suitable subclass of XML_CMS_object yet, in part because the XML
  # schema we'd need to validate is really just a fragment of another
  # schema.  Maybe.  Anyway, subclassing DERField here doesn't work
  # properly yet, so for the moment this is opaque binary data.
  #
  # Fix later.

  def __init__(self, *args, **kwargs):
    kwargs["serialize"] = False
    kwargs["blank"] = True
    django.db.models.Field.__init__(self, *args, **kwargs)

  def db_type(self, connection):
    if connection.settings_dict['ENGINE'] == "django.db.backends.posgresql":
      return "bytea"
    else:
      return "BLOB"

## @var ip_version_map
# Custom choice map for IP version enumerations, so we can use the
# obvious numeric values in the database, which is a bit easier on
# anybody reading the raw SQL.
#
ip_version_map = { "IPv4" : 4, "IPv6" : 6 }

## @var ip_version_choices
# Choice argument for fields implementing IP version numbers.
#
ip_version_choices = tuple((y, x) for (x, y) in ip_version_map.iteritems())

###

class Identity(django.db.models.Model):
  handle = HandleField(unique = True)

class CA(django.db.models.Model):
  identity = django.db.models.ForeignKey(Identity, related_name = "bpki_certificates")
  purpose_map = ChoiceMap("resources", "servers")
  purpose = django.db.models.PositiveSmallIntegerField(choices = purpose_map.choices)
  next_serial = django.db.models.BigIntegerField(default = 1)
  next_crl_number = django.db.models.BigIntegerField(default = 1)
  last_crl_update = django.db.models.DateTimeField()
  next_crl_update = django.db.models.DateTimeField()

  class Meta:
    unique_together = ("identity", "purpose")

class Certificate(django.db.models.Model):

  certificate = CertificateField()

  class Meta:
    abstract = True

  def generate_certificate(self):

    # This is sort of vaguely the right idea, but most of it probably
    # ought to be a method of the CA, not the object being certified,
    # and the rest doesn't yet cover all the different kinds of
    # certificates we need to support.

    # Perhaps something where each specialized class has its own
    # generate_certificate() method which is mostly just a wrapper for
    # a call to the CA object with the right parameters to get the CA
    # to issue the certificate.  Seems about right.  Not awake enough
    # to write it now.

    # This doesn't handle self-certification yet either.
    # Self-certification may be different enough that we want to move
    # the certificate and keypair back to the CA object, since we have
    # to special-case it no matter what we do.

    cacert = self.issuer.keyed_certificates.filter(purpose = KeyedCertificate.purpose_map["ca"])
    subject_name, subject_key = self.get_certificate_subject()
    cer = cacert.certificate
    key = cacert.private_key
    
    result = cer.bpki_certify(
      keypair = key,
      subject_name = subject_name,
      subject_key = subject_key,
      serial = ca.next_serial,
      
      # This needs to be configurable
      notAfter = rpki.sundial.now() + rpki.sundial.timedelta(days = 60),

      # This is (at least) per-class, not universal
      pathLenConstraint = 0,

      # This is per-class too
      is_ca = True)

    self.ca.next_serial += 1

    self.certificate = result



class CrossCertification(Certificate):
  handle = HandleField()
  ta = CertificateField()

  class Meta:
    abstract = True
    unique_together = ("issuer", "handle")

  def get_certificate_subject(self):
    return self.certificate.getSubject(), self.certificate.getPublicKey()

class Revocation(django.db.models.Model):
  issuer = django.db.models.ForeignKey(CA, related_name = "revocations")
  serial = django.db.models.BigIntegerField()
  revoked = django.db.models.DateTimeField()
  expires = django.db.models.DateTimeField()

  class Meta:
    unique_together = ("issuer", "serial")

class KeyedCertificate(Certificate):
  issuer = django.db.models.ForeignKey(CA, related_name = "keyed_certificates")
  purpose_map = ChoiceMap("ca", "rpkid", "pubd", "irdbd", "irbe", "rootd")
  purpose = django.db.models.PositiveSmallIntegerField(choices = purpose_map.choices)
  private_key = RSAKeyField()

  class Meta:
    unique_together = ("issuer", "purpose")

class BSC(Certificate):
  issuer = django.db.models.ForeignKey(CA, related_name = "bscs")
  handle = HandleField()
  pkcs10 = PKCS10Field()

  class Meta:
    unique_together = ("issuer", "handle")

class Child(CrossCertification):
  issuer = django.db.models.ForeignKey(CA, related_name = "children")
  name = django.db.models.TextField(null = True, blank = True)
  valid_until = django.db.models.DateTimeField()

class ChildASN(django.db.models.Model):
  child = django.db.models.ForeignKey(Child, related_name = "asns")
  start_as = django.db.models.BigIntegerField()
  end_as = django.db.models.BigIntegerField()

  class Meta:
    unique_together = ("child", "start_as", "end_as")

class ChildNet(django.db.models.Model):
  child = django.db.models.ForeignKey(Child, related_name = "address_ranges")
  start_ip = django.db.models.CharField(max_length = 40)
  end_ip   = django.db.models.CharField(max_length = 40)
  version_map = ip_version_map
  version = django.db.models.PositiveSmallIntegerField(choices = ip_version_choices)

  class Meta:
    unique_together = ("child", "start_ip", "end_ip", "version")

class Parent(CrossCertification):
  issuer = django.db.models.ForeignKey(CA, related_name = "parents")
  parent_handle = HandleField()
  child_handle  = HandleField()
  service_uri = django.db.models.CharField(max_length = 255)
  repository_type_map = ChoiceMap("none", "offer", "referral")
  repository_type = django.db.models.PositiveSmallIntegerField(choices = repository_type_map.choices)
  referrer = HandleField(null = True, blank = True)
  referral_authorization = SignedReferralField(null = True, blank = True)

class ROARequest(django.db.models.Model):
  identity = django.db.models.ForeignKey(Identity, related_name = "roa_requests")
  asn = django.db.models.BigIntegerField()

class ROARequestPrefix(django.db.models.Model):
  roa_request = django.db.models.ForeignKey(ROARequest, related_name = "prefixes")
  version_map = ip_version_map
  version = django.db.models.PositiveSmallIntegerField(choices = ip_version_choices)
  prefix = django.db.models.CharField(max_length = 40)
  prefixlen = django.db.models.PositiveSmallIntegerField()
  max_prefixlen = django.db.models.PositiveSmallIntegerField()

  class Meta:
    unique_together = ("roa_request", "version", "prefix", "prefixlen", "max_prefixlen")

class GhostbusterRequest(django.db.models.Model):
  identity = django.db.models.ForeignKey(Identity, related_name = "ghostbuster_requests")
  parent = django.db.models.ForeignKey(Parent,     related_name = "ghostbuster_requests", null = True)
  vcard = django.db.models.TextField()

class Repository(CrossCertification):
  issuer = django.db.models.ForeignKey(CA, related_name = "repositories")
  client_handle = HandleField()
  service_uri = django.db.models.CharField(max_length = 255)
  sia_base = django.db.models.TextField()
  parent = django.db.models.OneToOneField(Parent, related_name = "repository")

class Client(CrossCertification):
  issuer = django.db.models.ForeignKey(CA, related_name = "clients")
