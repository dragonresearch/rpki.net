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
import rpki.sundial

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


class SundialField(django.db.models.DateTimeField):
  """
  A field type for our customized datetime objects.
  """

  def to_python(self, value):
    return rpki.sundial.datetime.fromdatetime(
      django.db.models.DateTimeField.to_python(self, value))


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
    if value is None or isinstance(value, self.rpki_type):
      return value
    else:
      assert isinstance(value, str)
      return self.rpki_type(DER = value)

  def get_prep_value(self, value):
    if isinstance(value, self.rpki_type):
      return value.get_DER()
    elif value is None or isinstance(value, str):
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

class CRLField(DERField):
  description = "Certificate Revocation List"
  rpki_type = rpki.x509.CRL

class PKCS10Field(DERField):
  description = "PKCS #10 certificate request"
  rpki_type = rpki.x509.PKCS10

class SignedReferral(rpki.x509.XML_CMS_object):
  encoding = "us-ascii"
  schema = rpki.relaxng.myrpki
  saxify = staticmethod(lambda x: x)

class SignedReferralField(DERField):
  description = "CMS signed object containing XML"
  rpki_type = SignedReferral

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
  certificate = CertificateField()
  private_key = RSAKeyField()
  latest_crl = CRLField()

  # Might want to bring these into line with what rpkid does.  Current
  # variables here were chosen to map easily to what OpenSSL command
  # line tool was keeping on disk.

  next_serial = django.db.models.BigIntegerField(default = 1)
  next_crl_number = django.db.models.BigIntegerField(default = 1)
  last_crl_update = django.db.models.DateTimeField()
  next_crl_update = django.db.models.DateTimeField()

  class Meta:
    unique_together = ("identity", "purpose")

  # These should come from somewhere, but I don't yet know where
  ca_certificate_lifetime = rpki.sundial.timedelta(days = 3652)
  crl_interval = rpki.sundial.timedelta(days = 1)

  def self_certify(self):
    subject_name = rpki.x509.X501DN("%s BPKI %s CA" % (
      self.identity.handle, self.get_purpose_display()))
    now = rpki.sundial.now()
    notAfter = now + self.ca_certificate_lifetime
    self.certificate = rpki.x509.X509.bpki_self_certify(
      keypair = self.private_key,
      subject_name = subject_name,
      serial = self.next_serial,
      now = now,
      notAfter = notAfter)
    self.serial += 1
    return self.certificate

  def certify(self, subject_name, subject_key, validity_interval, is_ca, pathLenConstraint = None):
    now = rpki.sundial.now()
    notAfter = now + validity_interval
    result = self.certificate.bpki_certify(
      keypair = self.private_key,
      subject_name = subject_name,
      subject_key = subject_key,
      serial = self.next_serial,
      now = now,
      notAfter = notAfter,
      is_ca = is_ca,
      pathLenConstraint = pathLenConstraint)
    self.serial += 1
    return result

  def revoke(self, cert):
    Revocations.objects.create(
      issuer  = self,
      revoked = rpki.sundial.now(),
      serial  = cert.certificate.getSerial(),
      expires = cert.certificate.getNotAfter() + self.crl_interval)
    cert.delete()
    self.generate_crl()

  def generate_crl(self):
    now = rpki.sundial.now()
    self.revocations.filter(expires__lt = now).delete()
    revoked_certificates = [(r.serial, rpki.sundial.datetime.fromdatetime(r.revoked).toASN1tuple(), ())
                            for r in self.revocations]
    self.latest_crl = rpki.x509.CRL.generate(
      keypair = self.private_key,
      issuer  = self.certificate.getSubject(),
      thisUpdate = now,
      nextUpdate = now + self.crl_interval,
      revoked_certificates = revoked_certificates)


class Certificate(django.db.models.Model):
  certificate = CertificateField()

  default_interval = rpki.sundial.timedelta(days = 60)

  class Meta:
    abstract = True

  def revoke(self):
    self.ca.revoke(self)


class CrossCertification(Certificate):
  handle = HandleField()
  ta = CertificateField()

  class Meta:
    abstract = True
    unique_together = ("issuer", "handle")

  def generate_certificate(self):
    self.certificate = self.issuer.certify(
      subject_name = self.ta.getSubject(),
      subject_key  = self.ta.getPublicKey(),
      interval     = self.default_interval,
      is_ca        = True,
      pathLenConstraint = 0)


class Revocation(django.db.models.Model):
  issuer = django.db.models.ForeignKey(CA, related_name = "revocations")
  serial = django.db.models.BigIntegerField()
  revoked = django.db.models.DateTimeField()
  expires = django.db.models.DateTimeField()

  class Meta:
    unique_together = ("issuer", "serial")

class EECertificate(Certificate):
  issuer = django.db.models.ForeignKey(CA, related_name = "ee_certificates")
  purpose_map = ChoiceMap("rpkid", "pubd", "irdbd", "irbe", "rootd")
  purpose = django.db.models.PositiveSmallIntegerField(choices = purpose_map.choices)
  private_key = RSAKeyField()

  class Meta:
    unique_together = ("issuer", "purpose")

  def generate_certificate(self):
    subject_name = rpki.x509.X501DN("%s BPKI %s EE" % (
      self.issuer.identity.handle, self.get_purpose_display()))
    self.certificate = self.issuer.certify(
      subject_name = subject_name,
      subject_key  = self.private_key.getPublicKey(),
      interval     = self.default_interval,
      is_ca        = False)

class BSC(Certificate):
  issuer = django.db.models.ForeignKey(CA, related_name = "bscs")
  handle = HandleField()
  pkcs10 = PKCS10Field()

  class Meta:
    unique_together = ("issuer", "handle")

  def generate_certificate(self):
    self.certificate = self.issuer.certify(
      subject_name = self.pkcs10.getSubject(),
      subject_key  = self.pkcs10.getPublicKey(),
      interval     = self.default_interval,
      is_ca        = False)

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
