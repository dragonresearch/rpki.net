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
import socket

## @var ip_version_choices
# Choice argument for fields implementing IP version numbers.

ip_version_choices = ((4, "IPv4"), (6, "IPv6"))

###

# Field types

class HandleField(django.db.models.CharField):
  """
  A handle field type.
  """

  description = 'A "handle" in one of the RPKI protocols'

  def __init__(self, *args, **kwargs):
    kwargs["max_length"] = 120
    django.db.models.CharField.__init__(self, *args, **kwargs)

class EnumField(django.db.models.PositiveSmallIntegerField):
  """
  An enumeration type that uses strings in Python and small integers
  in SQL.
  """

  description = "An enumeration type"

  __metaclass__ = django.db.models.SubfieldBase

  def __init__(self, *args, **kwargs):
    if isinstance(kwargs["choices"], (tuple, list)) and isinstance(kwargs["choices"][0], str):
      kwargs["choices"] = tuple(enumerate(kwargs["choices"], 1))
    django.db.models.PositiveSmallIntegerField.__init__(self, *args, **kwargs)
    self.enum_i2s = dict(self.flatchoices)
    self.enum_s2i = dict((v, k) for k, v in self.flatchoices)

  def to_python(self, value):
    return self.enum_i2s.get(value, value)

  def get_prep_value(self, value):
    return self.enum_s2i.get(value, value)

class SundialField(django.db.models.DateTimeField):
  """
  A field type for our customized datetime objects.
  """

  description = "A datetime type using our customized datetime objects"

  def to_python(self, value):
    return rpki.sundial.datetime.fromdatetime(
      django.db.models.DateTimeField.to_python(self, value))

  def get_prep_value(self, value):
    if isinstance(value, rpki.sundial.datetime):
      return value.to_sql()
    else:
      return value

###

# Kludge to work around Django 1.2 problem.
#
# This should be a simple abstract base class DERField which we then
# subclass with trivial customization for specific kinds of DER
# objects.  Sadly, subclassing of user defined field classes doesn't
# work in Django 1.2 with the django.db.models.SubfieldBase metaclass,
# so instead we fake it by defining methods externally and defining
# each concrete class as a direct subclass of django.db.models.Field.
#
# The bug has been fixed in Django 1.3, so we can revert this to the
# obvious form once we're ready to require Django 1.3 or later.  The
# fix may have been backported to the 1.2 branch, but trying to test
# for it is likely more work than just working around it.
#
# See https://code.djangoproject.com/ticket/10728 for details.

def DERField_init(self, *args, **kwargs):
  kwargs["serialize"] = False
  kwargs["blank"] = True
  kwargs["default"] = None
  django.db.models.Field.__init__(self, *args, **kwargs)

def DERField_db_type(self, connection):
  if connection.settings_dict['ENGINE'] == "django.db.backends.posgresql":
    return "bytea"
  else:
    return "BLOB"

def DERField_to_python(self, value):
  assert value is None or isinstance(value, (self.rpki_type, str))
  if isinstance(value, str):
    return self.rpki_type(DER = value)
  else:
    return value

def DERField_get_prep_value(self, value):
  assert value is None or isinstance(value, (self.rpki_type, str))
  if isinstance(value, self.rpki_type):
    return value.get_DER()
  else:
    return value

def DERField(cls):
  cls.__init__       = DERField_init
  cls.db_type        = DERField_db_type
  cls.to_python      = DERField_to_python
  cls.get_prep_value = DERField_get_prep_value
  return cls

@DERField
class CertificateField(django.db.models.Field):
  __metaclass__ = django.db.models.SubfieldBase
  description   = "X.509 certificate"
  rpki_type     = rpki.x509.X509

@DERField
class RSAKeyField(django.db.models.Field):
  __metaclass__ = django.db.models.SubfieldBase
  description   = "RSA keypair"
  rpki_type     = rpki.x509.RSA

@DERField
class CRLField(django.db.models.Field):
  __metaclass__ = django.db.models.SubfieldBase
  description   = "Certificate Revocation List"
  rpki_type     = rpki.x509.CRL

@DERField
class PKCS10Field(django.db.models.Field):
  __metaclass__ = django.db.models.SubfieldBase
  description   = "PKCS #10 certificate request"
  rpki_type     = rpki.x509.PKCS10

@DERField
class SignedReferralField(django.db.models.Field):
  __metaclass__ = django.db.models.SubfieldBase
  description   = "CMS signed object containing XML"
  rpki_type     = rpki.x509.SignedReferral

###

# Custom managers

class CertificateManager(django.db.models.Manager):

  def get_or_certify(self, **kwargs):
    """
    Sort of like .get_or_create(), but for models containing
    certificates which need to be generated based on other fields.

    Takes keyword arguments like .get(), checks for existing object.
    If none, creates a new one; if found an existing object but some
    of the non-key fields don't match, updates the existing object.
    Runs certification method for new or updated objects.  Returns a
    tuple consisting of the object and a boolean indicating whether
    anything has changed.
    """

    changed = False

    try:
      obj = self.get(**self._get_or_certify_keys(kwargs))

    except self.model.DoesNotExist:
      obj = self.model(**kwargs)
      changed = True

    else:
      for k in kwargs:
        if getattr(obj, k) != kwargs[k]:
          setattr(obj, k, kwargs[k])
          changed = True

    if changed:
      obj.avow()
      obj.save()

    return obj, changed

  def _get_or_certify_keys(self, kwargs):
    assert len(self.model._meta.unique_together) == 1
    return dict((k, kwargs[k]) for k in self.model._meta.unique_together[0])

class ResourceHolderCAManager(CertificateManager):
  def _get_or_certify_keys(self, kwargs):
    return { "handle" : kwargs["handle"] }

class ServerCAManager(CertificateManager):
  def _get_or_certify_keys(self, kwargs):
    return { "pk" : 1 }

class ResourceHolderEEManager(CertificateManager):
  def _get_or_certify_keys(self, kwargs):
    return { "issuer" : kwargs["issuer"] }

###

class CA(django.db.models.Model):
  certificate = CertificateField()
  private_key = RSAKeyField()
  latest_crl = CRLField()

  # Might want to bring these into line with what rpkid does.  Current
  # variables here were chosen to map easily to what OpenSSL command
  # line tool was keeping on disk.

  next_serial = django.db.models.BigIntegerField(default = 1)
  next_crl_number = django.db.models.BigIntegerField(default = 1)
  last_crl_update = SundialField()
  next_crl_update = SundialField()

  # These should come from somewhere, but I don't yet know where
  ca_certificate_lifetime = rpki.sundial.timedelta(days = 3652)
  crl_interval = rpki.sundial.timedelta(days = 1)

  class Meta:
    abstract = True

  def avow(self):
    if self.private_key is None:
      self.private_key = rpki.x509.RSA.generate()
    now = rpki.sundial.now()
    notAfter = now + self.ca_certificate_lifetime
    self.certificate = rpki.x509.X509.bpki_self_certify(
      keypair = self.private_key,
      subject_name = self.subject_name,
      serial = self.next_serial,
      now = now,
      notAfter = notAfter)
    self.next_serial += 1
    self.generate_crl()
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
    self.next_serial += 1
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
    revoked = [(r.serial, rpki.sundial.datetime.fromdatetime(r.revoked).toASN1tuple(), ())
               for r in self.revocations.all()]
    self.latest_crl = rpki.x509.CRL.generate(
      keypair = self.private_key,
      issuer  = self.certificate,
      serial  = self.next_crl_number,
      thisUpdate = now,
      nextUpdate = now + self.crl_interval,
      revokedCertificates = revoked)
    self.last_crl_update = now
    self.next_crl_update = now + self.crl_interval
    self.next_crl_number += 1

class ServerCA(CA):
  objects = ServerCAManager()

  def __unicode__(self):
    return ""

  @property
  def subject_name(self):
    return rpki.x509.X501DN("%s BPKI server CA" % socket.gethostname())

class ResourceHolderCA(CA):
  handle = HandleField(unique = True)
  objects = ResourceHolderCAManager()

  def __unicode__(self):
    return self.handle

  @property
  def subject_name(self):
    return rpki.x509.X501DN("%s BPKI resource CA" % self.handle)

class Certificate(django.db.models.Model):

  certificate = CertificateField()
  objects = CertificateManager()

  default_interval = rpki.sundial.timedelta(days = 60)

  class Meta:
    abstract = True
    unique_together = ("issuer", "handle")

  def revoke(self):
    self.issuer.revoke(self)

class CrossCertification(Certificate):
  handle = HandleField()
  ta = CertificateField()

  class Meta:
    abstract = True

  def avow(self):
    self.certificate = self.issuer.certify(
      subject_name      = self.ta.getSubject(),
      subject_key       = self.ta.getPublicKey(),
      validity_interval = self.default_interval,
      is_ca             = True,
      pathLenConstraint = 0)

  def __unicode__(self):
    return self.handle

class HostedCA(Certificate):
  issuer = django.db.models.ForeignKey(ServerCA)
  hosted = django.db.models.OneToOneField(ResourceHolderCA, related_name = "hosted_by")

  def avow(self):
    self.certificate = self.issuer.certify(
      subject_name      = self.hosted.certificate.getSubject(),
      subject_key       = self.hosted.certificate.getPublicKey(),
      validity_interval = self.default_interval,
      is_ca             = True,
      pathLenConstraint = 1)

  class Meta:
    unique_together = ("issuer", "hosted")

  def __unicode__(self):
    return self.hosted_ca.handle

class Revocation(django.db.models.Model):
  serial = django.db.models.BigIntegerField()
  revoked = SundialField()
  expires = SundialField()

  class Meta:
    abstract = True
    unique_together = ("issuer", "serial")

class ServerRevocation(Revocation):
  issuer = django.db.models.ForeignKey(ServerCA, related_name = "revocations")

class ResourceHolderRevocation(Revocation):
  issuer = django.db.models.ForeignKey(ResourceHolderCA, related_name = "revocations")
  
class EECertificate(Certificate):
  private_key = RSAKeyField()

  class Meta:
    abstract = True

  def avow(self):
    if self.private_key is None:
      self.private_key = rpki.x509.RSA.generate()
    self.certificate = self.issuer.certify(
      subject_name      = self.subject_name,
      subject_key       = self.private_key.get_RSApublic(),
      validity_interval = self.default_interval,
      is_ca             = False)

class ServerEE(EECertificate):
  issuer = django.db.models.ForeignKey(ServerCA, related_name = "ee_certificates")
  purpose = EnumField(choices = ("rpkid", "pubd", "irdbd", "irbe"))

  class Meta:
    unique_together = ("issuer", "purpose")

  @property
  def subject_name(self):
    return rpki.x509.X501DN("%s BPKI %s EE" % (socket.gethostname(), self.get_purpose_display()))

class Referral(EECertificate):
  issuer = django.db.models.OneToOneField(ResourceHolderCA, related_name = "referral_certificate")
  objects = ResourceHolderEEManager()

  @property
  def subject_name(self):
    return rpki.x509.X501DN("%s BPKI Referral EE" % self.issuer.handle)

class Turtle(django.db.models.Model):
  service_uri = django.db.models.CharField(max_length = 255)

class Rootd(EECertificate, Turtle):
  issuer = django.db.models.OneToOneField(ResourceHolderCA, related_name = "rootd")
  objects = ResourceHolderEEManager()

  @property
  def subject_name(self):
    return rpki.x509.X501DN("%s BPKI rootd EE" % self.issuer.handle)

class BSC(Certificate):
  issuer = django.db.models.ForeignKey(ResourceHolderCA, related_name = "bscs")
  handle = HandleField()
  pkcs10 = PKCS10Field()

  def avow(self):
    self.certificate = self.issuer.certify(
      subject_name      = self.pkcs10.getSubject(),
      subject_key       = self.pkcs10.getPublicKey(),
      validity_interval = self.default_interval,
      is_ca             = False)

  def __unicode__(self):
    return self.handle

class Child(CrossCertification):
  issuer = django.db.models.ForeignKey(ResourceHolderCA, related_name = "children")
  name = django.db.models.TextField(null = True, blank = True)
  valid_until = SundialField()

  # This shouldn't be necessary
  class Meta:
    unique_together = ("issuer", "handle")

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
  version = EnumField(choices = ip_version_choices)

  class Meta:
    unique_together = ("child", "start_ip", "end_ip", "version")

class Parent(CrossCertification, Turtle):
  issuer = django.db.models.ForeignKey(ResourceHolderCA, related_name = "parents")
  parent_handle = HandleField()
  child_handle  = HandleField()
  repository_type = EnumField(choices = ("none", "offer", "referral"))
  referrer = HandleField(null = True, blank = True)
  referral_authorization = SignedReferralField(null = True, blank = True)

  # This shouldn't be necessary
  class Meta:
    unique_together = ("issuer", "handle")

class ROARequest(django.db.models.Model):
  issuer = django.db.models.ForeignKey(ResourceHolderCA, related_name = "roa_requests")
  asn = django.db.models.BigIntegerField()

class ROARequestPrefix(django.db.models.Model):
  roa_request = django.db.models.ForeignKey(ROARequest, related_name = "prefixes")
  version = EnumField(choices = ip_version_choices)
  prefix = django.db.models.CharField(max_length = 40)
  prefixlen = django.db.models.PositiveSmallIntegerField()
  max_prefixlen = django.db.models.PositiveSmallIntegerField()

  class Meta:
    unique_together = ("roa_request", "version", "prefix", "prefixlen", "max_prefixlen")

class GhostbusterRequest(django.db.models.Model):
  issuer = django.db.models.ForeignKey(ResourceHolderCA, related_name = "ghostbuster_requests")
  parent = django.db.models.ForeignKey(Parent, related_name = "ghostbuster_requests", null = True)
  vcard = django.db.models.TextField()

class Repository(CrossCertification):
  issuer = django.db.models.ForeignKey(ResourceHolderCA, related_name = "repositories")
  client_handle = HandleField()
  service_uri = django.db.models.CharField(max_length = 255)
  sia_base = django.db.models.TextField()
  turtle = django.db.models.OneToOneField(Turtle, related_name = "repository")

  # This shouldn't be necessary
  class Meta:
    unique_together = ("issuer", "handle")

class Client(CrossCertification):
  issuer = django.db.models.ForeignKey(ServerCA, related_name = "clients")
  sia_base = django.db.models.TextField()

  # This shouldn't be necessary
  class Meta:
    unique_together = ("issuer", "handle")
