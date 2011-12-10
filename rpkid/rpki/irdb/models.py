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

class BinaryField(django.db.models.Field):
  """
  A raw binary field type for Django models.  Yes, I know this is
  wrong, but breaking out all the ASN.1 isn't practical, and encoding
  binary data as Base64 text doesn't seem much of an improvement.
  """

  description = "Raw binary data"

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
  certificate = BinaryField()
  private_key = BinaryField()
  next_serial = django.db.models.BigIntegerField(default = 1)
  next_crl_number = django.db.models.BigIntegerField(default = 1)
  last_crl_update = django.db.models.DateTimeField()
  next_crl_update = django.db.models.DateTimeField()

  class Meta:
    unique_together = ("identity", "purpose")

class Certificate(django.db.models.Model):
  issuer = django.db.models.ForeignKey(CA)
  certificate = BinaryField()

  # We used to use multi-table inheritance here, but that turns out
  # not to work so well once we started applying uniqueness
  # constraints.  So now we use an abstract base class.
  #
  # This is probably the right approach for data fields, so that we
  # can share custom model methods for things like certificate
  # issuance, but is a bit tricky for foreign keys due to the
  # "related_name" reverse link.  See:
  # https://docs.djangoproject.com/en/dev/topics/db/models/#model-inheritance

  class Meta:
    abstract = True

class Revocation(django.db.models.Model):
  issuer = django.db.models.ForeignKey(CA, related_name = "revocations")
  serial = django.db.models.BigIntegerField()
  revoked = django.db.models.DateTimeField()
  expires = django.db.models.DateTimeField()

  class Meta:
    unique_together = ("issuer", "serial")

class EECertificate(Certificate):
  purpose_map = ChoiceMap("rpkid", "pubd", "irdbd", "irbe", "rootd")
  purpose = django.db.models.PositiveSmallIntegerField(choices = purpose_map.choices)
  private_key = BinaryField()

  class Meta:
    unique_together = ("issuer", "purpose")

class BSC(Certificate):
  handle = HandleField()
  pkcs10 = BinaryField()

  class Meta:
    unique_together = ("issuer", "handle")

class Child(Certificate):
  handle = HandleField()
  name = django.db.models.TextField(null = True, blank = True)
  valid_until = django.db.models.DateTimeField()
  ta = BinaryField()

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
  version_map = ip_version_map
  version = django.db.models.PositiveSmallIntegerField(choices = ip_version_choices)

  class Meta:
    unique_together = ("child", "start_ip", "end_ip", "version")

class Parent(Certificate):
  handle = HandleField()
  parent_handle = HandleField()
  child_handle  = HandleField()
  ta = BinaryField()
  service_uri = django.db.models.CharField(max_length = 255)
  repository_type_map = ChoiceMap("none", "offer", "referral")
  repository_type = django.db.models.PositiveSmallIntegerField(choices = repository_type_map.choices)
  referrer = HandleField(null = True, blank = True)
  referral_authorization = BinaryField(null = True, blank = True)

  class Meta:
    unique_together = ("issuer", "handle")

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

class Repository(Certificate):
  handle = HandleField()
  client_handle = HandleField()
  ta = BinaryField()
  service_uri = django.db.models.CharField(max_length = 255)
  sia_base = django.db.models.TextField()
  parent = django.db.models.OneToOneField(Parent, related_name = "repository")

  class Meta:
    unique_together = ("issuer", "handle")

class Client(Certificate):
  handle = HandleField()
  ta = BinaryField()

  class Meta:
    unique_together = ("issuer", "handle")
