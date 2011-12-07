"""
IR Database, Django-style.

This is the back-end code's interface to the database.  It's intended
to be usable by command line programs and other scripts, not just
Django GUI code, so be careful.

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
    return [(y, x) for (x, y) in self.iteritems()]

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

## @var IP_VERSION_MAP
# Choice map for IP version enumerations.

IP_VERSION_MAP = ChoiceMap("IPv4", "IPv6")

###

class Identity(django.db.models.Model):
  handle = HandleField()

class BPKICertificate(django.db.models.Model):
  certificate = BinaryField()
  identity = django.db.models.ForeignKey(Identity, related_name = "bpki_certificates")

class BPKIKey(BPKICertificate):
  purpose_map = ChoiceMap("resource_ta", "server_ta", "rpkid", "pubd", "irdbd", "irbe")
  purpose = django.db.models.PositiveSmallIntegerField(choices = purpose_map.choices)
  private_key = BinaryField()

class BSC(BPKICertificate):
  pkcs10 = BinaryField()

class BPKICRL(django.db.models.Model):
  serial = django.db.models.BigIntegerField()
  thisupdate = django.db.models.DateTimeField()
  nextupdate = django.db.models.DateTimeField()
  issuer = django.db.models.OneToOneField(BPKICertificate, related_name = "crl")

class BPKIRevocation(django.db.models.Model):
  serial = django.db.models.BigIntegerField()
  revoked = django.db.models.DateTimeField()
  expires = django.db.models.DateTimeField()
  crl = django.db.models.ForeignKey(BPKICRL, related_name = "revocations")

class Child(BPKICertificate):
  handle = HandleField()
  name = django.db.models.TextField(blank = True)
  valid_until = django.db.models.DateTimeField()
  bpki_ta = BinaryField()

class ChildASN(django.db.models.Model):
  start_as = django.db.models.BigIntegerField()
  end_as = django.db.models.BigIntegerField()
  child = django.db.models.ForeignKey(Child, related_name = "asns")

class ChildNet(django.db.models.Model):
  child_net_id = django.db.models.BigIntegerField(unique = True)
  start_ip = django.db.models.CharField(max_length = 40)
  end_ip   = django.db.models.CharField(max_length = 40)
  version_map = IP_VERSION_MAP
  version = django.db.models.PositiveSmallIntegerField(choices = version_map.choices)
  child = django.db.models.ForeignKey(Child, related_name = "address_ranges")

class Parent(BPKICertificate):
  handle = HandleField()
  parent_handle = HandleField()
  child_handle  = HandleField()
  bpki_ta = BinaryField()
  service_uri = django.db.models.CharField(max_length = 255)
  repository_type_map = ChoiceMap("none", "offer", "referral")
  repository_type = django.db.models.PositiveSmallIntegerField(choices = repository_type_map.choices)
  referral_authorization = BinaryField(null = True, blank = True)

class ROARequest(django.db.models.Model):
  identity = django.db.models.ForeignKey(Identity, related_name = "roa_requests")
  handle = HandleField()
  asn = django.db.models.BigIntegerField()

class ROARequestPrefix(django.db.models.Model):
  roa_request = django.db.models.ForeignKey(ROARequest, related_name = "prefixes")
  version_map = IP_VERSION_MAP
  version = django.db.models.PositiveSmallIntegerField(choices = version_map.choices)
  prefix = django.db.models.CharField(max_length = 40)
  prefixlen = django.db.models.PositiveSmallIntegerField()
  max_prefixlen = django.db.models.PositiveSmallIntegerField()

class GhostbusterRequest(django.db.models.Model):
  identity = django.db.models.ForeignKey(Identity, related_name = "ghostbuster_requests")
  parent = django.db.models.ForeignKey(Parent,     related_name = "ghostbuster_requests", null = True)
  vcard = django.db.models.TextField()

class Repository(BPKICertificate):
  handle = HandleField()
  client_handle = HandleField()
  bpki_ta = BinaryField()
  service_uri = django.db.models.CharField(max_length = 255)
  sia_base = django.db.models.TextField()
  parent = django.db.models.OneToOneField(Parent, related_name = "repository")

class Client(BPKICertificate):
  handle = HandleField()
  bpki_ta = BinaryField()
