"""
Django ORM models for rpkid.
"""

from __future__ import unicode_literals
from django.db import models
import rpki.left_right

from rpki.fields import (EnumField, SundialField, BlobField,
                         CertificateField, KeyField, CRLField, PKCS10Field,
                         ManifestField, ROAField, GhostbusterField)


# The objects available via the left-right protocol allow NULL values
# in places we wouldn't otherwise (eg, bpki_cert fields), to support
# existing protocol which allows back-end to build up objects
# gradually.  We may want to rethink this eventually, but that yak can
# wait for its shave, particularly since disallowing null should be a
# very simple change given migrations.
#
# At least for the moment, we use trivial custom managers on these
# classes to provide a simple way of looking up objects from lxml
# objects.  Rethink this later if it proves tedious.

# "self" was a really bad name for this, but we weren't using Python
# when we named it.  Perhaps "Tenant" would be a better name?  Even
# means sort of the right thing, well, in French anyway.
# Eventually rename in left-right too, I guess.

class SelfManager(models.Manager):
  def find_from_xml(self, elt):
    assert elt.tag == rpki.left_right.tag_self
    return self.get(self_handle = elt.get("self_handle"))

class Self(models.Model):
  self_handle = models.SlugField(max_length = 255)
  use_hsm = models.BooleanField(default = False)
  crl_interval = models.BigIntegerField(null = True)
  regen_margin = models.BigIntegerField(null = True)
  bpki_cert = CertificateField(null = True)
  bpki_glue = CertificateField(null = True)
  objects = SelfManager()

class BSCManager(models.Manager):
  def find_from_xml(self, elt):
    assert elt.tag == rpki.left_right.tag_bsc
    return self.get(self__self_handle = elt.get("self_handle"), bsc_handle = elt.get("bsc_handle"))

class BSC(models.Model):
  bsc_handle = models.SlugField(max_length = 255)
  private_key_id = KeyField()
  pkcs10_request = PKCS10Field()
  hash_alg = EnumField(choices = ("sha256",))
  signing_cert = CertificateField(null = True)
  signing_cert_crl = CRLField(null = True)
  self = models.ForeignKey(Self)
  objects = BSCManager()
  class Meta:
    unique_together = ("self", "bsc_handle")

class RepositoryManager(models.Manager):
  def find_from_xml(self, elt):
    assert elt.tag == rpki.left_right.tag_repository
    return self.get(self__self_handle = elt.get("self_handle"), repository_handle = elt.get("repository_handle"))

class Repository(models.Model):
  repository_handle = models.SlugField(max_length = 255)
  peer_contact_uri = models.TextField(null = True)
  bpki_cert = CertificateField(null = True)
  bpki_glue = CertificateField(null = True)
  last_cms_timestamp = SundialField(null = True)
  bsc = models.ForeignKey(BSC)
  self = models.ForeignKey(Self)
  objects = RepositoryManager()
  class Meta:
    unique_together = ("self", "repository_handle")

class ParentManager(models.Manager):
  def find_from_xml(self, elt):
    assert elt.tag == rpki.left_right.tag_parent
    return self.get(self__self_handle = elt.get("self_handle"), parent_handle = elt.get("parent_handle"))

class Parent(models.Model):
  parent_handle = models.SlugField(max_length = 255)
  bpki_cms_cert = CertificateField(null = True)
  bpki_cms_glue = CertificateField(null = True)
  peer_contact_uri = models.TextField(null = True)
  sia_base = models.TextField(null = True)
  sender_name = models.TextField(null = True)
  recipient_name = models.TextField(null = True)
  last_cms_timestamp = SundialField(null = True)
  self = models.ForeignKey(Self)
  bsc = models.ForeignKey(BSC)
  repository = models.ForeignKey(Repository)
  objects = ParentManager()
  class Meta:
    unique_together = ("self", "parent_handle")

class CA(models.Model):
  last_crl_sn = models.BigIntegerField()
  last_manifest_sn = models.BigIntegerField()
  next_manifest_update = SundialField(null = True)
  next_crl_update = SundialField(null = True)
  last_issued_sn = models.BigIntegerField()
  sia_uri = models.TextField(null = True)
  parent_resource_class = models.TextField(null = True)
  parent = models.ForeignKey(Parent)

class CADetail(models.Model):
  public_key = KeyField(null = True)
  private_key_id = KeyField(null = True)
  latest_crl = CRLField(null = True)
  crl_published = SundialField(null = True)
  latest_ca_cert = CertificateField(null = True)
  manifest_private_key_id = KeyField(null = True)
  manifest_public_key = KeyField(null = True)
  latest_manifest_cert = CertificateField(null = True)
  latest_manifest = ManifestField(null = True)
  manifest_published = SundialField(null = True)
  state = EnumField(choices = ("pending", "active", "deprecated", "revoked"))
  ca_cert_uri = models.TextField(null = True)
  ca = models.ForeignKey(CA)

class ChildManager(models.Manager):
  def find_from_xml(self, elt):
    assert elt.tag == rpki.left_right.tag_child
    return self.get(self__self_handle = elt.get("self_handle"), child_handle = elt.get("child_handle"))

class Child(models.Model):
  child_handle = models.SlugField(max_length = 255)
  bpki_cert = CertificateField(null = True)
  bpki_glue = CertificateField(null = True)
  last_cms_timestamp = SundialField(null = True)
  self = models.ForeignKey(Self)
  bsc = models.ForeignKey(BSC)
  objects = ChildManager()
  class Meta:
    unique_together = ("self", "child_handle")

class ChildCert(models.Model):
  cert = CertificateField()
  published = SundialField(null = True)
  ski = BlobField()
  child = models.ForeignKey(Child)
  ca_detail = models.ForeignKey(CADetail)

class EECert(models.Model):
  ski = BlobField()
  cert = CertificateField()
  published = SundialField(null = True)
  self = models.ForeignKey(Self)
  ca_detail = models.ForeignKey(CADetail)

class Ghostbuster(models.Model):
  vcard = models.TextField()
  cert = CertificateField()
  ghostbuster = GhostbusterField()
  published = SundialField(null = True)
  self = models.ForeignKey(Self)
  ca_detail = models.ForeignKey(CADetail)

class RevokedCert(models.Model):
  serial = models.BigIntegerField()
  revoked = SundialField()
  expires = SundialField()
  ca_detail = models.ForeignKey(CADetail)

class ROA(models.Model):
  asn = models.BigIntegerField()
  cert = CertificateField()
  roa = ROAField()
  published = SundialField(null = True)
  self = models.ForeignKey(Self)
  ca_detail = models.ForeignKey(CADetail)

class ROAPrefix(models.Model):
  prefix = models.CharField(max_length = 40)
  prefixlen = models.SmallIntegerField()
  max_prefixlen = models.SmallIntegerField()
  version = models.SmallIntegerField()
  roa = models.ForeignKey(ROA)
