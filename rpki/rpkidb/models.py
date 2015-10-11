"""
Django ORM models for rpkid.
"""

from __future__ import unicode_literals

import logging

from django.db import models

import rpki.left_right

from rpki.fields import (EnumField, SundialField, BlobField,
                         CertificateField, KeyField, CRLField, PKCS10Field,
                         ManifestField, ROAField, GhostbusterField)

from lxml.etree import Element, SubElement, tostring as ElementToString

logger = logging.getLogger(__name__)

# The objects available via the left-right protocol allow NULL values
# in places we wouldn't otherwise (eg, bpki_cert fields), to support
# existing protocol which allows back-end to build up objects
# gradually.  We may want to rethink this eventually, but that yak can
# wait for its shave, particularly since disallowing null should be a
# very simple change given migrations.

# The <self/> element was really badly named, but we weren't using
# Python when we named it.  Perhaps <tenant/> would be a better name?
# Would want to rename it in left-right too.
#
# To make things worse, <self/> elements are handled slightly
# differently in many places, so there are a number of occurances of
# "self" or "self_handle" as special case magic.  Feh.
#
# Cope for now, just be careful.

class XMLTemplate(object):
  """
  Encapsulate all the voodoo for transcoding between lxml and ORM.
  """

  # Type map to simplify declaration of Base64 sub-elements.

  element_type = dict(bpki_cert        = rpki.x509.X509,
                      bpki_glue        = rpki.x509.X509,
                      bpki_cms_cert    = rpki.x509.X509,
                      bpki_cms_glue    = rpki.x509.X509,
                      pkcs10_request   = rpki.x509.PKCS10,
                      signing_cert     = rpki.x509.X509,
                      signing_cert_crl = rpki.x509.CRL)

  def __init__(self, name, attributes = (), booleans = (), elements = (), handles = ()):
    self.name       = name
    self.handles    = handles
    self.attributes = attributes
    self.booleans   = booleans
    self.elements   = elements

  def encode(self, obj, r_msg):
    """
    Encode an ORM object as XML.
    """

    r_pdu = SubElement(r_msg, rpki.left_right.xmlns + self.name, nsmap = rpki.left_right.nsmap)
    r_pdu.set(self.name + "_handle", getattr(obj, self.name + "_handle"))
    if self.name != "self":
      r_pdu.set("self_handle", getattr(obj, "self_handle"))
    for h in self.handles:
      k = h.xml_template.name
      v = getattr(obj, k)
      if v is not None:
        r_pdu.set(k + "_handle", getattr(v, k + "_handle"))
    for k in self.attributes:
      v = getattr(obj, k)
      if v is not None:
        r_pdu.set(k, str(v))
    for k in self.booleans:
      if getattr(obj, k):
        r_pdu.set(k, "yes")
    for k in self.elements:
      v = getattr(obj, k)
      if v is not None and not v.empty():
        SubElement(r_pdu, rpki.left_right.xmlns + k).text = v.get_Base64()

  def acknowledge(self, obj, q_pdu, r_msg):
    """
    Add an acknowledgement PDU in response to a create, set, or
    destroy action.

    This includes a bit of special-case code for BSC objects which has
    to go somewhere; we could handle it via some kind method of
    call-out to the BSC model, but it's not worth building a general
    mechanism for one case, so we do it inline and have done.
    """

    assert q_pdu.tag == rpki.left_right.xmlns + self.name
    r_pdu = SubElement(r_msg, rpki.left_right.xmlns + self.name, nsmap = rpki.left_right.nsmap)
    r_pdu.set(self.name + "_handle", getattr(obj, self.name + "_handle"))
    if self.name != "self":
      r_pdu.set("self_handle", getattr(obj, "self_handle"))
    if self.name == "bsc" and q_pdu.get("action") != "destroy" and obj.pkcs11_request is not None:
      assert not obj.pkcs11_request.empty()
      SubElement(r_pdu, rpki.left_right.xmlns + "pkcs11_request").text = obj.pkcs11_request.get_Base64()

  def decode(self, obj, q_pdu):
    """
    Decode XML into an ORM object.
    """

    assert q_pdu.tag == rpki.left_right.xmlns + self.name
    for h in self.handles:
      k = h.xml_template.name
      v = q_pdu.get(k + "_handle")
      if v is not None:
        setattr(obj, k, h.objects.get(**{k + "_handle" : v, "self" : obj.self}))
    for k in self.attributes:
      v = q_pdu.get(k)
      if v is not None:
        v.encode("ascii")
        if v.isdigit():
          v = long(v)
        setattr(obj, k, v)
    for k in self.booleans:
      v = q_pdu.get(k)
      if v is not None:
        setattr(obj, k, v == "yes")
    for k in self.elements:
      v = q_pdu.findtext(rpki.left_right.xmlns + k)
      if v and v.strip():
        setattr(obj, k, self.element_type[k](Base64 = v))


class XMLManager(models.Manager):
  """
  Add a few methods which locate or create an object or objects
  corresponding to the handles in an XML element, as appropriate.

  This assumes that models which use it have an "xml" class attribute
  holding an XMLTemplate object (above).
  """

  def xml_get_or_create(self, xml):
    name   = self.model.xml_template.name
    action = xml.get("action")
    assert xml.tag == rpki.left_right.xmlns + name and action in ("create", "set")
    d = { name + "_handle" : xml.get(name + "_handle") }
    if name != "self" and action == "create":
      d["self"] = Self.objects.get(self_handle = xml.get("self_handle"))
    elif name != "self":
      d["self__self_handle"] = xml.get("self_handle")
    return self.model(**d) if action == "create" else self.get(**d)

  def xml_list(self, xml):
    name   = self.model.xml_template.name
    action = xml.get("action")
    assert xml.tag == rpki.left_right.xmlns + name and action in ("get", "list")
    d = {}
    if action == "get":
      d[name + "_handle"] = xml.get(name + "_handle")
    if name != "self":
      d["self__self_handle"] = xml.get("self_handle")
    return self.filter(**d) if d else self.all()

  def xml_get_for_delete(self, xml):
    name   = self.model.xml_template.name
    action = xml.get("action")
    assert xml.tag == rpki.left_right.xmlns + name and action == "destroy"
    d = { name + "_handle" : xml.get(name + "_handle") }
    if name != "self":
      d["self__self_handle"] = xml.get("self_handle")
    return self.get(**d)

# Models

class Self(models.Model):
  self_handle = models.SlugField(max_length = 255)
  use_hsm = models.BooleanField(default = False)
  crl_interval = models.BigIntegerField(null = True)
  regen_margin = models.BigIntegerField(null = True)
  bpki_cert = CertificateField(null = True)
  bpki_glue = CertificateField(null = True)
  objects = XMLManager()

  xml_template = XMLTemplate(
    name       = "self",
    attributes = ("crl_interval", "regen_margin"),
    booleans   = ("use_hsm",),
    elements   = ("bpki_cert", "bpki_glue"))

class BSC(models.Model):
  bsc_handle = models.SlugField(max_length = 255)
  private_key_id = KeyField()
  pkcs10_request = PKCS10Field()
  hash_alg = EnumField(choices = ("sha256",))
  signing_cert = CertificateField(null = True)
  signing_cert_crl = CRLField(null = True)
  self = models.ForeignKey(Self)
  objects = XMLManager()

  class Meta:
    unique_together = ("self", "bsc_handle")

  xml_template = XMLTemplate(
    name       = "bsc",
    elements   = ("signing_cert", "signing_cert_crl", "pkcs10_request"))

class Repository(models.Model):
  repository_handle = models.SlugField(max_length = 255)
  peer_contact_uri = models.TextField(null = True)
  bpki_cert = CertificateField(null = True)
  bpki_glue = CertificateField(null = True)
  last_cms_timestamp = SundialField(null = True)
  bsc = models.ForeignKey(BSC)
  self = models.ForeignKey(Self)
  objects = XMLManager()

  class Meta:
    unique_together = ("self", "repository_handle")

  xml_template = XMLTemplate(
    name       = "repository",
    handles    = (BSC,),
    attributes = ("peer_contact_uri",),
    elements   = ("bpki_cert", "bpki_glue"))


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
  objects = XMLManager()

  class Meta:
    unique_together = ("self", "parent_handle")

  xml_template = XMLTemplate(
    name       = "parent",
    handles    = (BSC, Repository),
    attributes = ("peer_contact_uri", "sia_base", "sender_name", "recipient_name"),
    elements   = ("bpki_cms_cert", "bpki_cms_glue"))

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

class Child(models.Model):
  child_handle = models.SlugField(max_length = 255)
  bpki_cert = CertificateField(null = True)
  bpki_glue = CertificateField(null = True)
  last_cms_timestamp = SundialField(null = True)
  self = models.ForeignKey(Self)
  bsc = models.ForeignKey(BSC)
  objects = XMLManager()

  class Meta:
    unique_together = ("self", "child_handle")

  xml_template = XMLTemplate(
    name     = "child",
    handles  = (BSC,),
    elements = ("bpki_cert", "bpki_glue"))

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
