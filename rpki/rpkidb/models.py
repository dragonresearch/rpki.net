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

  def __init__(self, name, attributes = (), booleans = (), elements = (), readonly = (), handles = ()):
    self.name       = name
    self.handles    = handles
    self.attributes = attributes
    self.booleans   = booleans
    self.elements   = elements
    self.readonly   = readonly

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
    for k in self.elements + self.readonly:
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

  def xml_pre_delete_hook(self):
    raise NotImplementedError

  def xml_pre_save_hook(self, q_pdu):
    pass

  def xml_post_save_hook(self, q_pdu, cb, eb):
    actions = []
    rekey                   = q_pdu.get("rekey")
    revoke                  = q_pdu.get("revoke")
    reissue                 = q_pdu.get("reissue")
    revoke_forgotten        = q_pdu.get("revoke_forgotten")
    publish_world_now       = q_pdu.get("publish_world_now")
    run_now                 = q_pdu.get("run_now")
    clear_replay_protection = q_pdu.get("clear_replay_protection")
    if rekey or revoke or reissue or revoke_forgotten or clear_replay_protection:
      for parent in self.parents.all():
        if rekey:
          actions.append(parent.serve_rekey)
        if revoke:
          actions.append(parent.serve_revoke)
        if reissue:
          actions.append(parent.serve_reissue)
        if revoke_forgotten:
          actions.append(parent.serve_revoke_forgotten)
        if clear_replay_protection:
          actions.append(parent.serve_clear_replay_protection)
    if clear_replay_protection:
      for child in self.children.all():
        actions.append(child.serve_clear_replay_protection)
      for repository in self.repositories.all():
        actions.append(repository.serve_clear_replay_protection)
    if publish_world_now:
      actions.append(self.serve_publish_world_now)
    if run_now:
      actions.append(self.serve_run_now)
    def loop(iterator, action):
      action(iterator, eb)
    rpki.async.iterator(actions, loop, cb)

  def serve_publish_world_now(self, cb, eb):
    publisher = rpki.rpkid.publication_queue()
    repositories = set()
    objects = dict()

    def loop(iterator, parent):
      repository = parent.repository
      if repository.peer_contact_uri in repositories:
        return iterator()
      repositories.add(repository.peer_contact_uri)
      q_msg = Element(rpki.publication.tag_msg, nsmap = rpki.publication.nsmap,
                      type = "query", version = rpki.publication.version)
      SubElement(q_msg, rpki.publication.tag_list, tag = "list")
      def list_handler(r_pdu):
        rpki.publication.raise_if_error(r_pdu)
        assert r_pdu.tag == rpki.publication.tag_list
        assert r_pdu.get("uri") not in objects
        objects[r_pdu.get("uri")] = (r_pdu.get("hash"), repository)
      repository.call_pubd(iterator, eb, q_msg, length_check = False, handlers = dict(list = list_handler))

    def reconcile(uri, obj, repository):
      h, r = objects.pop(uri, (None, None))
      if h is not None:
        assert r == repository
        publisher.queue(uri = uri, new_obj = obj, old_hash = h, repository = repository)

    def done():
      for parent in self.parents.all():
        repository = parent.repository
        for ca in parent.cas.all():
          ca_detail = ca.active_ca_detail
          if ca_detail is not None:
            reconcile(uri = ca_detail.crl_uri,      obj = ca_detail.latest_crl,      repository = repository)
            reconcile(uri = ca_detail.manifest_uri, obj = ca_detail.latest_manifest, repository = repository)
            for c in ca_detail.child_certs.all():
              reconcile(uri = c.uri,                obj = c.cert,                    repository = repository)
            for r in ca_detail.roas.all():
              if r.roa is not None:
                reconcile(uri = r.uri,              obj = r.roa,                     repository = repository)
            for g in ca_detail.ghostbusters.all():
              reconcile(uri = g.uri,                obj = g.ghostbuster,             repository = repository)
            for c in ca_detail.ee_certificates.all():
              reconcile(uri = c.uri,                obj = c.cert,                    repository = repository)
        for u in objects:
          h, r = objects[h]
          publisher.queue(uri = u, old_hash = h, repository = r)
      publisher.call_pubd(cb, eb)

    rpki.async.iterator(self.parents.all(), loop, done)

  def serve_run_now(self, cb, eb):
    logger.debug("Forced immediate run of periodic actions for self %s[%d]", self.self_handle, self.self_id)
    completion = rpki.rpkid_tasks.CompletionHandler(cb)
    self.schedule_cron_tasks(completion)
    assert completion.count > 0
    self.gctx.task_run()


class BSC(models.Model):
  bsc_handle = models.SlugField(max_length = 255)
  private_key_id = KeyField()
  pkcs10_request = PKCS10Field()
  hash_alg = EnumField(choices = ("sha256",))
  signing_cert = CertificateField(null = True)
  signing_cert_crl = CRLField(null = True)
  self = models.ForeignKey(Self, related_name = "bscs")
  objects = XMLManager()

  class Meta:
    unique_together = ("self", "bsc_handle")

  xml_template = XMLTemplate(
    name       = "bsc",
    elements   = ("signing_cert", "signing_cert_crl"),
    readonly   = ("pkcs10_request",))

  def xml_pre_delete_hook(self):
    pass

  def xml_pre_save_hook(self, q_pdu):
    # Handle key generation, only supports RSA with SHA-256 for now.
    if q_pdu.get("generate_keypair"):
      assert q_pdu.get("key_type") in (None, "rsa") and q_pdu.get("hash_alg") in (None, "sha256")
      self.private_key_id = rpki.x509.RSA.generate(keylength = int(q_pdu.get("key_length", 2048)))
      self.pkcs10_request = rpki.x509.PKCS10.create(keypair = self.private_key_id)

  def xml_post_save_hook(self, q_pdu):
    pass


class Repository(models.Model):
  repository_handle = models.SlugField(max_length = 255)
  peer_contact_uri = models.TextField(null = True)
  bpki_cert = CertificateField(null = True)
  bpki_glue = CertificateField(null = True)
  last_cms_timestamp = SundialField(null = True)
  bsc = models.ForeignKey(BSC, related_name = "repositories")
  self = models.ForeignKey(Self, related_name = "repositories")
  objects = XMLManager()

  class Meta:
    unique_together = ("self", "repository_handle")

  xml_template = XMLTemplate(
    name       = "repository",
    handles    = (BSC,),
    attributes = ("peer_contact_uri",),
    elements   = ("bpki_cert", "bpki_glue"))

  def xml_pre_delete_hook(self):        raise NotImplementedError
  def xml_pre_save_hook(self, q_pdu):   raise NotImplementedError
  def xml_post_save_hook(self, q_pdu):  raise NotImplementedError


class Parent(models.Model):
  parent_handle = models.SlugField(max_length = 255)
  bpki_cms_cert = CertificateField(null = True)
  bpki_cms_glue = CertificateField(null = True)
  peer_contact_uri = models.TextField(null = True)
  sia_base = models.TextField(null = True)
  sender_name = models.TextField(null = True)
  recipient_name = models.TextField(null = True)
  last_cms_timestamp = SundialField(null = True)
  self = models.ForeignKey(Self, related_name = "parents")
  bsc = models.ForeignKey(BSC, related_name = "parents")
  repository = models.ForeignKey(Repository, related_name = "parents")
  objects = XMLManager()

  class Meta:
    unique_together = ("self", "parent_handle")

  xml_template = XMLTemplate(
    name       = "parent",
    handles    = (BSC, Repository),
    attributes = ("peer_contact_uri", "sia_base", "sender_name", "recipient_name"),
    elements   = ("bpki_cms_cert", "bpki_cms_glue"))

  def xml_pre_delete_hook(self):        raise NotImplementedError
  def xml_pre_save_hook(self, q_pdu):   raise NotImplementedError
  def xml_post_save_hook(self, q_pdu):  raise NotImplementedError


class CA(models.Model):
  last_crl_sn = models.BigIntegerField()
  last_manifest_sn = models.BigIntegerField()
  next_manifest_update = SundialField(null = True)
  next_crl_update = SundialField(null = True)
  last_issued_sn = models.BigIntegerField()
  sia_uri = models.TextField(null = True)
  parent_resource_class = models.TextField(null = True)
  parent = models.ForeignKey(Parent, related_name = "cas")

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
  ca = models.ForeignKey(CA, related_name = "ca_details")

class Child(models.Model):
  child_handle = models.SlugField(max_length = 255)
  bpki_cert = CertificateField(null = True)
  bpki_glue = CertificateField(null = True)
  last_cms_timestamp = SundialField(null = True)
  self = models.ForeignKey(Self, related_name = "children")
  bsc = models.ForeignKey(BSC, related_name = "children")
  objects = XMLManager()

  class Meta:
    unique_together = ("self", "child_handle")

  xml_template = XMLTemplate(
    name     = "child",
    handles  = (BSC,),
    elements = ("bpki_cert", "bpki_glue"))

  def xml_pre_delete_hook(self):        raise NotImplementedError
  def xml_pre_save_hook(self, q_pdu):   raise NotImplementedError
  def xml_post_save_hook(self, q_pdu):  raise NotImplementedError


class ChildCert(models.Model):
  cert = CertificateField()
  published = SundialField(null = True)
  ski = BlobField()
  child = models.ForeignKey(Child, related_name = "child_certs")
  ca_detail = models.ForeignKey(CADetail, related_name = "child_certs")

class EECert(models.Model):
  ski = BlobField()
  cert = CertificateField()
  published = SundialField(null = True)
  self = models.ForeignKey(Self, related_name = "ee_certs")
  ca_detail = models.ForeignKey(CADetail, related_name = "ee_certs")

class Ghostbuster(models.Model):
  vcard = models.TextField()
  cert = CertificateField()
  ghostbuster = GhostbusterField()
  published = SundialField(null = True)
  self = models.ForeignKey(Self, related_name = "ghostbusters")
  ca_detail = models.ForeignKey(CADetail, related_name = "ghostbusters")

class RevokedCert(models.Model):
  serial = models.BigIntegerField()
  revoked = SundialField()
  expires = SundialField()
  ca_detail = models.ForeignKey(CADetail, related_name = "revoked_certs")

class ROA(models.Model):
  asn = models.BigIntegerField()
  cert = CertificateField()
  roa = ROAField()
  published = SundialField(null = True)
  self = models.ForeignKey(Self, related_name = "roas")
  ca_detail = models.ForeignKey(CADetail, related_name = "roas")

class ROAPrefix(models.Model):
  prefix = models.CharField(max_length = 40)
  prefixlen = models.SmallIntegerField()
  max_prefixlen = models.SmallIntegerField()
  version = models.SmallIntegerField()
  roa = models.ForeignKey(ROA, related_name = "roa_prefixes")
