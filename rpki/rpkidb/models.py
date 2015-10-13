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


  def xml_post_save_hook(self, q_pdu, cb, eb):
    if q_pdu.get("clear_replay_protection"):
      for parent in self.parents.all():
        parent.clear_replay_protection()
      for child in self.children.all():
        child.clear_replay_protection()
      for repository in self.repositories.all():
        repository.clear_replay_protection()
    actions = []
    rekey             = q_pdu.get("rekey")
    revoke            = q_pdu.get("revoke")
    reissue           = q_pdu.get("reissue")
    revoke_forgotten  = q_pdu.get("revoke_forgotten")
    if rekey or revoke or reissue or revoke_forgotten:
      for parent in self.parents.all():
        if rekey:
          actions.append(parent.serve_rekey)
        if revoke:
          actions.append(parent.serve_revoke)
        if reissue:
          actions.append(parent.serve_reissue)
        if revoke_forgotten:
          actions.append(parent.serve_revoke_forgotten)
    if q_pdu.get("publish_world_now"):
      actions.append(self.serve_publish_world_now)
    if q_pdu.get("run_now"):
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
      for ca_detail in CADetail.objects.filter(ca__parent__self = self, state = "active"):
        repository = ca_detail.ca.parent.repository
        reconcile(uri = ca_detail.crl_uri,      obj = ca_detail.latest_crl,      repository = repository)
        reconcile(uri = ca_detail.manifest_uri, obj = ca_detail.latest_manifest, repository = repository)
        for c in ca_detail.child_certs.all():
          reconcile(uri = c.uri,                obj = c.cert,                    repository = repository)
        for r in ca_detail.roas.filter(roa__isnull = False):
          reconcile(uri = r.uri,                obj = r.roa,                     repository = repository)
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


  def schedule_cron_tasks(self, completion):
    if self.cron_tasks is None:
      self.cron_tasks = tuple(task(self) for task in rpki.rpkid_tasks.task_classes)
    for task in self.cron_tasks:
      self.gctx.task_add(task)
      completion.register(task)


  def find_covering_ca_details(self, resources):
    """
    Return all active ca_detail_objs for this <self/> which cover a
    particular set of resources.

    If we expected there to be a large number of ca_detail_objs, we
    could add index tables and write fancy SQL query to do this, but
    for the expected common case where there are only one or two
    active ca_detail_objs per <self/>, it's probably not worth it.  In
    any case, this is an optimization we can leave for later.
    """

    return set(ca_detail
               for ca_detail in CADetail.objects.filter(ca__parent__self = self, state = "active")
               if ca_detail.covers(resources))


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


  def xml_pre_save_hook(self, q_pdu):
    # Handle key generation, only supports RSA with SHA-256 for now.
    if q_pdu.get("generate_keypair"):
      assert q_pdu.get("key_type") in (None, "rsa") and q_pdu.get("hash_alg") in (None, "sha256")
      self.private_key_id = rpki.x509.RSA.generate(keylength = int(q_pdu.get("key_length", 2048)))
      self.pkcs10_request = rpki.x509.PKCS10.create(keypair = self.private_key_id)


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


  def xml_post_save_hook(self, q_pdu, cb, eb):
    if q_pdu.get("clear_replay_protection"):
      self.clear_replay_protection()
    cb()


  def clear_replay_protection(self):
    self.last_cms_timestamp = None
    self.save()


  def call_pubd(self, callback, errback, q_msg, handlers = {}, length_check = True):
    """
    Send a message to publication daemon and return the response.

    As a convenience, attempting to send an empty message returns
    immediate success without sending anything.

    handlers is a dict of handler functions to process the response
    PDUs.  If the tag value in the response PDU appears in the dict,
    the associated handler is called to process the PDU.  If no tag
    matches, a default handler is called to check for errors; a
    handler value of False suppresses calling of the default handler.
    """

    try:
      if len(q_msg) == 0:
        return callback()

      for q_pdu in q_msg:
        logger.info("Sending %r to pubd", q_pdu)

      bsc = self.bsc
      q_der = rpki.publication.cms_msg().wrap(q_msg, bsc.private_key_id, bsc.signing_cert, bsc.signing_cert_crl)
      bpki_ta_path = (self.gctx.bpki_ta, self.self.bpki_cert, self.self.bpki_glue, self.bpki_cert, self.bpki_glue)

      def done(r_der):
        try:
          logger.debug("Received response from pubd")
          r_cms = rpki.publication.cms_msg(DER = r_der)
          r_msg = r_cms.unwrap(bpki_ta_path)
          r_cms.check_replay_sql(self, self.peer_contact_uri)
          for r_pdu in r_msg:
            handler = handlers.get(r_pdu.get("tag"), rpki.publication.raise_if_error)
            if handler:
              logger.debug("Calling pubd handler %r", handler)
              handler(r_pdu)
          if length_check and len(q_msg) != len(r_msg):
            raise rpki.exceptions.BadPublicationReply("Wrong number of response PDUs from pubd: sent %r, got %r" % (q_msg, r_msg))
          callback()
        except (rpki.async.ExitNow, SystemExit):
          raise
        except Exception, e:
          errback(e)

      logger.debug("Sending request to pubd")
      rpki.http.client(
        url          = self.peer_contact_uri,
        msg          = q_der,
        callback     = done,
        errback      = errback)

    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception, e:
      errback(e)


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


  def xml_pre_delete_hook(self, cb, eb):
    self.destroy(cb, delete_parent = False)


  def xml_post_save_hook(self, q_pdu, cb, eb):
    if q_pdu.get("clear_replay_protection"):
      self.clear_replay_protection()
    actions = []
    if q_pdu.get("rekey"):
      actions.append(self.serve_rekey)
    if q_pdu.get("revoke"):
      actions.append(self.serve_revoke)
    if q_pdu.get("reissue"):
      actions.append(self.serve_reissue)
    if q_pdu.get("revoke_forgotten"):
      actions.append(self.serve_revoke_forgotten)
    def loop(iterator, action):
      action(iterator, eb)
    rpki.async.iterator(actions, loop, cb)


  def serve_rekey(self, cb, eb):
    def loop(iterator, ca):
      ca.rekey(iterator, eb)
    rpki.async.iterator(self.cas.all(), loop, cb)


  def serve_revoke(self, cb, eb):
    def loop(iterator, ca):
      ca.revoke(cb = iterator, eb = eb)
    rpki.async.iterator(self.cas.all(), loop, cb)


  def serve_reissue(self, cb, eb):
    def loop(iterator, ca):
      ca.reissue(cb = iterator, eb = eb)
    rpki.async.iterator(self.cas.all(), loop, cb)


  def clear_replay_protection(self):
    self.last_cms_timestamp = None
    self.save()


  def get_skis(self, cb, eb):
    """
    Fetch SKIs that this parent thinks we have.  In theory this should
    agree with our own database, but in practice stuff can happen, so
    sometimes we need to know what our parent thinks.

    Result is a dictionary with the resource class name as key and a
    set of SKIs as value.
    """

    def done(r_msg):
      cb(dict((rc.get("class_name"),
               set(rpki.x509.X509(Base64 = c.text).gSKI()
                   for c in rc.getiterator(rpki.up_down.tag_certificate)))
              for rc in r_msg.getiterator(rpki.up_down.tag_class)))
    self.up_down_list_query(done, eb)


  def revoke_skis(self, rc_name, skis_to_revoke, cb, eb):
    """
    Revoke a set of SKIs within a particular resource class.
    """

    def loop(iterator, ski):
      def revoked(r_pdu):
        iterator()
      logger.debug("Asking parent %r to revoke class %r, SKI %s", self, rc_name, ski)
      self.up_down_revoke_query(rc_name, ski, revoked, eb)
    rpki.async.iterator(skis_to_revoke, loop, cb)


  def serve_revoke_forgotten(self, cb, eb):
    """
    Handle a left-right revoke_forgotten action for this parent.

    This is a bit fiddly: we have to compare the result of an up-down
    list query with what we have locally and identify the SKIs of any
    certificates that have gone missing.  This should never happen in
    ordinary operation, but can arise if we have somehow lost a
    private key, in which case there is nothing more we can do with
    the issued cert, so we have to clear it.  As this really is not
    supposed to happen, we don't clear it automatically, instead we
    require an explicit trigger.
    """

    def got_skis(skis_from_parent):
      def loop(iterator, item):
        rc_name, skis_to_revoke = item
        if rc_name in ca_map:
          for ca_detail in ca_map[rc_name].issue_response_candidate_ca_details:
            skis_to_revoke.discard(ca_detail.latest_ca_cert.gSKI())
        self.revoke_skis(rc_name, skis_to_revoke, iterator, eb)
      ca_map = dict((ca.parent_resource_class, ca) for ca in self.cas.all())
      rpki.async.iterator(skis_from_parent.items(), loop, cb)
    self.get_skis(got_skis, eb)


  def destroy(self, cb, delete_parent = True):
    """
    Delete all the CA stuff under this parent, and perhaps the parent
    itself.
    """

    # parent_elt.delete() renamed to .destroy() here to avoid conflict
    # with built-in ORM .delete() method.

    def loop(iterator, ca):
      ca.destroy(self, iterator)
    def revoke():
      self.serve_revoke_forgotten(done, fail)
    def fail(e):
      logger.warning("Trouble getting parent to revoke certificates, blundering onwards: %s", e)
      done()
    def done():
      if delete_parent:
        self.delete()
      cb()
    rpki.async.iterator(self.cas, loop, revoke)


  def _compose_up_down_query(self, query_type):
    return Element(rpki.up_down.tag_message, nsmap = rpki.up_down.nsmap, version = rpki.up_down.version,
                   sender  = self.sender_name, recipient = self.recipient_name, type = query_type)


  def up_down_list_query(self, cb, eb):
    q_msg = self._compose_up_down_query("list")
    self.query_up_down(q_msg, cb, eb)


  def up_down_issue_query(self, ca, ca_detail, cb, eb):
    pkcs10 = rpki.x509.PKCS10.create(
      keypair      = ca_detail.private_key_id,
      is_ca        = True,
      caRepository = ca.sia_uri,
      rpkiManifest = ca_detail.manifest_uri,
      rpkiNotify   = rpki.publication.rrdp_sia_uri_kludge)
    q_msg = self._compose_up_down_query("issue")
    q_pdu = SubElement(q_msg, rpki.up_down.tag_request, class_name = ca.parent_resource_class)
    q_pdu.text = pkcs10.get_Base64()
    self.query_up_down(q_msg, cb, eb)


  def up_down_revoke_query(self, class_name, ski, cb, eb):
    q_msg = self._compose_up_down_query("revoke")
    SubElement(q_msg, rpki.up_down.tag_key, class_name = class_name, ski = ski)
    self.query_up_down(q_msg, cb, eb)


  def query_up_down(self, q_msg, cb, eb):

    if self.bsc is None:
      raise rpki.exceptions.BSCNotFound("Could not find BSC")

    if self.bsc.signing_cert is None:
      raise rpki.exceptions.BSCNotReady("BSC %r is not yet usable" % eslf.bsc.bsc_handle)

    q_der = rpki.up_down.cms_msg().wrap(q_msg,
                                        self.bsc.private_key_id,
                                        self.bsc.signing_cert,
                                        self.bsc.signing_cert_crl)

    def unwrap(r_der):
      try:
        r_cms = rpki.up_down.cms_msg(DER = r_der)
        r_msg = r_cms.unwrap((self.gctx.bpki_ta,
                              self.self.bpki_cert,
                              self.self.bpki_glue,
                              self.bpki_cms_cert,
                              self.bpki_cms_glue))
        r_cms.check_replay_sql(self, self.peer_contact_uri)
        rpki.up_down.check_response(r_msg, q_msg.get("type"))

      except (SystemExit, rpki.async.ExitNow):
        raise
      except Exception, e:
        eb(e)
      else:
        cb(r_msg)

    rpki.http.client(
      msg          = q_der,
      url          = self.peer_contact_uri,
      callback     = unwrap,
      errback      = eb,
      content_type = rpki.up_down.content_type)


class CA(models.Model):
  last_crl_sn = models.BigIntegerField()
  last_manifest_sn = models.BigIntegerField()
  next_manifest_update = SundialField(null = True)
  next_crl_update = SundialField(null = True)
  last_issued_sn = models.BigIntegerField()
  sia_uri = models.TextField(null = True)
  parent_resource_class = models.TextField(null = True)
  parent = models.ForeignKey(Parent, related_name = "cas")

  # So it turns out that there's always a 1:1 mapping between the
  # class_name we receive from our parent and the class_name we issue
  # to our children: in spite of the obfuscated way that we used to
  # handle class names, we never actually added a way for the back-end
  # to create new classes.  Not clear we want to encourage this, but
  # if we wanted to support it, simple approach would probably be an
  # optional class_name attribute in the left-right <list_resources/>
  # response; if not present, we'd use parent's class_name as now,
  # otherwise we'd use the supplied class_name.



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


  def xml_pre_delete_hook(self, cb, eb):
    publisher = rpki.rpkid.publication_queue()
    for child_cert in self.child_certs.all():
      child_cert.revoke(publisher = publisher, generate_crl_and_manifest = True)
    publisher.call_pubd(cb, eb)


  def xml_post_save_hook(self, q_pdu, cb, eb):
    if q_pdu.get("clear_replay_protection"):
      self.clear_replay_protection()
    if q_pdu.get("reissue"):
      self.serve_reissue(cb, eb)
    else:
      cb()


  def serve_reissue(self, cb, eb):
    publisher = rpki.rpkid.publication_queue()
    for child_cert in self.child_certs.all():
      child_cert.reissue(child_cert.ca_detail, publisher, force = True)
    publisher.call_pubd(cb, eb)


  def clear_replay_protection(self):
    self.last_cms_timestamp = None
    self.save()


  def up_down_handle_list(self, q_msg, r_msg, callback, errback):
    def got_resources(irdb_resources):
      if irdb_resources.valid_until < rpki.sundial.now():
        logger.debug("Child %s's resources expired %s", self.child_handle, irdb_resources.valid_until)
      else:
        for ca_detail in CADetail.objects.filter(ca__parent__self = self.self, state = "active"):
          resources = ca_detail.latest_ca_cert.get_3779resources() & irdb_resources
          if resources.empty():
            logger.debug("No overlap between received resources and what child %s should get ([%s], [%s])",
                         self.child_handle, ca_detail.latest_ca_cert.get_3779resources(), irdb_resources)
            continue
          rc = SubElement(r_msg, rpki.up_down.tag_class,
                          class_name = ca_detail.ca.parent_resource_class,
                          cert_url = ca_detail.ca_cert_uri,
                          resource_set_as   = str(resources.asn),
                          resource_set_ipv4 = str(resources.v4),
                          resource_set_ipv6 = str(resources.v6),
                          resource_set_notafter = str(resources.valid_until))
          for child_cert in self.child_certs.filter(ca_detail = ca_detail):
            c = SubElement(rc, rpki.up_down.tag_certificate, cert_url = child_cert.uri)
            c.text = child_cert.cert.get_Base64()
          SubElement(rc, rpki.up_down.tag_issuer).text = ca_detail.latest_ca_cert.get_Base64()
      callback()
    self.gctx.irdb_query_child_resources(self.self.self_handle, self.child_handle, got_resources, errback)


  def up_down_handle_issue(self, q_msg, r_msg, callback, errback):

    def got_resources(irdb_resources):

      def done():
        rc = SubElement(r_msg, rpki.up_down.tag_class,
                        class_name = class_name,
                        cert_url = ca_detail.ca_cert_uri,
                        resource_set_as   = str(resources.asn),
                        resource_set_ipv4 = str(resources.v4),
                        resource_set_ipv6 = str(resources.v6),
                        resource_set_notafter = str(resources.valid_until))
        c = SubElement(rc, rpki.up_down.tag_certificate, cert_url = child_cert.uri)
        c.text = child_cert.cert.get_Base64()
        SubElement(rc, rpki.up_down.tag_issuer).text = ca_detail.latest_ca_cert.get_Base64()
        callback()

      if irdb_resources.valid_until < rpki.sundial.now():
        raise rpki.exceptions.IRDBExpired("IRDB entry for child %s expired %s" % (
          self.child_handle, irdb_resources.valid_until))

      resources = irdb_resources & ca_detail.latest_ca_cert.get_3779resources()
      resources.valid_until = irdb_resources.valid_until
      req_key = pkcs10.getPublicKey()
      req_sia = pkcs10.get_SIA()

      # Generate new cert or regenerate old one if necessary

      publisher = rpki.rpkid.publication_queue()

      try:
        child_cert = self.child_certs.get(ca_detail = ca_detail, ski = req_key.get_SKI())

      except ChildCert.NotFound:
        child_cert = ca_detail.issue(
          ca          = ca_detail.ca,
          child       = self,
          subject_key = req_key,
          sia         = req_sia,
          resources   = resources,
          publisher   = publisher)

      else:
        child_cert = child_cert.reissue(
          ca_detail = ca_detail,
          sia       = req_sia,
          resources = resources,
          publisher = publisher)

      publisher.call_pubd(done, errback)

    req = q_msg[0]
    assert req.tag == rpki.up_down.tag_request

    # Subsetting not yet implemented, this is the one place where we have to handle it, by reporting that we're lame.

    if any(req.get(a) for a in ("req_resource_set_as", "req_resource_set_ipv4", "req_resource_set_ipv6")):
      raise rpki.exceptions.NotImplementedYet("req_* attributes not implemented yet, sorry")

    class_name = req.get("class_name")
    pkcs10 = rpki.x509.PKCS10(Base64 = req.text)
    pkcs10.check_valid_request_ca()
    ca_detail = CADetail.objects.get(ca__parent__self = self.self,
                                     ca__parent_class_name = class_name,
                                     state = "active")
    self.gctx.irdb_query_child_resources(self.self.self_handle, self.child_handle, got_resources, errback)


  def up_down_handle_revoke(self, q_msg, r_msg, callback, errback):
    def done():
      SubElement(r_msg, key.tag, class_name = class_name, ski = key.get("ski"))
      callback()
    key = q_msg[0]
    assert key.tag == rpki.up_down.tag_key
    class_name = key.get("class_name")
    ski = base64.urlsafe_b64decode(key.get("ski") + "=")
    publisher = rpki.rpkid.publication_queue()
    for child_cert in ChildCert.objects.filter(ca_detail__ca__parent__self = self.self,
                                               ca_detail__ca__parent_class_name = class_name,
                                               ski = ski):
      child_cert.revoke(publisher = publisher)
    publisher.call_pubd(done, errback)


  def serve_up_down(self, q_der, callback):
    """
    Outer layer of server handling for one up-down PDU from this child.
    """

    def done():
      callback(rpki.up_down.cms_msg().wrap(r_msg, bsc.private_key_id, bsc.signing_cert, bsc.signing_cert_crl))

    def lose(e):
      logger.exception("Unhandled exception serving child %r", self)
      rpki.up_down.generate_error_response_from_exception(r_msg, e, q_type)
      done()

    if self.bsc is None:
      raise rpki.exceptions.BSCNotFound("Could not find BSC")
    q_cms = rpki.up_down.cms_msg(DER = q_der)
    q_msg = q_cms.unwrap((self.gctx.bpki_ta,
                          self.self.bpki_cert,
                          self.self.bpki_glue,
                          self.bpki_cert,
                          self.bpki_glue))
    q_cms.check_replay_sql(self, "child", self.child_handle)
    q_type = q_msg.get("type")
    logger.info("Serving %s query from child %s [sender %s, recipient %s]",
                q_type, self.child_handle, q_msg.get("sender"), q_msg.get("recipient"))
    if enforce_strict_up_down_xml_sender and q_msg.get("sender") != self.child_handle:
      raise rpki.exceptions.BadSender("Unexpected XML sender %s" % q_msg.get("sender"))

    r_msg = Element(rpki.up_down.tag_message, nsmap = rpki.up_down.nsmap, version = rpki.up_down.version,
                    sender = q_msg.get("recipient"), recipient = q_msg.get("sender"), type = q_type + "_response")

    try:
      getattr(self, "up_down_handle_" + q_type)(q_msg, r_msg, done, lose)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception, e:
      lose(e)



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
