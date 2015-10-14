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
    Return all active CADetails for this <self/> which cover a
    particular set of resources.

    If we expected there to be a large number of CADetails, we
    could add index tables and write fancy SQL query to do this, but
    for the expected common case where there are only one or two
    active CADetails per <self/>, it's probably not worth it.  In
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


  def construct_sia_uri(self, rc):
    """
    Construct the sia_uri value for a CA under this parent given
    configured information and the parent's up-down protocol
    list_response PDU.
    """

    sia_uri = rc.get("suggested_sia_head", "")
    if not sia_uri.startswith("rsync://") or not sia_uri.startswith(self.sia_base):
      sia_uri = self.sia_base
    if not sia_uri.endswith("/"):
      raise rpki.exceptions.BadURISyntax("SIA URI must end with a slash: %s" % sia_uri)
    return sia_uri


class CA(models.Model):
  last_crl_sn = models.BigIntegerField(default = 1)
  last_manifest_sn = models.BigIntegerField(default = 1)
  next_manifest_update = SundialField(null = True)
  next_crl_update = SundialField(null = True)
  last_issued_sn = models.BigIntegerField(default = 1)
  sia_uri = models.TextField(null = True)
  parent_resource_class = models.TextField(null = True)                 # Not sure this should allow NULL
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

  # ca_obj has a zillion properties encoding various specialized
  # ca_detail queries.  ORM query syntax probably renders this OBE,
  # but need to translate in existing code.
  #
  #def pending_ca_details(self):                  return self.ca_details.filter(state = "pending")
  #def active_ca_detail(self):                    return self.ca_details.get(state = "active")
  #def deprecated_ca_details(self):               return self.ca_details.filter(state = "deprecated")
  #def active_or_deprecated_ca_details(self):     return self.ca_details.filter(state__in = ("active", "deprecated"))
  #def revoked_ca_details(self):                  return self.ca_details.filter(state = "revoked")
  #def issue_response_candidate_ca_details(self): return self.ca_details.exclude(state = "revoked")


  def check_for_updates(self, parent, rc, cb, eb):
    """
    Parent has signaled continued existance of a resource class we
    already knew about, so we need to check for an updated
    certificate, changes in resource coverage, revocation and reissue
    with the same key, etc.
    """

    sia_uri = parent.construct_sia_uri(rc)
    sia_uri_changed = self.sia_uri != sia_uri
    if sia_uri_changed:
      logger.debug("SIA changed: was %s now %s", self.sia_uri, sia_uri)
      self.sia_uri = sia_uri
      self.sql_mark_dirty()
    class_name = rc.get("class_name")
    rc_resources = rpki.resource_set.resource_bag(
      rc.get("resource_set_as"),
      rc.get("resource_set_ipv4"),
      rc.get("resource_set_ipv6"),
      rc.get("resource_set_notafter"))
    cert_map = {}
    for c in rc.getiterator(rpki.up_down.tag_certificate):
      x = rpki.x509.X509(Base64 = c.text)
      u = rpki.up_down.multi_uri(c.get("cert_url")).rsync()
      cert_map[x.gSKI()] = (x, u)
    def loop(iterator, ca_detail):
      rc_cert, rc_cert_uri = cert_map.pop(ca_detail.public_key.gSKI(), (None, None))
      if rc_cert is None:
        logger.warning("SKI %s in resource class %s is in database but missing from list_response to %s from %s, "
                       "maybe parent certificate went away?",
                       ca_detail.public_key.gSKI(), class_name, parent.self.self_handle, parent.parent_handle)
        publisher = publication_queue()
        ca_detail.destroy(ca = ca_detail.ca, publisher = publisher)
        return publisher.call_pubd(iterator, eb)
      if ca_detail.state == "active" and ca_detail.ca_cert_uri != rc_cert_uri:
        logger.debug("AIA changed: was %s now %s", ca_detail.ca_cert_uri, rc_cert_uri)
        ca_detail.ca_cert_uri = rc_cert_uri
        ca_detail.save()
      if ca_detail.state not in ("pending", "active"):
        return iterator()
      if ca_detail.state == "pending":
        current_resources = rpki.resource_set.resource_bag()
      else:
        current_resources = ca_detail.latest_ca_cert.get_3779resources()
      if (ca_detail.state == "pending" or
          sia_uri_changed or
          ca_detail.latest_ca_cert != rc_cert or
          ca_detail.latest_ca_cert.getNotAfter() != rc_resources.valid_until or
          current_resources.undersized(rc_resources) or
          current_resources.oversized(rc_resources)):
        return ca_detail.update(
          parent           = parent,
          ca               = self,
          rc               = rc,
          sia_uri_changed  = sia_uri_changed,
          old_resources    = current_resources,
          callback         = iterator,
          errback          = eb)
      iterator()
    def done():
      if cert_map:
        logger.warning("Unknown certificate SKI%s %s in resource class %s in list_response to %s from %s, maybe you want to \"revoke_forgotten\"?",
                       "" if len(cert_map) == 1 else "s", ", ".join(cert_map), class_name, parent.self.self_handle, parent.parent_handle)
      cb()
    ca_details = self.ca_details.exclude(state = "revoked")
    if ca_details:
      rpki.async.iterator(ca_details, loop, done)
    else:
      logger.warning("Existing resource class %s to %s from %s with no certificates, rekeying",
                     class_name, parent.self.self_handle, parent.parent_handle)
      self.rekey(cb, eb)


  # Called from exactly one place, in rpki.rpkid_tasks.PollParentTask.class_loop().
  # Might want to refactor.

  @classmethod
  def create(cls, parent, rc, cb, eb):
    """
    Parent has signaled existance of a new resource class, so we need
    to create and set up a corresponding CA object.
    """

    self = cls.objects.create(parent = parent,
                              parent_resource_class = rc.get("class_name"),
                              sia_uri = parent.construct_sia_uri(rc))
    ca_detail = CADetail.create(self)
    def done(r_msg):
      c = r_msg[0][0]
      logger.debug("CA %r received certificate %s", self, c.get("cert_url"))
      ca_detail.activate(
        ca       = self,
        cert     = rpki.x509.X509(Base64 = c.text),
        uri      = c.get("cert_url"),
        callback = cb,
        errback  = eb)
    logger.debug("Sending issue request to %r from %r", parent, self.create)
    parent.up_down_issue_query(self, ca_detail, done, eb)


  # Was .delete()
  def destroy(self, parent, callback):
    """
    The list of current resource classes received from parent does not
    include the class corresponding to this CA, so we need to delete
    it (and its little dog too...).

    All certs published by this CA are now invalid, so need to
    withdraw them, the CRL, and the manifest from the repository,
    delete all child_cert and ca_detail records associated with this
    CA, then finally delete this CA itself.
    """

    def lose(e):
      logger.exception("Could not delete CA %r, skipping", self)
      callback()
    def done():
      logger.debug("Deleting %r", self)
      self.delete()
      callback()
    publisher = publication_queue()
    for ca_detail in self.ca_details.all():
      ca_detail.destroy(ca = self, publisher = publisher, allow_failure = True)
    publisher.call_pubd(done, lose)


  def next_serial_number(self):
    """
    Allocate a certificate serial number.
    """

    self.last_issued_sn += 1
    self.save()
    return self.last_issued_sn


  def next_manifest_number(self):
    """
    Allocate a manifest serial number.
    """

    self.last_manifest_sn += 1
    self.save()
    return self.last_manifest_sn


  def next_crl_number(self):
    """
    Allocate a CRL serial number.
    """

    self.last_crl_sn += 1
    self.save()
    return self.last_crl_sn


  def rekey(self, cb, eb):
    """
    Initiate a rekey operation for this CA.  Generate a new keypair.
    Request cert from parent using new keypair.  Mark result as our
    active ca_detail.  Reissue all child certs issued by this CA using
    the new ca_detail.
    """

    old_detail = self.ca_details.get(state = "active")
    new_detail = CADetail.create(self)
    def done(r_msg):
      c = r_msg[0][0]
      logger.debug("CA %r received certificate %s", self, c.get("cert_url"))
      new_detail.activate(
        ca          = self,
        cert        = rpki.x509.X509(Base64 = c.text),
        uri         = c.get("cert_url"),
        predecessor = old_detail,
        callback    = cb,
        errback     = eb)
    logger.debug("Sending issue request to %r from %r", self.parent, self.rekey)
    self.parent.up_down_issue_query(self, new_detail, done, eb)


  def revoke(self, cb, eb, revoke_all = False):
    """
    Revoke deprecated ca_detail objects associated with this CA, or
    all ca_details associated with this CA if revoke_all is set.
    """

    def loop(iterator, ca_detail):
      ca_detail.revoke(cb = iterator, eb = eb)
    rpki.async.iterator(self.ca_details.all() if revoke_all else self.ca_details.filter(state = "deprecated"),
                        loop, cb)


  def reissue(self, cb, eb):
    """
    Reissue all current certificates issued by this CA.
    """

    ca_detail = self.ca_details.get(state = "active")
    if ca_detail:
      ca_detail.reissue(cb, eb)
    else:
      cb()


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


  # Like the old ca_obj class, the old ca_detail_obj class had ten
  # zillion properties and methods encapsulating SQL queries.
  # Translate as we go.


  @property
  def crl_uri(self):
    """
    Return publication URI for this ca_detail's CRL.
    """

    return self.ca.sia_uri + self.crl_uri_tail


  @property
  def crl_uri_tail(self):
    """
    Return tail (filename portion) of publication URI for this ca_detail's CRL.
    """

    return self.public_key.gSKI() + ".crl"


  @property
  def manifest_uri(self):
    """
    Return publication URI for this ca_detail's manifest.
    """

    return self.ca.sia_uri + self.public_key.gSKI() + ".mft"


  def has_expired(self):
    """
    Return whether this ca_detail's certificate has expired.
    """

    return self.latest_ca_cert.getNotAfter() <= rpki.sundial.now()


  def covers(self, target):
    """
    Test whether this ca-detail covers a given set of resources.
    """

    assert not target.asn.inherit and not target.v4.inherit and not target.v6.inherit
    me = self.latest_ca_cert.get_3779resources()
    return target.asn <= me.asn and target.v4 <= me.v4 and target.v6  <= me.v6


  def activate(self, ca, cert, uri, callback, errback, predecessor = None):
    """
    Activate this ca_detail.
    """

    publisher = publication_queue()
    self.latest_ca_cert = cert
    self.ca_cert_uri = uri
    self.generate_manifest_cert()
    self.state = "active"
    self.generate_crl(publisher = publisher)
    self.generate_manifest(publisher = publisher)
    self.save()
    if predecessor is not None:
      predecessor.state = "deprecated"
      predecessor.save()
      for child_cert in predecessor.child_certs.all():
        child_cert.reissue(ca_detail = self, publisher = publisher)
      for roa in predecessor.roas.all():
        roa.regenerate(publisher = publisher)
      for ghostbuster in predecessor.ghostbusters.all():
        ghostbuster.regenerate(publisher = publisher)
      predecessor.generate_crl(publisher = publisher)
      predecessor.generate_manifest(publisher = publisher)
    publisher.call_pubd(callback, errback)


  def destroy(self, ca, publisher, allow_failure = False):
    """
    Delete this ca_detail and all of the certs it issued.

    If allow_failure is true, we clean up as much as we can but don't
    raise an exception.
    """

    repository = ca.parent.repository
    handler = False if allow_failure else None
    for child_cert in self.child_certs.all():
      publisher.queue(uri = child_cert.uri, old_obj = child_cert.cert, repository = repository, handler = handler)
      child_cert.delete()
    for roa in self.roas.all():
      roa.revoke(publisher = publisher, allow_failure = allow_failure, fast = True)
    for ghostbuster in self.ghostbusters.all():
      ghostbuster.revoke(publisher = publisher, allow_failure = allow_failure, fast = True)
    if self.latest_manifest is not None:
      publisher.queue(uri = self.manifest_uri, old_obj = self.latest_manifest, repository = repository, handler = handler)
    if self.latest_crl is not None:
      publisher.queue(uri = self.crl_uri, old_obj = self.latest_crl, repository = repository, handler = handler)
    for cert in self.revoked_certs.all():     # + self.child_certs.all()
      logger.debug("Deleting %r", cert)
      cert.delete()
    logger.debug("Deleting %r", self)
    self.delete()

  def revoke(self, cb, eb):
    """
    Request revocation of all certificates whose SKI matches the key
    for this ca_detail.

    Tasks:

    - Request revocation of old keypair by parent.

    - Revoke all child certs issued by the old keypair.

    - Generate a final CRL, signed with the old keypair, listing all
      the revoked certs, with a next CRL time after the last cert or
      CRL signed by the old keypair will have expired.

    - Generate a corresponding final manifest.

    - Destroy old keypairs.

    - Leave final CRL and manifest in place until their nextupdate
      time has passed.
    """

    ca = self.ca
    parent = ca.parent
    class_name = ca.parent_resource_class
    gski = self.latest_ca_cert.gSKI()

    def parent_revoked(r_msg):
      if r_msg[0].get("class_name") != class_name:
        raise rpki.exceptions.ResourceClassMismatch
      if r_msg[0].get("ski") != gski:
        raise rpki.exceptions.SKIMismatch
      logger.debug("Parent revoked %s, starting cleanup", gski)
      crl_interval = rpki.sundial.timedelta(seconds = parent.self.crl_interval)
      nextUpdate = rpki.sundial.now()
      if self.latest_manifest is not None:
        self.latest_manifest.extract_if_needed()
        nextUpdate = nextUpdate.later(self.latest_manifest.getNextUpdate())
      if self.latest_crl is not None:
        nextUpdate = nextUpdate.later(self.latest_crl.getNextUpdate())
      publisher = publication_queue()
      for child_cert in self.child_certs.all():
        nextUpdate = nextUpdate.later(child_cert.cert.getNotAfter())
        child_cert.revoke(publisher = publisher)
      for roa in self.roas.all():
        nextUpdate = nextUpdate.later(roa.cert.getNotAfter())
        roa.revoke(publisher = publisher)
      for ghostbuster in self.ghostbusters.all():
        nextUpdate = nextUpdate.later(ghostbuster.cert.getNotAfter())
        ghostbuster.revoke(publisher = publisher)
      nextUpdate += crl_interval
      self.generate_crl(publisher = publisher, nextUpdate = nextUpdate)
      self.generate_manifest(publisher = publisher, nextUpdate = nextUpdate)
      self.private_key_id = None
      self.manifest_private_key_id = None
      self.manifest_public_key = None
      self.latest_manifest_cert = None
      self.state = "revoked"
      self.save()
      publisher.call_pubd(cb, eb)
    logger.debug("Asking parent to revoke CA certificate %s", gski)
    parent.up_down_revoke_query(class_name, gski, parent_revoked, eb)


  def update(self, parent, ca, rc, sia_uri_changed, old_resources, callback, errback):
    """
    Need to get a new certificate for this ca_detail and perhaps frob
    children of this ca_detail.
    """

    def issued(r_msg):
      c = r_msg[0][0]
      cert = rpki.x509.X509(Base64 = c.text)
      cert_url = c.get("cert_url")
      logger.debug("CA %r received certificate %s", self, cert_url)
      if self.state == "pending":
        return self.activate(ca = ca, cert = cert, uri = cert_url, callback = callback, errback  = errback)
      validity_changed = self.latest_ca_cert is None or self.latest_ca_cert.getNotAfter() != cert.getNotAfter()
      publisher = publication_queue()
      if self.latest_ca_cert != cert:
        self.latest_ca_cert = cert
        self.save()
        self.generate_manifest_cert()
        self.generate_crl(publisher = publisher)
        self.generate_manifest(publisher = publisher)
      new_resources = self.latest_ca_cert.get_3779resources()
      if sia_uri_changed or old_resources.oversized(new_resources):
        for child_cert in self.child_certs.all():
          child_resources = child_cert.cert.get_3779resources()
          if sia_uri_changed or child_resources.oversized(new_resources):
            child_cert.reissue(ca_detail = self, resources = child_resources & new_resources, publisher = publisher)
      if sia_uri_changed or validity_changed or old_resources.oversized(new_resources):
        for roa in self.roas.all():
          roa.update(publisher = publisher, fast = True)
      if sia_uri_changed or validity_changed:
        for ghostbuster in self.ghostbusters.all():
          ghostbuster.update(publisher = publisher, fast = True)
      publisher.call_pubd(callback, errback)
    logger.debug("Sending issue request to %r from %r", parent, self.update)
    parent.up_down_issue_query(ca, self, issued, errback)


  @classmethod
  def create(cls, ca):
    """
    Create a new ca_detail object for a specified CA.
    """

    cer_keypair = rpki.x509.RSA.generate()
    mft_keypair = rpki.x509.RSA.generate()
    return cls.objects.create(ca = ca, state = "pending",
                              private_key_id          = cer_keypair, public_key          = cer_keypair.get_public(),
                              manifest_private_key_id = mft_keypair, manifest_public_key = mft_keypair.get_public())


  def issue_ee(self, ca, resources, subject_key, sia,
               cn = None, sn = None, notAfter = None, eku = None):
    """
    Issue a new EE certificate.
    """

    if notAfter is None:
      notAfter = self.latest_ca_cert.getNotAfter()
    return self.latest_ca_cert.issue(
      keypair     = self.private_key_id,
      subject_key = subject_key,
      serial      = ca.next_serial_number(),
      sia         = sia,
      aia         = self.ca_cert_uri,
      crldp       = self.crl_uri,
      resources   = resources,
      notAfter    = notAfter,
      is_ca       = False,
      cn          = cn,
      sn          = sn,
      eku         = eku)


  def generate_manifest_cert(self):
    """
    Generate a new manifest certificate for this ca_detail.
    """

    resources = rpki.resource_set.resource_bag.from_inheritance()
    self.latest_manifest_cert = self.issue_ee(
      ca          = self.ca,
      resources   = resources,
      subject_key = self.manifest_public_key,
      sia         = (None, None, self.manifest_uri, rpki.publication.rrdp_sia_uri_kludge))


  def issue(self, ca, child, subject_key, sia, resources, publisher, child_cert = None):
    """
    Issue a new certificate to a child.  Optional child_cert argument
    specifies an existing child_cert object to update in place; if not
    specified, we create a new one.  Returns the child_cert object
    containing the newly issued cert.
    """

    self.check_failed_publication(publisher)
    cert = self.latest_ca_cert.issue(
      keypair     = self.private_key_id,
      subject_key = subject_key,
      serial      = ca.next_serial_number(),
      aia         = self.ca_cert_uri,
      crldp       = self.crl_uri,
      sia         = sia,
      resources   = resources,
      notAfter    = resources.valid_until)
    if child_cert is None:
      old_cert = None
      child_cert = ChildCert(child = child, ca_detail = self, cert = cert)
      logger.debug("Created new child_cert %r", child_cert)
    else:
      old_cert = child_cert.cert
      child_cert.cert = cert
      child_cert.ca_detail = self
      logger.debug("Reusing existing child_cert %r", child_cert)
    child_cert.ski = cert.get_SKI()
    child_cert.published = rpki.sundial.now()
    child_cert.save()
    publisher.queue(
      uri = child_cert.uri,
      old_obj = old_cert,
      new_obj = child_cert.cert,
      repository = ca.parent.repository,
      handler = child_cert.published_callback)
    self.generate_manifest(publisher = publisher)
    return child_cert


  def generate_crl(self, publisher, nextUpdate = None):
    """
    Generate a new CRL for this ca_detail.  At the moment this is
    unconditional, that is, it is up to the caller to decide whether a
    new CRL is needed.
    """

    self.check_failed_publication(publisher)
    crl_interval = rpki.sundial.timedelta(seconds = self.ca.parent.self.crl_interval)
    now = rpki.sundial.now()
    if nextUpdate is None:
      nextUpdate = now + crl_interval
    certlist = []
    for revoked_cert in self.revoked_certs.all():
      if now > revoked_cert.expires + crl_interval:
        revoked_cert.delete()
      else:
        certlist.append((revoked_cert.serial, revoked_cert.revoked))
    certlist.sort()
    old_crl = self.latest_crl
    self.latest_crl = rpki.x509.CRL.generate(
      keypair             = self.private_key_id,
      issuer              = self.latest_ca_cert,
      serial              = self.ca.next_crl_number(),
      thisUpdate          = now,
      nextUpdate          = nextUpdate,
      revokedCertificates = certlist)
    self.crl_published = now
    self.save()
    publisher.queue(
      uri        = self.crl_uri,
      old_obj    = old_crl,
      new_obj    = self.latest_crl,
      repository = self.ca.parent.repository,
      handler    = self.crl_published_callback)


  def crl_published_callback(self, pdu):
    """
    Check result of CRL publication.
    """

    rpki.publication.raise_if_error(pdu)
    self.crl_published = None
    self.save()


  def generate_manifest(self, publisher, nextUpdate = None):
    """
    Generate a new manifest for this ca_detail.
    """

    self.check_failed_publication(publisher)

    crl_interval = rpki.sundial.timedelta(seconds = self.ca.parent.self.crl_interval)
    now = rpki.sundial.now()
    uri = self.manifest_uri
    if nextUpdate is None:
      nextUpdate = now + crl_interval
    if (self.latest_manifest_cert is None or
        (self.latest_manifest_cert.getNotAfter() < nextUpdate and
         self.latest_manifest_cert.getNotAfter() < self.latest_ca_cert.getNotAfter())):
      logger.debug("Generating EE certificate for %s", uri)
      self.generate_manifest_cert()
      logger.debug("Latest CA cert notAfter %s, new %s EE notAfter %s",
                   self.latest_ca_cert.getNotAfter(), uri, self.latest_manifest_cert.getNotAfter())
    logger.debug("Constructing manifest object list for %s", uri)
    objs = [(self.crl_uri_tail, self.latest_crl)]
    objs.extend((c.uri_tail, c.cert)        for c in self.child_certs.all())
    objs.extend((r.uri_tail, r.roa)         for r in self.roas.filter(roa__isnull = False))
    objs.extend((g.uri_tail, g.ghostbuster) for g in self.ghostbusters.all())
    objs.extend((e.uri_tail, e.cert)        for e in self.ee_certificates.all())
    logger.debug("Building manifest object %s", uri)
    old_manifest = self.latest_manifest
    self.latest_manifest = rpki.x509.SignedManifest.build(
      serial         = self.ca.next_manifest_number(),
      thisUpdate     = now,
      nextUpdate     = nextUpdate,
      names_and_objs = objs,
      keypair        = self.manifest_private_key_id,
      certs          = self.latest_manifest_cert)
    logger.debug("Manifest generation took %s", rpki.sundial.now() - now)
    self.manifest_published = now
    self.save()
    publisher.queue(uri = uri,
                    old_obj = old_manifest,
                    new_obj = self.latest_manifest,
                    repository = self.ca.parent.repository,
                    handler = self.manifest_published_callback)


  def manifest_published_callback(self, pdu):
    """
    Check result of manifest publication.
    """

    rpki.publication.raise_if_error(pdu)
    self.manifest_published = None
    self.save()


  def reissue(self, cb, eb):
    """
    Reissue all current certificates issued by this ca_detail.
    """

    publisher = publication_queue()
    self.check_failed_publication(publisher)
    for roa in self.roas.all():
      roa.regenerate(publisher, fast = True)
    for ghostbuster in self.ghostbusters.all():
      ghostbuster.regenerate(publisher, fast = True)
    for ee_certificate in self.ee_certificates.all():
      ee_certificate.reissue(publisher, force = True)
    for child_cert in self.child_certs.all():
      child_cert.reissue(self, publisher, force = True)
    self.generate_manifest_cert()
    self.save()
    self.generate_crl(publisher = publisher)
    self.generate_manifest(publisher = publisher)
    self.save()
    publisher.call_pubd(cb, eb)


  def check_failed_publication(self, publisher, check_all = True):
    """
    Check for failed publication of objects issued by this ca_detail.

    All publishable objects have timestamp fields recording time of
    last attempted publication, and callback methods which clear these
    timestamps once publication has succeeded.  Our task here is to
    look for objects issued by this ca_detail which have timestamps
    set (indicating that they have not been published) and for which
    the timestamps are not very recent (for some definition of very
    recent -- intent is to allow a bit of slack in case pubd is just
    being slow).  In such cases, we want to retry publication.

    As an optimization, we can probably skip checking other products
    if manifest and CRL have been published, thus saving ourselves
    several complex SQL queries.  Not sure yet whether this
    optimization is worthwhile.

    For the moment we check everything without optimization, because
    it simplifies testing.

    For the moment our definition of staleness is hardwired; this
    should become configurable.
    """

    logger.debug("Checking for failed publication for %r", self)

    stale = rpki.sundial.now() - rpki.sundial.timedelta(seconds = 60)
    repository = self.ca.parent.repository
    if self.latest_crl is not None and self.crl_published is not None and self.crl_published < stale:
      logger.debug("Retrying publication for %s", self.crl_uri)
      publisher.queue(uri = self.crl_uri,
                      new_obj = self.latest_crl,
                      repository = repository,
                      handler = self.crl_published_callback)
    if self.latest_manifest is not None and self.manifest_published is not None and self.manifest_published < stale:
      logger.debug("Retrying publication for %s", self.manifest_uri)
      publisher.queue(uri = self.manifest_uri,
                      new_obj = self.latest_manifest,
                      repository = repository,
                      handler = self.manifest_published_callback)
    if not check_all:
      return
    for child_cert in self.child_certs.filter(published__isnull = False, published__lt = stale):
      logger.debug("Retrying publication for %s", child_cert)
      publisher.queue(
        uri = child_cert.uri,
        new_obj = child_cert.cert,
        repository = repository,
        handler = child_cert.published_callback)
    for roa in self.roas.filter(published__isnull = False, published__lt = stale):
      logger.debug("Retrying publication for %s", roa)
      publisher.queue(
        uri = roa.uri,
        new_obj = roa.roa,
        repository = repository,
        handler = roa.published_callback)
    for ghostbuster in self.ghostbusters.filter(published__isnull = False, published__lt = stale):
      logger.debug("Retrying publication for %s", ghostbuster)
      publisher.queue(
        uri = ghostbuster.uri,
        new_obj = ghostbuster.ghostbuster,
        repository = repository,
        handler = ghostbuster.published_callback)
    for ee_cert in self.ee_certs.filter(published__isnull = False, published__lt = stale):
      logger.debug("Retrying publication for %s", ee_cert)
      publisher.queue(
        uri = ee_cert.uri,
        new_obj = ee_cert.cert,
        repository = repository,
        handler = ee_cert.published_callback)


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


  @property
  def uri_tail(self):
    """
    Return the tail (filename) portion of the URI for this child_cert.
    """

    return self.cert.gSKI() + ".cer"


  @property
  def uri(self):
    """
    Return the publication URI for this child_cert.
    """

    return self.ca_detail.ca.sia_uri + self.uri_tail


  def revoke(self, publisher, generate_crl_and_manifest = True):
    """
    Revoke a child cert.
    """

    ca_detail = self.ca_detail
    logger.debug("Revoking %r %r", self, self.uri)
    RevokedCert.revoke(cert = self.cert, ca_detail = ca_detail)
    publisher.queue(uri = self.uri, old_obj = self.cert, repository = ca_detail.ca.parent.repository)
    self.delete()
    if generate_crl_and_manifest:
      ca_detail.generate_crl(publisher = publisher)
      ca_detail.generate_manifest(publisher = publisher)


  def reissue(self, ca_detail, publisher, resources = None, sia = None, force = False):
    """
    Reissue an existing child cert, reusing the public key.  If the
    child cert we would generate is identical to the one we already
    have, we just return the one we already have.  If we have to
    revoke the old child cert when generating the new one, we have to
    generate a new child_cert_obj, so calling code that needs the
    updated child_cert_obj must use the return value from this method.
    """

    ca = ca_detail.ca
    child = self.child
    old_resources = self.cert.get_3779resources()
    old_sia       = self.cert.get_SIA()
    old_aia       = self.cert.get_AIA()[0]
    old_ca_detail = self.ca_detail
    needed = False
    if resources is None:
      resources = old_resources
    if sia is None:
      sia = old_sia
    assert resources.valid_until is not None and old_resources.valid_until is not None
    if resources.asn != old_resources.asn or resources.v4 != old_resources.v4 or resources.v6 != old_resources.v6:
      logger.debug("Resources changed for %r: old %s new %s", self, old_resources, resources)
      needed = True
    if resources.valid_until != old_resources.valid_until:
      logger.debug("Validity changed for %r: old %s new %s",
                   self, old_resources.valid_until, resources.valid_until)
      needed = True
    if sia != old_sia:
      logger.debug("SIA changed for %r: old %r new %r", self, old_sia, sia)
      needed = True
    if ca_detail != old_ca_detail:
      logger.debug("Issuer changed for %r: old %r new %r", self, old_ca_detail, ca_detail)
      needed = True
    if ca_detail.ca_cert_uri != old_aia:
      logger.debug("AIA changed for %r: old %r new %r", self, old_aia, ca_detail.ca_cert_uri)
      needed = True
    must_revoke = old_resources.oversized(resources) or old_resources.valid_until > resources.valid_until
    if must_revoke:
      logger.debug("Must revoke any existing cert(s) for %r", self)
      needed = True
    if not needed and force:
      logger.debug("No change needed for %r, forcing reissuance anyway", self)
      needed = True
    if not needed:
      logger.debug("No change to %r", self)
      return self
    if must_revoke:
      for x in child.child_certs.filter(ca_detail = ca_detail, ski = self.ski):
        logger.debug("Revoking child_cert %r", x)
        x.revoke(publisher = publisher)
      ca_detail.generate_crl(publisher = publisher)
      ca_detail.generate_manifest(publisher = publisher)
    child_cert = ca_detail.issue(
      ca          = ca,
      child       = child,
      subject_key = self.cert.getPublicKey(),
      sia         = sia,
      resources   = resources,
      child_cert  = None if must_revoke else self,
      publisher   = publisher)
    logger.debug("New child_cert %r uri %s", child_cert, child_cert.uri)
    return child_cert


  def published_callback(self, pdu):
    """
    Publication callback: check result and mark published.
    """

    rpki.publication.raise_if_error(pdu)
    self.published = None
    self.save()


class EECert(models.Model):
  ski = BlobField()
  cert = CertificateField()
  published = SundialField(null = True)
  self = models.ForeignKey(Self, related_name = "ee_certs")
  ca_detail = models.ForeignKey(CADetail, related_name = "ee_certs")


  @property
  def gski(self):
    """
    Calculate g(SKI), for ease of comparison with XML.

    Although, really, one has to ask why we don't just store g(SKI)
    in rpkid.sql instead of ski....
    """

    return base64.urlsafe_b64encode(self.ski).rstrip("=")

  @gski.setter
  def gski(self, val):
    self.ski = base64.urlsafe_b64decode(val + ("=" * ((4 - len(val)) % 4)))


  @property
  def uri(self):
    """
    Return the publication URI for this ee_cert_obj.
    """

    return self.ca_detail.ca.sia_uri + self.uri_tail


  @property
  def uri_tail(self):
    """
    Return the tail (filename portion) of the publication URI for this
    ee_cert_obj.
    """

    return self.cert.gSKI() + ".cer"


  @classmethod
  def create(cls, ca_detail, subject_name, subject_key, resources, publisher, eku = None):
    """
    Generate a new EE certificate.
    """

    cn, sn = subject_name.extract_cn_and_sn()
    ca = ca_detail.ca
    sia = (None, None, ca_detail.ca.sia_uri + subject_key.gSKI() + ".cer", rpki.publication.rrdp_sia_uri_kludge)
    cert = ca_detail.issue_ee(
      ca          = ca_detail.ca,
      subject_key = subject_key,
      sia         = sia,
      resources   = resources,
      notAfter    = resources.valid_until,
      cn          = cn,
      sn          = sn,
      eku         = eku)
    self = cls(self = ca_detail.ca.parent.self, ca_detail_id = ca_detail.ca_detail_id, cert = cert)
    publisher.queue(
      uri        = self.uri,
      new_obj    = self.cert,
      repository = ca_detail.ca.parent.repository,
      handler    = self.published_callback)
    self.save()
    ca_detail.generate_manifest(publisher = publisher)
    logger.debug("New ee_cert %r", self)
    return self


  def revoke(self, publisher, generate_crl_and_manifest = True):
    """
    Revoke and withdraw an EE certificate.
    """

    ca_detail = self.ca_detail
    logger.debug("Revoking %r %r", self, self.uri)
    RevokedCert.revoke(cert = self.cert, ca_detail = ca_detail)
    publisher.queue(uri = self.uri, old_obj = self.cert, repository = ca_detail.ca.parent.repository)
    self.delete()
    if generate_crl_and_manifest:
      ca_detail.generate_crl(publisher = publisher)
      ca_detail.generate_manifest(publisher = publisher)


  def reissue(self, publisher, ca_detail = None, resources = None, force = False):
    """
    Reissue an existing EE cert, reusing the public key.  If the EE
    cert we would generate is identical to the one we already have, we
    just return; if we need to reissue, we reuse this ee_cert_obj and
    just update its contents, as the publication URI will not have
    changed.
    """

    needed = False
    old_cert = self.cert
    old_ca_detail = self.ca_detail
    if ca_detail is None:
      ca_detail = old_ca_detail
    assert ca_detail.ca is old_ca_detail.ca
    old_resources = old_cert.get_3779resources()
    if resources is None:
      resources = old_resources
    assert resources.valid_until is not None and old_resources.valid_until is not None
    assert ca_detail.covers(resources)
    if ca_detail != self.ca_detail:
      logger.debug("ca_detail changed for %r: old %r new %r", self, self.ca_detail, ca_detail)
      needed = True
    if ca_detail.ca_cert_uri != old_cert.get_AIA()[0]:
      logger.debug("AIA changed for %r: old %s new %s", self, old_cert.get_AIA()[0], ca_detail.ca_cert_uri)
      needed = True
    if resources.valid_until != old_resources.valid_until:
      logger.debug("Validity changed for %r: old %s new %s", self, old_resources.valid_until, resources.valid_until)
      needed = True
    if resources.asn != old_resources.asn or resources.v4 != old_resources.v4 or resources.v6 != old_resources.v6:
      logger.debug("Resources changed for %r: old %s new %s", self, old_resources, resources)
      needed = True
    must_revoke = old_resources.oversized(resources) or old_resources.valid_until > resources.valid_until
    if must_revoke:
      logger.debug("Must revoke existing cert(s) for %r", self)
      needed = True
    if not needed and force:
      logger.debug("No change needed for %r, forcing reissuance anyway", self)
      needed = True
    if not needed:
      logger.debug("No change to %r", self)
      return
    cn, sn = self.cert.getSubject().extract_cn_and_sn()
    self.cert = ca_detail.issue_ee(
      ca          = ca_detail.ca,
      subject_key = self.cert.getPublicKey(),
      eku         = self.cert.get_EKU(),
      sia         = (None, None, self.uri, rpki.publication.rrdp_sia_uri_kludge),
      resources   = resources,
      notAfter    = resources.valid_until,
      cn          = cn,
      sn          = sn)
    self.save()
    publisher.queue(
      uri = self.uri,
      old_obj = old_cert,
      new_obj = self.cert,
      repository = ca_detail.ca.parent.repository,
      handler = self.published_callback)
    if must_revoke:
      RevokedCert.revoke(cert = old_cert.cert, ca_detail = old_ca_detail)
      ca_detail.generate_crl(publisher = publisher)
    ca_detail.generate_manifest(publisher = publisher)


  def published_callback(self, pdu):
    """
    Publication callback: check result and mark published.
    """

    rpki.publication.raise_if_error(pdu)
    self.published = None
    self.save()



class Ghostbuster(models.Model):
  vcard = models.TextField()
  cert = CertificateField()
  ghostbuster = GhostbusterField()
  published = SundialField(null = True)
  self = models.ForeignKey(Self, related_name = "ghostbusters")
  ca_detail = models.ForeignKey(CADetail, related_name = "ghostbusters")


  def update(self, publisher, fast = False):
    """
    Bring this ghostbuster_obj up to date if necesssary.
    """

    if self.ghostbuster is None:
      logger.debug("Ghostbuster record doesn't exist, generating")
      return self.generate(publisher = publisher, fast = fast)

    now = rpki.sundial.now()
    regen_time = self.cert.getNotAfter() - rpki.sundial.timedelta(seconds = self.self.regen_margin)

    if now > regen_time and self.cert.getNotAfter() < self.ca_detail.latest_ca_cert.getNotAfter():
      logger.debug("%r past threshold %s, regenerating", self, regen_time)
      return self.regenerate(publisher = publisher, fast = fast)

    if now > regen_time:
      logger.warning("%r is past threshold %s but so is issuer %r, can't regenerate", self, regen_time, self.ca_detail)

    if self.cert.get_AIA()[0] != self.ca_detail.ca_cert_uri:
      logger.debug("%r AIA changed, regenerating", self)
      return self.regenerate(publisher = publisher, fast = fast)


  def generate(self, publisher, fast = False):
    """
    Generate a Ghostbuster record

    Once we have the right covering certificate, we generate the
    ghostbuster payload, generate a new EE certificate, use the EE
    certificate to sign the ghostbuster payload, publish the result,
    then throw away the private key for the EE cert.  This is modeled
    after the way we handle ROAs.

    If fast is set, we leave generating the new manifest for our
    caller to handle, presumably at the end of a bulk operation.
    """

    resources = rpki.resource_set.resource_bag.from_inheritance()
    keypair = rpki.x509.RSA.generate()
    self.cert = self.ca_detail.issue_ee(
      ca          = self.ca_detail.ca,
      resources   = resources,
      subject_key = keypair.get_public(),
      sia         = (None, None, self.uri_from_key(keypair), rpki.publication.rrdp_sia_uri_kludge))
    self.ghostbuster = rpki.x509.Ghostbuster.build(self.vcard, keypair, (self.cert,))
    self.published = rpki.sundial.now()
    self.save()
    logger.debug("Generating Ghostbuster record %r", self.uri)
    publisher.queue(
      uri = self.uri,
      new_obj = self.ghostbuster,
      repository = self.ca_detail.ca.parent.repository,
      handler = self.published_callback)
    if not fast:
      self.ca_detail.generate_manifest(publisher = publisher)


  def published_callback(self, pdu):
    """
    Check publication result.
    """

    rpki.publication.raise_if_error(pdu)
    self.published = None
    self.save()


  def revoke(self, publisher, regenerate = False, allow_failure = False, fast = False):
    """
    Withdraw Ghostbuster associated with this ghostbuster_obj.

    In order to preserve make-before-break properties without
    duplicating code, this method also handles generating a
    replacement ghostbuster when requested.

    If allow_failure is set, failing to withdraw the ghostbuster will not be
    considered an error.

    If fast is set, SQL actions will be deferred, on the assumption
    that our caller will handle regenerating CRL and manifest and
    flushing the SQL cache.
    """

    ca_detail = self.ca_detail
    logger.debug("%s %r, ca_detail %r state is %s",
                 "Regenerating" if regenerate else "Not regenerating",
                 self, ca_detail, ca_detail.state)
    if regenerate:
      self.generate(publisher = publisher, fast = fast)
    logger.debug("Withdrawing %r %s and revoking its EE cert", self, self.uri)
    RevokedCert.revoke(cert = self.cert, ca_detail = ca_detail)
    publisher.queue(uri = self.uri,
                    old_obj = self.ghostbuster,
                    repository = ca_detail.ca.parent.repository,
                    handler = False if allow_failure else None)
    if not regenerate:
      self.delete()
    if not fast:
      ca_detail.generate_crl(publisher = publisher)
      ca_detail.generate_manifest(publisher = publisher)


  def regenerate(self, publisher, fast = False):
    """
    Reissue Ghostbuster associated with this ghostbuster_obj.
    """

    if self.ghostbuster is None:
      self.generate(publisher = publisher, fast = fast)
    else:
      self.revoke(publisher = publisher, regenerate = True, fast = fast)


  def uri_from_key(self, key):
    """
    Return publication URI for a public key.
    """

    return self.ca_detail.ca.sia_uri + key.gSKI() + ".gbr"


  @property
  def uri(self):
    """
    Return the publication URI for this ghostbuster_obj's ghostbuster.
    """

    return self.ca_detail.ca.sia_uri + self.uri_tail


  @property
  def uri_tail(self):
    """
    Return the tail (filename portion) of the publication URI for this
    ghostbuster_obj's ghostbuster.
    """

    return self.cert.gSKI() + ".gbr"


class RevokedCert(models.Model):
  serial = models.BigIntegerField()
  revoked = SundialField()
  expires = SundialField()
  ca_detail = models.ForeignKey(CADetail, related_name = "revoked_certs")

  @classmethod
  def revoke(cls, cert, ca_detail):
    """
    Revoke a certificate.
    """

    return cls.objects.create(
      serial    = cert.getSerial(),
      expires   = cert.getNotAfter(),
      revoked   = rpki.sundial.now(),
      ca_detail = ca_detail)


class ROA(models.Model):
  asn = models.BigIntegerField()
  ipv4 = models.TextField(null = True)
  ipv6 = models.TextField(null = True)
  cert = CertificateField()
  roa = ROAField()
  published = SundialField(null = True)
  self = models.ForeignKey(Self, related_name = "roas")
  ca_detail = models.ForeignKey(CADetail, related_name = "roas")


  def update(self, publisher, fast = False):
    """
    Bring ROA up to date if necesssary.
    """

    if self.roa is None:
      logger.debug("%r doesn't exist, generating", self)
      return self.generate(publisher = publisher, fast = fast)

    if self.ca_detail is None:
      logger.debug("%r has no associated ca_detail, generating", self)
      return self.generate(publisher = publisher, fast = fast)

    if self.ca_detail.state != "active":
      logger.debug("ca_detail associated with %r not active (state %s), regenerating", self, self.ca_detail.state)
      return self.regenerate(publisher = publisher, fast = fast)

    now = rpki.sundial.now()
    regen_time = self.cert.getNotAfter() - rpki.sundial.timedelta(seconds = self.self.regen_margin)

    if now > regen_time and self.cert.getNotAfter() < self.ca_detail.latest_ca_cert.getNotAfter():
      logger.debug("%r past threshold %s, regenerating", self, regen_time)
      return self.regenerate(publisher = publisher, fast = fast)

    if now > regen_time:
      logger.warning("%r is past threshold %s but so is issuer %r, can't regenerate", self, regen_time, self.ca_detail)

    ca_resources = self.ca_detail.latest_ca_cert.get_3779resources()
    ee_resources = self.cert.get_3779resources()

    if ee_resources.oversized(ca_resources):
      logger.debug("%r oversized with respect to CA, regenerating", self)
      return self.regenerate(publisher = publisher, fast = fast)

    v4 = rpki.resource_set.resource_set_ipv4(self.ipv4)
    v6 = rpki.resource_set.resource_set_ipv6(self.ipv6)

    if ee_resources.v4 != v4 or ee_resources.v6 != v6:
      logger.debug("%r resources do not match EE, regenerating", self)
      return self.regenerate(publisher = publisher, fast = fast)

    if self.cert.get_AIA()[0] != self.ca_detail.ca_cert_uri:
      logger.debug("%r AIA changed, regenerating", self)
      return self.regenerate(publisher = publisher, fast = fast)


  def generate(self, publisher, fast = False):
    """
    Generate a ROA.

    At present we have no way of performing a direct lookup from a
    desired set of resources to a covering certificate, so we have to
    search.  This could be quite slow if we have a lot of active
    ca_detail objects.  Punt on the issue for now, revisit if
    profiling shows this as a hotspot.

    Once we have the right covering certificate, we generate the ROA
    payload, generate a new EE certificate, use the EE certificate to
    sign the ROA payload, publish the result, then throw away the
    private key for the EE cert, all per the ROA specification.  This
    implies that generating a lot of ROAs will tend to thrash
    /dev/random, but there is not much we can do about that.

    If fast is set, we leave generating the new manifest for our
    caller to handle, presumably at the end of a bulk operation.
    """

    if self.ipv4 is None and self.ipv6 is None:
      raise rpki.exceptions.EmptyROAPrefixList

    v4 = rpki.resource_set.resource_set_ipv4(self.ipv4)
    v6 = rpki.resource_set.resource_set_ipv6(self.ipv6)

    if self.ca_detail is not None and self.ca_detail.state == "active" and not self.ca_detail.has_expired():
      logger.debug("Keeping old ca_detail %r for ROA %r", ca_detail, self)
    else:
      logger.debug("Searching for new ca_detail for ROA %r", self)
      for ca_detail in CADetail.objects.filter(ca__parent__self = self.self, state = "active"):
        resources = ca_detail.latest_ca_cert.get_3779resources()
        if not ca_detail.has_expired() and v4.issubset(resources.v4) and v6.issubset(resources.v6):
          break
      else:
        raise rpki.exceptions.NoCoveringCertForROA("Could not find a certificate covering %r" % self)
      logger.debug("Using new ca_detail %r for ROA %r", ca_detail, self)
      self.ca_detail = ca_detail

    resources = rpki.resource_set.resource_bag(v4 = v4, v6 = v6)
    keypair = rpki.x509.RSA.generate()

    self.cert = self.ca_detail.issue_ee(
      ca          = self.ca_detail.ca,
      resources   = resources,
      subject_key = keypair.get_public(),
      sia         = (None, None, self.uri_from_key(keypair), rpki.publication.rrdp_sia_uri_kludge))
    self.roa = rpki.x509.ROA.build(self.asn, self.ipv4, self.ipv6, keypair, (self.cert,))
    self.published = rpki.sundial.now()
    self.save()

    logger.debug("Generating %r URI %s", self, self.uri)
    publisher.queue(uri = self.uri, new_obj = self.roa,
                    repository = self.ca_detail.ca.parent.repository,
                    handler = self.published_callback)
    if not fast:
      ca_detail.generate_manifest(publisher = publisher)


  def published_callback(self, pdu):
    """
    Check publication result.
    """

    rpki.publication.raise_if_error(pdu)
    self.published = None
    self.save()


  def revoke(self, publisher, regenerate = False, allow_failure = False, fast = False):
    """
    Withdraw ROA associated with this roa_obj.

    In order to preserve make-before-break properties without
    duplicating code, this method also handles generating a
    replacement ROA when requested.

    If allow_failure is set, failing to withdraw the ROA will not be
    considered an error.

    If fast is set, SQL actions will be deferred, on the assumption
    that our caller will handle regenerating CRL and manifest and
    flushing the SQL cache.
    """

    ca_detail = self.ca_detail
    logger.debug("%s %r, ca_detail %r state is %s",
                 "Regenerating" if regenerate else "Not regenerating",
                 self, ca_detail, ca_detail.state)
    if regenerate:
      self.generate(publisher = publisher, fast = fast)
    logger.debug("Withdrawing %r %s and revoking its EE cert", self, self.uri)
    RevokedCert.revoke(cert = self.cert, ca_detail = ca_detail)
    publisher.queue(uri = self.uri, old_obj = self.roa,
                    repository = ca_detail.ca.parent.repository,
                    handler = False if allow_failure else None)
    if not regenerate:
      self.delete()
    if not fast:
      ca_detail.generate_crl(publisher = publisher)
      ca_detail.generate_manifest(publisher = publisher)


  def regenerate(self, publisher, fast = False):
    """
    Reissue ROA associated with this roa_obj.
    """

    if self.ca_detail is None:
      self.generate(publisher = publisher, fast = fast)
    else:
      self.revoke(publisher = publisher, regenerate = True, fast = fast)


  def uri_from_key(self, key):
    """
    Return publication URI for a public key.
    """

    return self.ca_detail.ca.sia_uri + key.gSKI() + ".roa"


  @property
  def uri(self):
    """
    Return the publication URI for this roa_obj's ROA.
    """

    return self.ca_detail.ca.sia_uri + self.uri_tail


  @property
  def uri_tail(self):
    """
    Return the tail (filename portion) of the publication URI for this
    roa_obj's ROA.
    """

    return self.cert.gSKI() + ".roa"
