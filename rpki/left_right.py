# $Id$
#
# Copyright (C) 2013--2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2009--2012  Internet Systems Consortium ("ISC")
# Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL, ISC, AND ARIN DISCLAIM ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL DRL,
# ISC, OR ARIN BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
# OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
RPKI "left-right" protocol.
"""

import base64
import logging
import collections

import rpki.x509
import rpki.sql
import rpki.exceptions
import rpki.http
import rpki.up_down
import rpki.relaxng
import rpki.sundial
import rpki.log
import rpki.publication
import rpki.async
import rpki.rpkid_tasks

from lxml.etree import Element, SubElement, tostring as ElementToString

logger = logging.getLogger(__name__)


xmlns   = rpki.relaxng.left_right.xmlns
nsmap   = rpki.relaxng.left_right.nsmap
version = rpki.relaxng.left_right.version

tag_bpki_cert                    = xmlns + "bpki_cert"
tag_bpki_glue                    = xmlns + "bpki_glue"
tag_bsc                          = xmlns + "bsc"
tag_child                        = xmlns + "child"
tag_list_ee_certificate_requests = xmlns + "list_ee_certificate_requests"
tag_list_ghostbuster_requests    = xmlns + "list_ghostbuster_requests"
tag_list_published_objects       = xmlns + "list_published_objects"
tag_list_received_resources      = xmlns + "list_received_resources"
tag_list_resources               = xmlns + "list_resources"
tag_list_roa_requests            = xmlns + "list_roa_requests"
tag_msg                          = xmlns + "msg"
tag_parent                       = xmlns + "parent"
tag_pkcs10                       = xmlns + "pkcs10"
tag_pkcs10_request               = xmlns + "pkcs10_request"
tag_report_error                 = xmlns + "report_error"
tag_repository                   = xmlns + "repository"
tag_self                         = xmlns + "self"
tag_signing_cert                 = xmlns + "signing_cert"
tag_signing_cert_crl             = xmlns + "signing_cert_crl"


## @var enforce_strict_up_down_xml_sender
# Enforce strict checking of XML "sender" field in up-down protocol

enforce_strict_up_down_xml_sender = False


class base_elt(rpki.sql.sql_persistent):
  """
  Virtual class for persistent left-right protocol elements.
  These classes are being phased out in favor of Django ORM models.
  """

  handles = ()
  attributes = ()
  elements = ()
  booleans = ()

  self_id = None
  self_handle = None

  def __str__(self):
    return ElementToString(self.toXML(), pretty_print = True, encoding = "us-ascii")

  @classmethod
  def fromXML(cls, elt):
    self = cls()
    for key in self.attributes:
      val = elt.get(key, None)
      if val is not None:
        val = val.encode("ascii")
        if isinstance(self.attributes, dict) and self.attributes[key] is not None:
          val = self.attributes[key](val)
        elif val.isdigit() and not key.endswith("_handle"):
          val = long(val)
      setattr(self, key, val)
    for key in self.booleans:
      setattr(self, key, elt.get(key, False))
    for b64 in elt:
      assert b64.tag.startswith(xmlns)
      setattr(self, b64.tag[len(xmlns):], self.elements[b64.tag](Base64 = b64.text))
    return self

  def toXML(self):
    elt = Element(self.element_name, nsmap = nsmap)
    for key in self.attributes:
      val = getattr(self, key, None)
      if val is not None:
        elt.set(key, str(val))
    for key in self.booleans:
      if getattr(self, key, False):
        elt.set(key, "yes")
    for name in self.elements:
      value = getattr(self, name[len(xmlns):], None)
      if value is not None and not value.empty():
        SubElement(elt, name, nsmap = nsmap).text = value.get_Base64()
    return elt

  def make_reply(self, r_pdu = None):
    if r_pdu is None:
      r_pdu = self.__class__()
      self.make_reply_clone_hook(r_pdu)
      handle_name = self.element_name[len(xmlns):] + "_handle"
      setattr(r_pdu, handle_name, getattr(self, handle_name, None))
    else:
      self.make_reply_clone_hook(r_pdu)
      for b in r_pdu.booleans:
        setattr(r_pdu, b, False)
    r_pdu.action = self.action
    r_pdu.tag = self.tag
    return r_pdu

  def serve_fetch_one(self):
    """
    Find the object on which a get, set, or destroy method should
    operate.
    """

    r = self.serve_fetch_one_maybe()
    if r is None:
      raise rpki.exceptions.NotFound
    return r

  def serve_post_save_hook(self, q_pdu, r_pdu, cb, eb):
    cb()

  def serve_create(self, r_msg, cb, eb):
    r_pdu = self.make_reply()
    def one():
      self.sql_store()
      setattr(r_pdu, self.sql_template.index, getattr(self, self.sql_template.index))
      self.serve_post_save_hook(self, r_pdu, two, eb)
    def two():
      r_msg.append(r_pdu)
      cb()
    oops = self.serve_fetch_one_maybe()
    if oops is not None:
      raise rpki.exceptions.DuplicateObject("Object already exists: %r[%r] %r[%r]" % (
        self, getattr(self, self.element_name[len(xmlns):] + "_handle"),
        oops, getattr(oops, oops.element_name[len(xmlns):] + "_handle")))
    self.serve_pre_save_hook(self, r_pdu, one, eb)

  def serve_set(self, r_msg, cb, eb):
    db_pdu = self.serve_fetch_one()
    r_pdu = self.make_reply()
    for a in db_pdu.sql_template.columns[1:]:
      v = getattr(self, a, None)
      if v is not None:
        setattr(db_pdu, a, v)
    db_pdu.sql_mark_dirty()
    def one():
      db_pdu.sql_store()
      db_pdu.serve_post_save_hook(self, r_pdu, two, eb)
    def two():
      r_msg.append(r_pdu)
      cb()
    db_pdu.serve_pre_save_hook(self, r_pdu, one, eb)

  def serve_get(self, r_msg, cb, eb):
    r_pdu = self.serve_fetch_one()
    self.make_reply(r_pdu)
    r_msg.append(r_pdu)
    cb()

  def serve_list(self, r_msg, cb, eb):
    for r_pdu in self.serve_fetch_all():
      self.make_reply(r_pdu)
      r_msg.append(r_pdu)
    cb()

  def serve_destroy_hook(self, cb, eb):
    cb()

  def serve_destroy(self, r_msg, cb, eb):
    def done():
      db_pdu.sql_delete()
      r_msg.append(self.make_reply())
      cb()
    db_pdu = self.serve_fetch_one()
    db_pdu.serve_destroy_hook(done, eb)

  def serve_dispatch(self, r_msg, cb, eb):
    # Transition hack: handle the .toXML() call for old handlers.
    fake_r_msg = []
    def fake_convert():
      r_msg.extend(r_pdu.toXML() if isinstance(r_pdu, base_elt) else r_pdu
                   for r_pdu in fake_r_msg)
    def fake_cb():
      fake_convert()
      cb()
    def fake_eb(e):
      fake_convert()
      eb(e)
    method = getattr(self, "serve_" + self.action, None)
    if method is None:
      raise rpki.exceptions.BadQuery("Unexpected query: action %s" % self.action)
    method(fake_r_msg, fake_cb, fake_eb)

  def unimplemented_control(self, *controls):
    unimplemented = [x for x in controls if getattr(self, x, False)]
    if unimplemented:
      raise rpki.exceptions.NotImplementedYet("Unimplemented control %s" % ", ".join(unimplemented))

  @property
  @rpki.sql.cache_reference
  def self(self):
    return self_elt.sql_fetch(self.gctx, self.self_id)

  @property
  @rpki.sql.cache_reference
  def bsc(self):
    return bsc_elt.sql_fetch(self.gctx, self.bsc_id)

  def make_reply_clone_hook(self, r_pdu):
    if r_pdu.self_handle is None:
      r_pdu.self_handle = self.self_handle
    for tag, elt in self.handles:
      id_name = tag + "_id"
      handle_name = tag + "_handle"
      if getattr(r_pdu, handle_name, None) is None:
        try:
          setattr(r_pdu, handle_name, getattr(elt.sql_fetch(self.gctx, getattr(r_pdu, id_name)), handle_name))
        except AttributeError:
          continue

  @classmethod
  def serve_fetch_handle(cls, gctx, self_id, handle):
    name = cls.element_name[len(xmlns):]
    return cls.sql_fetch_where1(gctx, name + "_handle = %s AND self_id = %s", (handle, self_id))

  def serve_fetch_one_maybe(self):
    name = self.element_name[len(xmlns):]
    where = "%s.%s_handle = %%s AND %s.self_id = self.self_id AND self.self_handle = %%s" % (name, name, name)
    args = (getattr(self, name + "_handle"), self.self_handle)
    logger.debug(".serve_fetch_one_maybe() %s %s", args[0], args[1])
    return self.sql_fetch_where1(self.gctx, where, args, "self")

  def serve_fetch_all(self):
    name = self.element_name[len(xmlns):]
    where = "%s.self_id = self.self_id and self.self_handle = %%s" % name
    return self.sql_fetch_where(self.gctx, where, (self.self_handle,), "self")

  def serve_pre_save_hook(self, q_pdu, r_pdu, cb, eb):
    # self is always the object to be saved to SQL.
    for tag, elt in self.handles:
      id_name = tag + "_id"
      if getattr(self, id_name, None) is None:
        x = elt.serve_fetch_handle(self.gctx, self.self_id, getattr(q_pdu, tag + "_handle"))
        if x is None:
          raise rpki.exceptions.HandleTranslationError("Could not translate %r %s_handle" % (self, tag))
        setattr(self, id_name, getattr(x, id_name))
    cb()


class self_elt(base_elt):
  """
  <self/> element.
  """

  element_name = xmlns + "self"
  attributes = ("action", "tag", "self_handle", "crl_interval", "regen_margin")
  booleans = ("rekey", "reissue", "revoke", "run_now", "publish_world_now", "revoke_forgotten",
              "clear_replay_protection")

  elements = collections.OrderedDict((
    (tag_bpki_cert, rpki.x509.X509),
    (tag_bpki_glue, rpki.x509.X509)))

  sql_template = rpki.sql.template(
    "self",
    "self_id",
    "self_handle",
    "use_hsm",
    "crl_interval",
    "regen_margin",
    ("bpki_cert", rpki.x509.X509),
    ("bpki_glue", rpki.x509.X509))

  handles = ()

  use_hsm = False
  crl_interval = None
  regen_margin = None
  bpki_cert = None
  bpki_glue = None
  cron_tasks = None

  def __repr__(self):
    return rpki.log.log_repr(self)

  @property
  def bscs(self):
    return bsc_elt.sql_fetch_where(self.gctx, "self_id = %s", (self.self_id,))

  @property
  def repositories(self):
    return repository_elt.sql_fetch_where(self.gctx, "self_id = %s", (self.self_id,))

  @property
  def parents(self):
    return parent_elt.sql_fetch_where(self.gctx, "self_id = %s", (self.self_id,))

  @property
  def children(self):
    return child_elt.sql_fetch_where(self.gctx, "self_id = %s", (self.self_id,))

  @property
  def roas(self):
    return rpki.rpkid.roa_obj.sql_fetch_where(self.gctx, "self_id = %s", (self.self_id,))

  @property
  def ghostbusters(self):
    return rpki.rpkid.ghostbuster_obj.sql_fetch_where(self.gctx, "self_id = %s", (self.self_id,))

  @property
  def ee_certificates(self):
    return rpki.rpkid.ee_cert_obj.sql_fetch_where(self.gctx, "self_id = %s", (self.self_id,))

  def serve_post_save_hook(self, q_pdu, r_pdu, cb, eb):
    actions = []
    if q_pdu.rekey:
      actions.append(self.serve_rekey)
    if q_pdu.revoke:
      actions.append(self.serve_revoke)
    if q_pdu.reissue:
      actions.append(self.serve_reissue)
    if q_pdu.revoke_forgotten:
      actions.append(self.serve_revoke_forgotten)
    if q_pdu.publish_world_now:
      actions.append(self.serve_publish_world_now)
    if q_pdu.run_now:
      actions.append(self.serve_run_now)
    if q_pdu.clear_replay_protection:
      actions.append(self.serve_clear_replay_protection)
    def loop(iterator, action):
      action(iterator, eb)
    rpki.async.iterator(actions, loop, cb)

  def serve_rekey(self, cb, eb):
    def loop(iterator, parent):
      parent.serve_rekey(iterator, eb)
    rpki.async.iterator(self.parents, loop, cb)

  def serve_revoke(self, cb, eb):
    def loop(iterator, parent):
      parent.serve_revoke(iterator, eb)
    rpki.async.iterator(self.parents, loop, cb)

  def serve_reissue(self, cb, eb):
    def loop(iterator, parent):
      parent.serve_reissue(iterator, eb)
    rpki.async.iterator(self.parents, loop, cb)

  def serve_revoke_forgotten(self, cb, eb):
    def loop(iterator, parent):
      parent.serve_revoke_forgotten(iterator, eb)
    rpki.async.iterator(self.parents, loop, cb)

  def serve_clear_replay_protection(self, cb, eb):
    def loop(iterator, obj):
      obj.serve_clear_replay_protection(iterator, eb)
    rpki.async.iterator(self.parents + self.children + self.repositories, loop, cb)

  def serve_destroy_hook(self, cb, eb):
    def loop(iterator, parent):
      parent.delete(iterator)
    rpki.async.iterator(self.parents, loop, cb)


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
      repository.call_pubd(iterator, eb,
                           q_msg, length_check = False,
                           handlers = dict(list = list_handler))

    def reconcile(uri, obj, repository):
      h, r = objects.pop(uri, (None, None))
      if h is not None:
        assert r == repository
        publisher.queue(uri = uri, new_obj = obj, old_hash = h, repository = repository)

    def done():
      for parent in self.parents:
        repository = parent.repository
        for ca in parent.cas:
          ca_detail = ca.active_ca_detail
          if ca_detail is not None:
            reconcile(uri = ca_detail.crl_uri,
                      obj = ca_detail.latest_crl,
                      repository = repository)
            reconcile(uri = ca_detail.manifest_uri,
                      obj = ca_detail.latest_manifest,
                      repository = repository)
            for c in ca_detail.child_certs:
              reconcile(uri = c.uri,
                        obj = c.cert,
                        repository = repository)
            for r in ca_detail.roas:
              if r.roa is not None:
                reconcile(uri = r.uri,
                          obj = r.roa,
                          repository = repository)
            for g in ca_detail.ghostbusters:
              reconcile(uri = g.uri,
                        obj = g.ghostbuster,
                        repository = repository)
            for c in ca_detail.ee_certificates:
              reconcile(uri = c.uri,
                        obj = c.cert,
                        repository = repository)
        for u in objects:
          h, r = objects[h]
          publisher.queue(uri = u, old_hash = h, repository = r)
      publisher.call_pubd(cb, eb)

    rpki.async.iterator(self.parents, loop, done)

  def serve_run_now(self, cb, eb):
    logger.debug("Forced immediate run of periodic actions for self %s[%d]",
                 self.self_handle, self.self_id)
    completion = rpki.rpkid_tasks.CompletionHandler(cb)
    self.schedule_cron_tasks(completion)
    assert completion.count > 0
    self.gctx.task_run()

  def serve_fetch_one_maybe(self):
    """
    Find the self object upon which a get, set, or destroy action
    should operate, or which would conflict with a create method.
    """

    return self.serve_fetch_handle(self.gctx, None, self.self_handle)

  @classmethod
  def serve_fetch_handle(cls, gctx, self_id, self_handle):
    return cls.sql_fetch_where1(gctx, "self_handle = %s", (self_handle,))

  def serve_fetch_all(self):
    """
    Find the self objects upon which a list action should operate.
    This is different from the list action for all other objects,
    where list only works within a given self_id context.
    """

    return self.sql_fetch_all(self.gctx)

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

    results = set()
    for parent in self.parents:
      for ca in parent.cas:
        ca_detail = ca.active_ca_detail
        if ca_detail is not None and ca_detail.covers(resources):
          results.add(ca_detail)
    return results


class bsc_elt(base_elt):
  """
  <bsc/> (Business Signing Context) element.
  """

  element_name = xmlns + "bsc"
  attributes = ("action", "tag", "self_handle", "bsc_handle", "key_type", "hash_alg", "key_length")
  booleans = ("generate_keypair",)

  elements = collections.OrderedDict((
    (tag_signing_cert,     rpki.x509.X509),
    (tag_signing_cert_crl, rpki.x509.CRL),
    (tag_pkcs10_request,   rpki.x509.PKCS10)))

  sql_template = rpki.sql.template(
    "bsc",
    "bsc_id",
    "bsc_handle",
    "self_id",
    "hash_alg",
    ("private_key_id", rpki.x509.RSA),
    ("pkcs10_request", rpki.x509.PKCS10),
    ("signing_cert", rpki.x509.X509),
    ("signing_cert_crl", rpki.x509.CRL))

  handles = (("self", self_elt),)

  private_key_id = None
  pkcs10_request = None
  signing_cert = None
  signing_cert_crl = None

  def __repr__(self):
    return rpki.log.log_repr(self, self.bsc_handle)

  @property
  def repositories(self):
    return repository_elt.sql_fetch_where(self.gctx, "bsc_id = %s", (self.bsc_id,))

  @property
  def parents(self):
    return parent_elt.sql_fetch_where(self.gctx, "bsc_id = %s", (self.bsc_id,))

  @property
  def children(self):
    return child_elt.sql_fetch_where(self.gctx, "bsc_id = %s", (self.bsc_id,))

  def serve_pre_save_hook(self, q_pdu, r_pdu, cb, eb):
    """
    Extra server actions -- handle key generation, only RSA with SHA-256 for now.
    """

    if q_pdu.generate_keypair:
      assert q_pdu.key_type in (None, "rsa") and q_pdu.hash_alg in (None, "sha256")
      self.private_key_id = rpki.x509.RSA.generate(keylength = q_pdu.key_length or 2048)
      self.pkcs10_request = rpki.x509.PKCS10.create(keypair = self.private_key_id)
      r_pdu.pkcs10_request = self.pkcs10_request
    super(bsc_elt, self).serve_pre_save_hook(q_pdu, r_pdu, cb, eb)


class repository_elt(base_elt):
  """
  <repository/> element.
  """

  element_name = xmlns + "repository"
  attributes = ("action", "tag", "self_handle", "repository_handle", "bsc_handle", "peer_contact_uri", "rrdp_notification_uri")
  booleans = ("clear_replay_protection",)

  elements = collections.OrderedDict((
    (tag_bpki_cert, rpki.x509.X509),
    (tag_bpki_glue, rpki.x509.X509)))

  sql_template = rpki.sql.template(
    "repository",
    "repository_id",
    "repository_handle",
    "self_id",
    "bsc_id",
    "peer_contact_uri",
    "rrdp_notification_uri",
    ("bpki_cert", rpki.x509.X509),
    ("bpki_glue", rpki.x509.X509),
    ("last_cms_timestamp", rpki.sundial.datetime))

  handles = (("self", self_elt),
             ("bsc", bsc_elt))

  bpki_cert = None
  bpki_glue = None
  last_cms_timestamp = None
  rrdp_notification_uri = None

  def __repr__(self):
    return rpki.log.log_repr(self, self.repository_handle)

  @property
  def parents(self):
    return parent_elt.sql_fetch_where(self.gctx, "repository_id = %s", (self.repository_id,))

  def serve_post_save_hook(self, q_pdu, r_pdu, cb, eb):
    actions = []
    if q_pdu.clear_replay_protection:
      actions.append(self.serve_clear_replay_protection)
    def loop(iterator, action):
      action(iterator, eb)
    rpki.async.iterator(actions, loop, cb)

  def serve_clear_replay_protection(self, cb, eb):
    self.last_cms_timestamp = None
    self.sql_mark_dirty()
    cb()


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
      self.gctx.sql.sweep()

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


class parent_elt(base_elt):
  """
  <parent/> element.
  """

  element_name = xmlns + "parent"
  attributes = ("action", "tag", "self_handle", "parent_handle", "bsc_handle", "repository_handle",
                "peer_contact_uri", "sia_base", "sender_name", "recipient_name")
  booleans = ("rekey", "reissue", "revoke", "revoke_forgotten", "clear_replay_protection")

  elements = collections.OrderedDict((
    (tag_bpki_cert, rpki.x509.X509),
    (tag_bpki_glue, rpki.x509.X509)))

  sql_template = rpki.sql.template(
    "parent",
    "parent_id",
    "parent_handle",
    "self_id",
    "bsc_id",
    "repository_id",
    "peer_contact_uri",
    "sia_base",
    "sender_name",
    "recipient_name",
    ("bpki_cert", rpki.x509.X509),
    ("bpki_glue", rpki.x509.X509),
    ("last_cms_timestamp", rpki.sundial.datetime))

  handles = (("self", self_elt),
             ("bsc", bsc_elt),
             ("repository", repository_elt))

  bpki_cert = None
  bpki_glue = None
  last_cms_timestamp = None

  def __repr__(self):
    return rpki.log.log_repr(self, self.parent_handle)

  @property
  @rpki.sql.cache_reference
  def repository(self):
    return repository_elt.sql_fetch(self.gctx, self.repository_id)

  @property
  def cas(self):
    return rpki.rpkid.ca_obj.sql_fetch_where(self.gctx, "parent_id = %s", (self.parent_id,))

  def serve_post_save_hook(self, q_pdu, r_pdu, cb, eb):
    actions = []
    if q_pdu.rekey:
      actions.append(self.serve_rekey)
    if q_pdu.revoke:
      actions.append(self.serve_revoke)
    if q_pdu.reissue:
      actions.append(self.serve_reissue)
    if q_pdu.revoke_forgotten:
      actions.append(self.serve_revoke_forgotten)
    if q_pdu.clear_replay_protection:
      actions.append(self.serve_clear_replay_protection)
    def loop(iterator, action):
      action(iterator, eb)
    rpki.async.iterator(actions, loop, cb)

  def serve_rekey(self, cb, eb):
    def loop(iterator, ca):
      ca.rekey(iterator, eb)
    rpki.async.iterator(self.cas, loop, cb)

  def serve_revoke(self, cb, eb):
    def loop(iterator, ca):
      ca.revoke(cb = iterator, eb = eb)
    rpki.async.iterator(self.cas, loop, cb)

  def serve_reissue(self, cb, eb):
    def loop(iterator, ca):
      ca.reissue(cb = iterator, eb = eb)
    rpki.async.iterator(self.cas, loop, cb)

  def serve_clear_replay_protection(self, cb, eb):
    self.last_cms_timestamp = None
    self.sql_mark_dirty()
    cb()


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

      ca_map = dict((ca.parent_resource_class, ca) for ca in self.cas)
      rpki.async.iterator(skis_from_parent.items(), loop, cb)

    self.get_skis(got_skis, eb)


  def delete(self, cb, delete_parent = True):
    """
    Delete all the CA stuff under this parent, and perhaps the parent
    itself.
    """

    def loop(iterator, ca):
      self.gctx.checkpoint()
      ca.delete(self, iterator)

    def revoke():
      self.gctx.checkpoint()
      self.serve_revoke_forgotten(done, fail)

    def fail(e):
      logger.warning("Trouble getting parent to revoke certificates, blundering onwards: %s", e)
      done()

    def done():
      self.gctx.checkpoint()
      self.gctx.sql.sweep()
      if delete_parent:
        self.sql_delete()
      cb()

    rpki.async.iterator(self.cas, loop, revoke)


  def serve_destroy_hook(self, cb, eb):
    self.delete(cb, delete_parent = False)


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
      rpkiNotify   = ca.parent.repository.rrdp_notification_uri)
    q_msg = self._compose_up_down_query("issue")
    q_pdu = SubElement(q_msg, rpki.up_down.tag_request, class_name = ca.parent_resource_class)
    q_pdu.text = pkcs10.get_Base64()
    self.query_up_down(q_msg, cb, eb)


  def up_down_revoke_query(self, class_name, ski, cb, eb):
    q_msg = self._compose_up_down_query("revoke")
    SubElement(q_msg, rpki.up_down.tag_key, class_name = class_name, ski = ski)
    self.query_up_down(q_msg, cb, eb)


  def query_up_down(self, q_msg, cb, eb):

    bsc = self.bsc
    if bsc is None:
      raise rpki.exceptions.BSCNotFound("Could not find BSC %s" % self.bsc_id)

    if bsc.signing_cert is None:
      raise rpki.exceptions.BSCNotReady("BSC %r[%s] is not yet usable" % (bsc.bsc_handle, bsc.bsc_id))

    q_der = rpki.up_down.cms_msg().wrap(q_msg, bsc.private_key_id,
                                        bsc.signing_cert,
                                        bsc.signing_cert_crl)

    def unwrap(r_der):
      try:
        r_cms = rpki.up_down.cms_msg(DER = r_der)
        r_msg = r_cms.unwrap((self.gctx.bpki_ta,
                              self.self.bpki_cert,
                              self.self.bpki_glue,
                              self.bpki_cert,
                              self.bpki_glue))
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


class child_elt(base_elt):
  """
  <child/> element.
  """

  element_name = xmlns + "child"
  attributes = ("action", "tag", "self_handle", "child_handle", "bsc_handle")
  booleans = ("reissue", "clear_replay_protection")

  elements = collections.OrderedDict((
    (tag_bpki_cert, rpki.x509.X509),
    (tag_bpki_glue, rpki.x509.X509)))

  sql_template = rpki.sql.template(
    "child",
    "child_id",
    "child_handle",
    "self_id",
    "bsc_id",
    ("bpki_cert", rpki.x509.X509),
    ("bpki_glue", rpki.x509.X509),
    ("last_cms_timestamp", rpki.sundial.datetime))

  handles = (("self", self_elt),
             ("bsc", bsc_elt))

  bpki_cert = None
  bpki_glue = None
  last_cms_timestamp = None

  def __repr__(self):
    return rpki.log.log_repr(self, self.child_handle)

  def fetch_child_certs(self, ca_detail = None, ski = None, unique = False):
    return rpki.rpkid.child_cert_obj.fetch(self.gctx, self, ca_detail, ski, unique)

  @property
  def child_certs(self):
    return self.fetch_child_certs()

  @property
  def parents(self):
    return parent_elt.sql_fetch_where(self.gctx, "self_id = %s", (self.self_id,))

  def serve_post_save_hook(self, q_pdu, r_pdu, cb, eb):
    actions = []
    if q_pdu.reissue:
      actions.append(self.serve_reissue)
    if q_pdu.clear_replay_protection:
      actions.append(self.serve_clear_replay_protection)
    def loop(iterator, action):
      action(iterator, eb)
    rpki.async.iterator(actions, loop, cb)

  def serve_reissue(self, cb, eb):
    publisher = rpki.rpkid.publication_queue()
    for child_cert in self.child_certs:
      child_cert.reissue(child_cert.ca_detail, publisher, force = True)
    publisher.call_pubd(cb, eb)

  def serve_clear_replay_protection(self, cb, eb):
    self.last_cms_timestamp = None
    self.sql_mark_dirty()
    cb()

  def ca_from_class_name(self, class_name):
    if not class_name.isdigit():
      raise rpki.exceptions.BadClassNameSyntax("Bad class name %s" % class_name)
    ca = rpki.rpkid.ca_obj.sql_fetch(self.gctx, long(class_name))
    if ca is None:
      raise rpki.exceptions.ClassNameUnknown("Unknown class name %s" % class_name)
    parent = ca.parent
    if self.self_id != parent.self_id:
      raise rpki.exceptions.ClassNameMismatch(
        "Class name mismatch: child.self_id = %d, parent.self_id = %d" % (
        self.self_id, parent.self_id))
    return ca

  def serve_destroy_hook(self, cb, eb):
    publisher = rpki.rpkid.publication_queue()
    for child_cert in self.child_certs:
      child_cert.revoke(publisher = publisher,
                        generate_crl_and_manifest = True)
    publisher.call_pubd(cb, eb)


  def up_down_handle_list(self, q_msg, r_msg, callback, errback):

    def got_resources(irdb_resources):

      if irdb_resources.valid_until < rpki.sundial.now():
        logger.debug("Child %s's resources expired %s", self.child_handle, irdb_resources.valid_until)
      else:
        for parent in self.parents:
          for ca in parent.cas:
            ca_detail = ca.active_ca_detail
            if not ca_detail:
              logger.debug("No active ca_detail, can't issue to %s", self.child_handle)
              continue
            resources = ca_detail.latest_ca_cert.get_3779resources() & irdb_resources
            if resources.empty():
              logger.debug("No overlap between received resources and what child %s should get ([%s], [%s])",
                           self.child_handle, ca_detail.latest_ca_cert.get_3779resources(), irdb_resources)
              continue
            rc = SubElement(r_msg, rpki.up_down.tag_class,
                            class_name = str(ca.ca_id),
                            cert_url = ca_detail.ca_cert_uri,
                            resource_set_as   = str(resources.asn),
                            resource_set_ipv4 = str(resources.v4),
                            resource_set_ipv6 = str(resources.v6),
                            resource_set_notafter = str(resources.valid_until))
            for child_cert in self.fetch_child_certs(ca_detail = ca_detail):
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
      child_cert = self.fetch_child_certs(ca_detail = ca_detail, ski = req_key.get_SKI(), unique = True)

      # Generate new cert or regenerate old one if necessary

      publisher = rpki.rpkid.publication_queue()

      if child_cert is None:
        child_cert = ca_detail.issue(
          ca          = ca,
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

      self.gctx.sql.sweep()
      assert child_cert and child_cert.sql_in_db
      publisher.call_pubd(done, errback)

    req = q_msg[0]
    assert req.tag == rpki.up_down.tag_request

    # Subsetting not yet implemented, this is the one place where we
    # have to handle it, by reporting that we're lame.

    if any(req.get(a) for a in ("req_resource_set_as", "req_resource_set_ipv4", "req_resource_set_ipv6")):
      raise rpki.exceptions.NotImplementedYet("req_* attributes not implemented yet, sorry")

    class_name = req.get("class_name")
    pkcs10 = rpki.x509.PKCS10(Base64 = req.text)
    pkcs10.check_valid_request_ca()
    ca = self.ca_from_class_name(class_name)
    ca_detail = ca.active_ca_detail
    if ca_detail is None:
      raise rpki.exceptions.NoActiveCA("No active CA for class %r" % class_name)

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

    ca = child.ca_from_class_name(class_name)
    for ca_detail in ca.ca_details:
      for child_cert in child.fetch_child_certs(ca_detail = ca_detail, ski = ski):
        child_cert.revoke(publisher = publisher)

    self.gctx.sql.sweep()
    publisher.call_pubd(done, errback)


  def serve_up_down(self, q_der, callback):
    """
    Outer layer of server handling for one up-down PDU from this child.
    """

    def done():
      callback(rpki.up_down.cms_msg().wrap(r_msg, bsc.private_key_id,
                                           bsc.signing_cert, bsc.signing_cert_crl))

    def lose(e):
      logger.exception("Unhandled exception serving child %r", self)
      rpki.up_down.generate_error_response_from_exception(r_msg, e, q_type)
      done()

    bsc = self.bsc
    if bsc is None:
      raise rpki.exceptions.BSCNotFound("Could not find BSC %s" % self.bsc_id)
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
    self.gctx.sql.sweep()

    r_msg = Element(rpki.up_down.tag_message, nsmap = rpki.up_down.nsmap, version = rpki.up_down.version,
                    sender = q_msg.get("recipient"), recipient = q_msg.get("sender"), type = q_type + "_response")

    try:
      getattr(self, "up_down_handle_" + q_type)(q_msg, r_msg, done, lose)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception, e:
      lose(e)


class cms_msg(rpki.x509.XML_CMS_object):
  """
  CMS-signed left-right PDU.
  """

  encoding = "us-ascii"
  schema = rpki.relaxng.left_right
