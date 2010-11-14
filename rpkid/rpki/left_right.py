"""
RPKI "left-right" protocol.

$Id$

Copyright (C) 2009--2010  Internet Systems Consortium ("ISC")

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

Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import rpki.resource_set, rpki.x509, rpki.sql, rpki.exceptions, rpki.xml_utils
import rpki.http, rpki.up_down, rpki.relaxng, rpki.sundial, rpki.log, rpki.roa
import rpki.publication, rpki.async

# Enforce strict checking of XML "sender" field in up-down protocol
enforce_strict_up_down_xml_sender = False

class left_right_namespace(object):
  """
  XML namespace parameters for left-right protocol.
  """

  xmlns = "http://www.hactrn.net/uris/rpki/left-right-spec/"
  nsmap = { None : xmlns }

class data_elt(rpki.xml_utils.data_elt, rpki.sql.sql_persistent, left_right_namespace):
  """
  Virtual class for top-level left-right protocol data elements.
  """

  handles = ()

  self_id = None
  self_handle = None

  def self(self):
    """
    Fetch self object to which this object links.
    """
    return self_elt.sql_fetch(self.gctx, self.self_id)

  def bsc(self):
    """
    Return BSC object to which this object links.
    """
    return bsc_elt.sql_fetch(self.gctx, self.bsc_id)

  def make_reply_clone_hook(self, r_pdu):
    """
    Set handles when cloning, including _id -> _handle translation.
    """
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
    """
    Find an object based on its handle.
    """
    return cls.sql_fetch_where1(gctx, cls.element_name + "_handle = %s AND self_id = %s", (handle, self_id))

  def serve_fetch_one_maybe(self):
    """
    Find the object on which a get, set, or destroy method should
    operate, or which would conflict with a create method.
    """
    where = "%s.%s_handle = %%s AND %s.self_id = self.self_id AND self.self_handle = %%s" % ((self.element_name,) * 3)
    args = (getattr(self, self.element_name + "_handle"), self.self_handle)
    return self.sql_fetch_where1(self.gctx, where, args, "self")

  def serve_fetch_all(self):
    """
    Find the objects on which a list method should operate.
    """
    where = "%s.self_id = self.self_id and self.self_handle = %%s" % self.element_name
    return self.sql_fetch_where(self.gctx, where, (self.self_handle,), "self")
  
  def serve_pre_save_hook(self, q_pdu, r_pdu, cb, eb):
    """
    Hook to do _handle => _id translation before saving.

    self is always the object to be saved to SQL.  For create
    operations, self and q_pdu are be the same object; for set
    operations, self is the pre-existing object from SQL and q_pdu is
    the set request received from the the IRBE.
    """
    for tag, elt in self.handles:
      id_name = tag + "_id"
      if getattr(self, id_name, None) is None:
        x = elt.serve_fetch_handle(self.gctx, self.self_id, getattr(q_pdu, tag + "_handle"))
        if x is None:
          raise rpki.exceptions.HandleTranslationError, "Could not translate %r %s_handle" % (self, tag)
        setattr(self, id_name, getattr(x, id_name))
    cb()

class self_elt(data_elt):
  """
  <self/> element.
  """

  element_name = "self"
  attributes = ("action", "tag", "self_handle", "crl_interval", "regen_margin")
  elements = ("bpki_cert", "bpki_glue")
  booleans = ("rekey", "reissue", "revoke", "run_now", "publish_world_now", "revoke_forgotten")

  sql_template = rpki.sql.template("self", "self_id", "self_handle",
                                   "use_hsm", "crl_interval", "regen_margin",
                                   ("bpki_cert", rpki.x509.X509), ("bpki_glue", rpki.x509.X509))
  handles = ()

  use_hsm = False
  crl_interval = None
  regen_margin = None
  bpki_cert = None
  bpki_glue = None

  def bscs(self):
    """
    Fetch all BSC objects that link to this self object.
    """
    return bsc_elt.sql_fetch_where(self.gctx, "self_id = %s", (self.self_id,))

  def repositories(self):
    """
    Fetch all repository objects that link to this self object.
    """
    return repository_elt.sql_fetch_where(self.gctx, "self_id = %s", (self.self_id,))

  def parents(self):
    """
    Fetch all parent objects that link to this self object.
    """
    return parent_elt.sql_fetch_where(self.gctx, "self_id = %s", (self.self_id,))

  def children(self):
    """
    Fetch all child objects that link to this self object.
    """
    return child_elt.sql_fetch_where(self.gctx, "self_id = %s", (self.self_id,))

  def roas(self):
    """
    Fetch all ROA objects that link to this self object.
    """
    return rpki.rpki_engine.roa_obj.sql_fetch_where(self.gctx, "self_id = %s", (self.self_id,))

  def serve_post_save_hook(self, q_pdu, r_pdu, cb, eb):
    """
    Extra server actions for self_elt.
    """
    rpki.log.trace()
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
    def loop(iterator, action):
      action(iterator, eb)
    rpki.async.iterator(actions, loop, cb)

  def serve_rekey(self, cb, eb):
    """
    Handle a left-right rekey action for this self.
    """
    rpki.log.trace()
    def loop(iterator, parent):
      parent.serve_rekey(iterator, eb)
    rpki.async.iterator(self.parents(), loop, cb)

  def serve_revoke(self, cb, eb):
    """
    Handle a left-right revoke action for this self.
    """
    rpki.log.trace()
    def loop(iterator, parent):
      parent.serve_revoke(iterator, eb)
    rpki.async.iterator(self.parents(), loop, cb)

  def serve_reissue(self, cb, eb):
    """
    Handle a left-right reissue action for this self.
    """
    rpki.log.trace()
    def loop(iterator, parent):
      parent.serve_reissue(iterator, eb)
    rpki.async.iterator(self.parents(), loop, cb)

  def serve_revoke_forgotten(self, cb, eb):
    """
    Handle a left-right revoke_forgotten action for this self.
    """
    rpki.log.trace()
    def loop(iterator, parent):
      parent.serve_revoke_forgotten(iterator, eb)
    rpki.async.iterator(self.parents(), loop, cb)

  def serve_publish_world_now(self, cb, eb):
    """
    Handle a left-right publish_world_now action for this self.

    The publication stuff needs refactoring, right now publication is
    interleaved with local operations in a way that forces far too
    many bounces through the task system for any complex update.  The
    whole thing ought to be rewritten to queue up outgoing publication
    PDUs and only send them when we're all done or when we need to
    force publication at a particular point in a multi-phase operation.

    Once that reorganization has been done, this method should be
    rewritten to reuse the low-level publish() methods that each
    object will have...but we're not there yet.  So, for now, we just
    do this via brute force.  Think of it as a trial version to see
    whether we've identified everything that needs to be republished
    for this operation.
    """

    def loop(iterator, parent):
      q_msg = rpki.publication.msg.query()
      for ca in parent.cas():
        ca_detail = ca.fetch_active()
        if ca_detail is not None:
          q_msg.append(rpki.publication.crl_elt.make_publish(ca_detail.crl_uri(ca), ca_detail.latest_crl))
          q_msg.append(rpki.publication.manifest_elt.make_publish(ca_detail.manifest_uri(ca), ca_detail.latest_manifest))
          q_msg.extend(rpki.publication.certificate_elt.make_publish(c.uri(ca), c.cert) for c in ca_detail.child_certs())
          q_msg.extend(rpki.publication.roa_elt.make_publish(r.uri(), r.roa) for r in ca_detail.roas() if r.roa is not None)
      parent.repository().call_pubd(iterator, eb, q_msg)

    rpki.async.iterator(self.parents(), loop, cb)

  def serve_run_now(self, cb, eb):
    """
    Handle a left-right run_now action for this self.
    """
    rpki.log.debug("Forced immediate run of periodic actions for self %s[%d]" % (self.self_handle, self.self_id))
    self.cron(cb)

  def serve_fetch_one_maybe(self):
    """
    Find the self object upon which a get, set, or destroy action
    should operate, or which would conflict with a create method.
    """
    return self.serve_fetch_handle(self.gctx, None, self.self_handle)

  @classmethod
  def serve_fetch_handle(cls, gctx, self_id, self_handle):
    """
    Find a self object based on its self_handle.
    """
    return cls.sql_fetch_where1(gctx, "self_handle = %s", self_handle)

  def serve_fetch_all(self):
    """
    Find the self objects upon which a list action should operate.
    This is different from the list action for all other objects,
    where list only works within a given self_id context.
    """
    return self.sql_fetch_all(self.gctx)

  def cron(self, cb):
    """
    Periodic tasks.
    """

    def one():
      self.gctx.checkpoint()
      rpki.log.debug("Self %s[%d] polling parents" % (self.self_handle, self.self_id))
      self.client_poll(two)

    def two():
      self.gctx.checkpoint()
      rpki.log.debug("Self %s[%d] updating children" % (self.self_handle, self.self_id))
      self.update_children(three)

    def three():
      self.gctx.checkpoint()
      rpki.log.debug("Self %s[%d] updating ROAs" % (self.self_handle, self.self_id))
      self.update_roas(four)

    def four():
      self.gctx.checkpoint()
      rpki.log.debug("Self %s[%d] regenerating CRLs and manifests" % (self.self_handle, self.self_id))
      self.regenerate_crls_and_manifests(cb)

    one()


  def client_poll(self, callback):
    """
    Run the regular client poll cycle with each of this self's parents
    in turn.
    """

    rpki.log.trace()

    def parent_loop(parent_iterator, parent):

      def got_list(r_msg):
        ca_map = dict((ca.parent_resource_class, ca) for ca in parent.cas())
        self.gctx.checkpoint()

        def class_loop(class_iterator, rc):

          def class_update_failed(e):
            rpki.log.traceback()
            rpki.log.warn("Couldn't update class, skipping: %s" % e)
            class_iterator()

          def class_create_failed(e):
            rpki.log.traceback()
            rpki.log.warn("Couldn't create class, skipping: %s" % e)
            class_iterator()

          self.gctx.checkpoint()
          if rc.class_name in ca_map:
            ca = ca_map[rc.class_name]
            del  ca_map[rc.class_name]
            ca.check_for_updates(parent, rc, class_iterator, class_update_failed)
          else:
            rpki.rpki_engine.ca_obj.create(parent, rc, class_iterator, class_create_failed)

        def class_done():

          def ca_loop(iterator, ca):
            self.gctx.checkpoint()
            ca.delete(parent, iterator)
            
          def ca_done():
            self.gctx.checkpoint()
            self.gctx.sql.sweep()
            parent_iterator()

          rpki.async.iterator(ca_map.values(), ca_loop, ca_done)

        rpki.async.iterator(r_msg.payload.classes, class_loop, class_done)

      def list_failed(e):
        rpki.log.traceback()
        rpki.log.warn("Couldn't get resource class list from parent %r, skipping: %s" % (parent, e))
        parent_iterator()

      rpki.up_down.list_pdu.query(parent, got_list, list_failed)

    rpki.async.iterator(self.parents(), parent_loop, callback)


  def update_children(self, cb):
    """
    Check for updated IRDB data for all of this self's children and
    issue new certs as necessary.  Must handle changes both in
    resources and in expiration date.
    """

    rpki.log.trace()
    now = rpki.sundial.now()
    rsn = now + rpki.sundial.timedelta(seconds = self.regen_margin)
    publisher = rpki.rpki_engine.publication_queue()

    def loop(iterator, child):

      def lose(e):
        rpki.log.traceback()
        rpki.log.warn("Couldn't update child %r, skipping: %s" % (child, e))
        iterator()

      def got_resources(irdb_resources):
        try:
          for child_cert in child_certs:
            ca_detail = child_cert.ca_detail()
            ca = ca_detail.ca()
            if ca_detail.state == "active":
              old_resources = child_cert.cert.get_3779resources()
              new_resources = irdb_resources.intersection(old_resources).intersection(ca_detail.latest_ca_cert.get_3779resources())

              if new_resources.empty():
                rpki.log.debug("Resources shrank to the null set, revoking and withdrawing child certificate SKI %s" % child_cert.cert.gSKI())
                child_cert.revoke(publisher = publisher)
                ca_detail.generate_crl(publisher = publisher)
                ca_detail.generate_manifest(publisher = publisher)

              elif old_resources != new_resources or (old_resources.valid_until < rsn and irdb_resources.valid_until > now):
                rpki.log.debug("Need to reissue child certificate SKI %s" % child_cert.cert.gSKI())
                child_cert.reissue(
                  ca_detail = ca_detail,
                  resources = new_resources,
                  publisher = publisher)

              elif old_resources.valid_until < now:
                rpki.log.debug("Child certificate SKI %s has expired: cert.valid_until %s, irdb.valid_until %s"
                               % (child_cert.cert.gSKI(), old_resources.valid_until, irdb_resources.valid_until))
                child_cert.sql_delete()
                publisher.withdraw(cls = rpki.publication.certificate_elt, uri = child_cert.uri(ca), obj = child_cert.cert, repository = ca.parent().repository())
                ca_detail.generate_manifest(publisher = publisher)

        except (SystemExit, rpki.async.ExitNow):
          raise
        except Exception, e:
          self.gctx.checkpoint()
          lose(e)
        else:
          self.gctx.checkpoint()
          iterator()

      self.gctx.checkpoint()
      child_certs = child.child_certs()
      if child_certs:
        self.gctx.irdb_query_child_resources(child.self().self_handle, child.child_handle, got_resources, lose)
      else:
        iterator()

    def done():
      def lose(e):
        rpki.log.traceback()
        rpki.log.warn("Couldn't publish for %s, skipping: %s" % (self.self_handle, e))
        self.gctx.checkpoint()
        cb()
      self.gctx.checkpoint()
      publisher.call_pubd(cb, lose)

    rpki.async.iterator(self.children(), loop, done)


  def regenerate_crls_and_manifests(self, cb):
    """
    Generate new CRLs and manifests as necessary for all of this
    self's CAs.  Extracting nextUpdate from a manifest is hard at the
    moment due to implementation silliness, so for now we generate a
    new manifest whenever we generate a new CRL

    This method also cleans up tombstones left behind by revoked
    ca_detail objects, since we're walking through the relevant
    portions of the database anyway.
    """

    rpki.log.trace()
    now = rpki.sundial.now()
    regen_margin = rpki.sundial.timedelta(seconds = self.regen_margin)
    publisher = rpki.rpki_engine.publication_queue()

    for parent in self.parents():
      for ca in parent.cas():
        try:
          for ca_detail in ca.fetch_revoked():
            if now > ca_detail.latest_crl.getNextUpdate():
              ca_detail.delete(ca = ca, publisher = publisher)
          ca_detail = ca.fetch_active()
          if ca_detail is not None and now + regen_margin> ca_detail.latest_crl.getNextUpdate():
            ca_detail.generate_crl(publisher = publisher)
            ca_detail.generate_manifest(publisher = publisher)
        except (SystemExit, rpki.async.ExitNow):
          raise
        except Exception, e:
          rpki.log.traceback()
          rpki.log.warn("Couldn't regenerate CRLs and manifests for CA %r, skipping: %s" % (ca, e))

    def lose(e):
      rpki.log.traceback()
      rpki.log.warn("Couldn't publish updated CRLs and manifests for self %r, skipping: %s" % (self.self_handle, e))
      self.gctx.checkpoint()
      cb()

    self.gctx.checkpoint()
    publisher.call_pubd(cb, lose)


  def update_roas(self, cb):
    """
    Generate or update ROAs for this self.
    """

    def got_roa_requests(roa_requests):

      self.gctx.checkpoint()

      if self.gctx.sql.dirty:
        rpki.log.warn("Unexpected dirty SQL cache, flushing")
        self.gctx.sql.sweep()

      roas = {}
      orphans = []
      for roa in self.roas():
        k = (roa.asn, str(roa.ipv4), str(roa.ipv6))
        if k not in roas:
          roas[k] = roa
        elif (roa.roa is not None and roa.cert is not None and roa.ca_detail() is not None and roa.ca_detail().state == "active" and
              (roas[k].roa is None or roas[k].cert is None or roas[k].ca_detail() is None or roas[k].ca_detail().state != "active")):
          orphans.append(roas[k])
          roas[k] = roa
        else:
          orphans.append(roa)

      publisher = rpki.rpki_engine.publication_queue()
      ca_details = set()

      seen = set()
      for roa_request in roa_requests:
        try:
          k = (roa_request.asn, str(roa_request.ipv4), str(roa_request.ipv6))
          if k in seen:
            rpki.log.warn("Skipping duplicate ROA request %r for %r" % (k, roa_request))
            continue
          seen.add(k)
          roa = roas.pop(k, None)
          if roa is None:
            roa = rpki.rpki_engine.roa_obj(self.gctx, self.self_id, roa_request.asn, roa_request.ipv4, roa_request.ipv6)
            rpki.log.debug("Couldn't find existing ROA matching %r, created %r" % (k, roa))
          else:
            rpki.log.debug("Found existing ROA %r matching %r" % (roa, k))
          roa.update(publisher = publisher, fast = True)
          ca_details.add(roa.ca_detail())
        except (SystemExit, rpki.async.ExitNow):
          raise
        except Exception, e:
          if not isinstance(e, rpki.exceptions.NoCoveringCertForROA):
            rpki.log.traceback()
          rpki.log.warn("Could not update ROA %r, %r, skipping: %s" % (roa_request, roa, e))

      orphans.extend(roas.itervalues())
      for roa in orphans:
        try:
          ca_details.add(roa.ca_detail())
          roa.revoke(publisher = publisher, fast = True)
        except (SystemExit, rpki.async.ExitNow):
          raise
        except Exception, e:
          rpki.log.traceback()
          rpki.log.warn("Could not revoke ROA %r: %s" % (roa, e))

      for ca_detail in ca_details:
        ca_detail.generate_crl(publisher = publisher)
        ca_detail.generate_manifest(publisher = publisher)

      self.gctx.sql.sweep()

      def publication_failed(e):
        rpki.log.traceback()
        rpki.log.warn("Couldn't publish for %s, skipping: %s" % (self.self_handle, e))
        self.gctx.checkpoint()
        cb()

      self.gctx.checkpoint()
      publisher.call_pubd(cb, publication_failed)

    def roa_requests_failed(e):
      rpki.log.traceback()
      rpki.log.warn("Could not fetch ROA requests for %s, skipping: %s" % (self.self_handle, e))
      cb()

    self.gctx.checkpoint()
    self.gctx.irdb_query_roa_requests(self.self_handle, got_roa_requests, roa_requests_failed)

class bsc_elt(data_elt):
  """
  <bsc/> (Business Signing Context) element.
  """
  
  element_name = "bsc"
  attributes = ("action", "tag", "self_handle", "bsc_handle", "key_type", "hash_alg", "key_length")
  elements = ("signing_cert", "signing_cert_crl", "pkcs10_request")
  booleans = ("generate_keypair",)

  sql_template = rpki.sql.template("bsc", "bsc_id", "bsc_handle",
                                   "self_id", "hash_alg",
                                   ("private_key_id", rpki.x509.RSA),
                                   ("pkcs10_request", rpki.x509.PKCS10),
                                   ("signing_cert", rpki.x509.X509),
                                   ("signing_cert_crl", rpki.x509.CRL))
  handles = (("self", self_elt),)

  private_key_id = None
  pkcs10_request = None
  signing_cert = None
  signing_cert_crl = None

  def repositories(self):
    """
    Fetch all repository objects that link to this BSC object.
    """
    return repository_elt.sql_fetch_where(self.gctx, "bsc_id = %s", (self.bsc_id,))

  def parents(self):
    """
    Fetch all parent objects that link to this BSC object.
    """
    return parent_elt.sql_fetch_where(self.gctx, "bsc_id = %s", (self.bsc_id,))

  def children(self):
    """
    Fetch all child objects that link to this BSC object.
    """
    return child_elt.sql_fetch_where(self.gctx, "bsc_id = %s", (self.bsc_id,))

  def serve_pre_save_hook(self, q_pdu, r_pdu, cb, eb):
    """
    Extra server actions for bsc_elt -- handle key generation.  For
    now this only allows RSA with SHA-256.
    """
    if q_pdu.generate_keypair:
      assert q_pdu.key_type in (None, "rsa") and q_pdu.hash_alg in (None, "sha256")
      self.private_key_id = rpki.x509.RSA.generate(keylength = q_pdu.key_length or 2048)
      self.pkcs10_request = rpki.x509.PKCS10.create(self.private_key_id)
      r_pdu.pkcs10_request = self.pkcs10_request
    data_elt.serve_pre_save_hook(self, q_pdu, r_pdu, cb, eb)

class repository_elt(data_elt):
  """
  <repository/> element.
  """

  element_name = "repository"
  attributes = ("action", "tag", "self_handle", "repository_handle", "bsc_handle", "peer_contact_uri")
  elements = ("bpki_cert", "bpki_glue")

  sql_template = rpki.sql.template("repository", "repository_id", "repository_handle",
                                   "self_id", "bsc_id", "peer_contact_uri",
                                   ("bpki_cert", rpki.x509.X509),
                                   ("bpki_glue", rpki.x509.X509),
                                   ("last_cms_timestamp", rpki.sundial.datetime))

  handles = (("self", self_elt), ("bsc", bsc_elt))

  bpki_cert = None
  bpki_glue = None

  def parents(self):
    """
    Fetch all parent objects that link to this repository object.
    """
    return parent_elt.sql_fetch_where(self.gctx, "repository_id = %s", (self.repository_id,))

  @staticmethod
  def default_pubd_handler(pdu):
    """
    Default handler for publication response PDUs.
    """
    pdu.raise_if_error()

  def call_pubd(self, callback, errback, q_msg, handlers = None):
    """
    Send a message to publication daemon and return the response.

    As a convenience, attempting to send an empty message returns
    immediate success without sending anything.

    Handlers is a dict of handler functions to process the response
    PDUs.  If the tag value in the response PDU appears in the dict,
    the associated handler is called to process the PDU.  If no tag
    matches, default_pubd_handler() is called.  A handler value of
    False suppresses calling of the default handler.
    """

    try:
      rpki.log.trace()

      self.gctx.sql.sweep()

      if not q_msg:
        return callback()

      if handlers is None:
        handlers = {}

      for q_pdu in q_msg:
        rpki.log.info("Sending <%s %r %r> to pubd" % (q_pdu.action, q_pdu.uri, q_pdu.payload))

      bsc = self.bsc()
      q_der = rpki.publication.cms_msg().wrap(q_msg, bsc.private_key_id, bsc.signing_cert, bsc.signing_cert_crl)
      bpki_ta_path = (self.gctx.bpki_ta, self.self().bpki_cert, self.self().bpki_glue, self.bpki_cert, self.bpki_glue)

      def done(r_der):
        try:
          r_msg = rpki.publication.cms_msg(DER = r_der).unwrap(bpki_ta_path)
          for r_pdu in r_msg:
            handler = handlers.get(r_pdu.tag, self.default_pubd_handler)
            if handler:
              handler(r_pdu)
          if len(q_msg) != len(r_msg):
            raise rpki.exceptions.BadPublicationReply, "Wrong number of response PDUs from pubd: sent %r, got %r" % (q_msg, r_msg)
          callback()
        except (rpki.async.ExitNow, SystemExit):
          raise
        except Exception, e:
          errback(e)

      rpki.http.client(
        url          = self.peer_contact_uri,
        msg          = q_der,
        callback     = done,
        errback      = errback)

    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception, e:
      errback(e)

class parent_elt(data_elt):
  """
  <parent/> element.
  """

  element_name = "parent"
  attributes = ("action", "tag", "self_handle", "parent_handle", "bsc_handle", "repository_handle",
                "peer_contact_uri", "sia_base", "sender_name", "recipient_name")
  elements = ("bpki_cms_cert", "bpki_cms_glue")
  booleans = ("rekey", "reissue", "revoke", "revoke_forgotten")

  sql_template = rpki.sql.template("parent", "parent_id", "parent_handle",
                                   "self_id", "bsc_id", "repository_id",
                                   "peer_contact_uri", "sia_base",
                                   "sender_name", "recipient_name",
                                   ("bpki_cms_cert", rpki.x509.X509),
                                   ("bpki_cms_glue", rpki.x509.X509),
                                   ("last_cms_timestamp", rpki.sundial.datetime))

  handles = (("self", self_elt), ("bsc", bsc_elt), ("repository", repository_elt))

  bpki_cms_cert = None
  bpki_cms_glue = None

  def repository(self):
    """
    Fetch repository object to which this parent object links.
    """
    return repository_elt.sql_fetch(self.gctx, self.repository_id)

  def cas(self):
    """
    Fetch all CA objects that link to this parent object.
    """
    return rpki.rpki_engine.ca_obj.sql_fetch_where(self.gctx, "parent_id = %s", (self.parent_id,))

  def serve_post_save_hook(self, q_pdu, r_pdu, cb, eb):
    """
    Extra server actions for parent_elt.
    """
    actions = []
    if q_pdu.rekey:
      actions.append(self.serve_rekey)
    if q_pdu.revoke:
      actions.append(self.serve_revoke)
    if q_pdu.reissue:
      actions.append(self.serve_reissue)
    if q_pdu.revoke_forgotten:
      actions.append(self.serve_revoke_forgotten)
    def loop(iterator, action):
      action(iterator, eb)
    rpki.async.iterator(actions, loop, cb)

  def serve_rekey(self, cb, eb):
    """
    Handle a left-right rekey action for this parent.
    """
    def loop(iterator, ca):
      ca.rekey(iterator, eb)
    rpki.async.iterator(self.cas(), loop, cb)

  def serve_revoke(self, cb, eb):
    """
    Handle a left-right revoke action for this parent.
    """
    def loop(iterator, ca):
      ca.revoke(cb = iterator, eb = eb)
    rpki.async.iterator(self.cas(), loop, cb)

  def serve_reissue(self, cb, eb):
    """
    Handle a left-right reissue action for this parent.
    """
    def loop(iterator, ca):
      ca.reissue(cb = iterator, eb = eb)
    rpki.async.iterator(self.cas(), loop, cb)

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

    def got_list(r_msg):

      ca_map = dict((ca.parent_resource_class, ca) for ca in self.cas())

      def rc_loop(rc_iterator, rc):

        if rc.class_name in ca_map:

          def ski_loop(ski_iterator, ski):
            rpki.log.warn("Revoking certificates missing from our database, class %r, SKI %s" % (rc.class_name, ski))
            rpki.up_down.revoke_pdu.query(ca, ski, lambda x: ski_iterator(), eb)

          ca = ca_map[rc.class_name]
          skis_parent_knows_about = set(c.cert.gSKI() for c in rc.certs)
          skis_ca_knows_about = set(ca_detail.latest_ca_cert.gSKI() for ca_detail in ca.fetch_issue_response_candidates())
          skis_only_parent_knows_about = skis_parent_knows_about - skis_ca_knows_about
          rpki.async.iterator(skis_only_parent_knows_about, ski_loop, rc_iterator)

        else:
          rc_iterator()

      rpki.async.iterator(r_msg.payload.classes, rc_loop, cb)

    rpki.up_down.list_pdu.query(self, got_list, eb)


  def query_up_down(self, q_pdu, cb, eb):
    """
    Client code for sending one up-down query PDU to this parent.
    """

    rpki.log.trace()

    bsc = self.bsc()
    if bsc is None:
      raise rpki.exceptions.BSCNotFound, "Could not find BSC %s" % self.bsc_id

    if bsc.signing_cert is None:
      raise rpki.exceptions.BSCNotReady, "BSC %r[%s] is not yet usable" % (bsc.bsc_handle, bsc.bsc_id)

    q_msg = rpki.up_down.message_pdu.make_query(
      payload = q_pdu,
      sender = self.sender_name,
      recipient = self.recipient_name)

    q_der = rpki.up_down.cms_msg().wrap(q_msg, bsc.private_key_id,
                                        bsc.signing_cert,
                                        bsc.signing_cert_crl)

    def unwrap(r_der):
      try:
        r_msg = rpki.up_down.cms_msg(DER = r_der).unwrap((self.gctx.bpki_ta,
                                                          self.self().bpki_cert,
                                                          self.self().bpki_glue,
                                                          self.bpki_cms_cert,
                                                          self.bpki_cms_glue))
        r_msg.payload.check_response()
      except (SystemExit, rpki.async.ExitNow):
        raise
      except Exception, e:
        eb(e)
      else:
        cb(r_msg)

    rpki.http.client(
      msg      = q_der,
      url      = self.peer_contact_uri,
      callback = unwrap,
      errback  = eb)

class child_elt(data_elt):
  """
  <child/> element.
  """

  element_name = "child"
  attributes = ("action", "tag", "self_handle", "child_handle", "bsc_handle")
  elements = ("bpki_cert", "bpki_glue")
  booleans = ("reissue", )

  sql_template = rpki.sql.template("child", "child_id", "child_handle",
                                   "self_id", "bsc_id",
                                   ("bpki_cert", rpki.x509.X509),
                                   ("bpki_glue", rpki.x509.X509),
                                   ("last_cms_timestamp", rpki.sundial.datetime))

  handles = (("self", self_elt), ("bsc", bsc_elt))

  bpki_cert = None
  bpki_glue = None

  def child_certs(self, ca_detail = None, ski = None, unique = False):
    """
    Fetch all child_cert objects that link to this child object.
    """
    return rpki.rpki_engine.child_cert_obj.fetch(self.gctx, self, ca_detail, ski, unique)

  def parents(self):
    """
    Fetch all parent objects that link to self object to which this child object links.
    """
    return parent_elt.sql_fetch_where(self.gctx, "self_id = %s", (self.self_id,))

  def serve_post_save_hook(self, q_pdu, r_pdu, cb, eb):
    """
    Extra server actions for child_elt.
    """
    if q_pdu.reissue:
      self.serve_reissue(cb, eb)
    else:
      cb()

  def serve_reissue(self, cb, eb):
    """
    Handle a left-right reissue action for this child.
    """
    publisher = rpki.rpki_engine.publication_queue()
    for child_cert in self.child_certs():
      child_cert.reissue(child_cert.ca_detail(), publisher, force = True)
    publisher.call_pubd(cb, eb)

  def ca_from_class_name(self, class_name):
    """
    Fetch the CA corresponding to an up-down class_name.
    """
    if not class_name.isdigit():
      raise rpki.exceptions.BadClassNameSyntax, "Bad class name %s" % class_name
    ca = rpki.rpki_engine.ca_obj.sql_fetch(self.gctx, long(class_name))
    if ca is None:
      raise rpki.exceptions.ClassNameUnknown, "Unknown class name %s" % class_name
    parent = ca.parent()
    if self.self_id != parent.self_id:
      raise rpki.exceptions.ClassNameMismatch, "Class name mismatch: child.self_id = %d, parent.self_id = %d" % (self.self_id, parent.self_id)
    return ca

  def serve_destroy_hook(self, cb, eb):
    """
    Extra server actions when destroying a child_elt.
    """
    publisher = rpki.rpki_engine.publication_queue()
    for child_cert in self.child_certs():
      child_cert.revoke(publisher = publisher,
                        generate_crl_and_manifest = True)
    publisher.call_pubd(cb, eb)

  def serve_up_down(self, query, callback):
    """
    Outer layer of server handling for one up-down PDU from this child.
    """

    rpki.log.trace()

    bsc = self.bsc()
    if bsc is None:
      raise rpki.exceptions.BSCNotFound, "Could not find BSC %s" % self.bsc_id
    q_msg = rpki.up_down.cms_msg(DER = query).unwrap((self.gctx.bpki_ta,
                                                      self.self().bpki_cert,
                                                      self.self().bpki_glue,
                                                      self.bpki_cert,
                                                      self.bpki_glue))
    q_msg.payload.gctx = self.gctx
    if enforce_strict_up_down_xml_sender and q_msg.sender != str(self.child_id):
      raise rpki.exceptions.BadSender, "Unexpected XML sender %s" % q_msg.sender

    def done(r_msg):
      #
      # Exceptions from this point on are problematic, as we have no
      # sane way of reporting errors in the error reporting mechanism.
      # May require refactoring, ignore the issue for now.
      #
      reply = rpki.up_down.cms_msg().wrap(r_msg, bsc.private_key_id,
                                          bsc.signing_cert, bsc.signing_cert_crl)
      callback(reply)

    try:
      q_msg.serve_top_level(self, done)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except rpki.exceptions.NoActiveCA, data:
      done(q_msg.serve_error(data))
    except Exception, data:
      rpki.log.traceback()
      done(q_msg.serve_error(data))

class list_resources_elt(rpki.xml_utils.base_elt, left_right_namespace):
  """
  <list_resources/> element.
  """

  element_name = "list_resources"
  attributes = ("self_handle", "tag", "child_handle", "valid_until", "asn", "ipv4", "ipv6")
  valid_until = None

  def startElement(self, stack, name, attrs):
    """
    Handle <list_resources/> element.  This requires special handling
    due to the data types of some of the attributes.
    """
    assert name == "list_resources", "Unexpected name %s, stack %s" % (name, stack)
    self.read_attrs(attrs)
    if isinstance(self.valid_until, str):
      self.valid_until = rpki.sundial.datetime.fromXMLtime(self.valid_until)
    if self.asn is not None:
      self.asn = rpki.resource_set.resource_set_as(self.asn)
    if self.ipv4 is not None:
      self.ipv4 = rpki.resource_set.resource_set_ipv4(self.ipv4)
    if self.ipv6 is not None:
      self.ipv6 = rpki.resource_set.resource_set_ipv6(self.ipv6)

  def toXML(self):
    """
    Generate <list_resources/> element.  This requires special
    handling due to the data types of some of the attributes.
    """
    elt = self.make_elt()
    if isinstance(self.valid_until, int):
      elt.set("valid_until", self.valid_until.toXMLtime())
    return elt

class list_roa_requests_elt(rpki.xml_utils.base_elt, left_right_namespace):
  """
  <list_roa_requests/> element.
  """

  element_name = "list_roa_requests"
  attributes = ("self_handle", "tag", "asn", "ipv4", "ipv6")

  def startElement(self, stack, name, attrs):
    """
    Handle <list_roa_requests/> element.  This requires special handling
    due to the data types of some of the attributes.
    """
    assert name == "list_roa_requests", "Unexpected name %s, stack %s" % (name, stack)
    self.read_attrs(attrs)
    if self.ipv4 is not None:
      self.ipv4 = rpki.resource_set.roa_prefix_set_ipv4(self.ipv4)
    if self.ipv6 is not None:
      self.ipv6 = rpki.resource_set.roa_prefix_set_ipv6(self.ipv6)

class list_published_objects_elt(rpki.xml_utils.text_elt, left_right_namespace):
  """
  <list_published_objects/> element.
  """

  element_name = "list_published_objects"
  attributes = ("self_handle", "tag", "uri")
  text_attribute = "obj"

  obj = None

  def serve_dispatch(self, r_msg, cb, eb):
    """
    Handle a <list_published_objects/> query.  The method name is a
    misnomer here, there's no action attribute and no dispatch, we
    just dump every published object for the specified <self/> and return.
    """
    for  parent in self_elt.serve_fetch_handle(self.gctx, None, self.self_handle).parents():
      for ca in parent.cas():
        ca_detail = ca.fetch_active()
        if ca_detail is not None:
          r_msg.append(self.make_reply(ca_detail.crl_uri(ca), ca_detail.latest_crl))
          r_msg.append(self.make_reply(ca_detail.manifest_uri(ca), ca_detail.latest_manifest))
          r_msg.extend(self.make_reply(c.uri(ca), c.cert) for c in ca_detail.child_certs())
          r_msg.extend(self.make_reply(r.uri(), r.roa) for r in ca_detail.roas() if r.roa is not None)
    cb()

  def make_reply(self, uri, obj):
    """
    Generate one reply PDU.
    """
    r_pdu = self.make_pdu(tag = self.tag, self_handle = self.self_handle, uri = uri)
    r_pdu.obj = obj.get_Base64()
    return r_pdu

class list_received_resources_elt(rpki.xml_utils.base_elt, left_right_namespace):
  """
  <list_received_resources/> element.
  """

  element_name = "list_received_resources"
  attributes = ("self_handle", "tag", "parent_handle",
                "notBefore", "notAfter", "uri", "sia_uri", "aia_uri", "asn", "ipv4", "ipv6")

  def serve_dispatch(self, r_msg, cb, eb):
    """
    Handle a <list_received_resources/> query.  The method name is a
    misnomer here, there's no action attribute and no dispatch, we
    just dump a bunch of data about every certificate issued to us by
    one of our parents, then return.
    """
    for parent in self_elt.serve_fetch_handle(self.gctx, None, self.self_handle).parents():
      for ca in parent.cas():
        ca_detail = ca.fetch_active()
        if ca_detail is not None and ca_detail.latest_ca_cert is not None:
          r_msg.append(self.make_reply(parent.parent_handle, ca_detail.ca_cert_uri, ca_detail.latest_ca_cert))
    cb()

  def make_reply(self, parent_handle, uri, cert):
    """
    Generate one reply PDU.
    """
    resources = cert.get_3779resources()
    return self.make_pdu(
      tag = self.tag,
      self_handle = self.self_handle,
      parent_handle = parent_handle,
      notBefore = str(cert.getNotBefore()),
      notAfter = str(cert.getNotAfter()),
      uri = uri,
      sia_uri = cert.get_sia_directory_uri(),
      aia_uri = cert.get_aia_uri(),
      asn = resources.asn,
      ipv4 = resources.v4,
      ipv6 = resources.v6)

class report_error_elt(rpki.xml_utils.text_elt, left_right_namespace):
  """
  <report_error/> element.
  """

  element_name = "report_error"
  attributes = ("tag", "self_handle", "error_code")
  text_attribute = "error_text"

  error_text = None

  @classmethod
  def from_exception(cls, e, self_handle = None, tag = None):
    """
    Generate a <report_error/> element from an exception.
    """
    self = cls()
    self.self_handle = self_handle
    self.tag = tag
    self.error_code = e.__class__.__name__
    self.error_text = str(e)
    return self

class msg(rpki.xml_utils.msg, left_right_namespace):
  """
  Left-right PDU.
  """

  ## @var version
  # Protocol version
  version = 1

  ## @var pdus
  # Dispatch table of PDUs for this protocol.
  pdus = dict((x.element_name, x)
              for x in (self_elt, child_elt, parent_elt, bsc_elt, repository_elt,
                        list_resources_elt, list_roa_requests_elt,
                        list_published_objects_elt, list_received_resources_elt,
                        report_error_elt))

  def serve_top_level(self, gctx, cb):
    """
    Serve one msg PDU.
    """

    r_msg = self.__class__.reply()

    def loop(iterator, q_pdu):

      def fail(e):
        if not isinstance(e, rpki.exceptions.NotFound):
          rpki.log.traceback()
        r_msg.append(report_error_elt.from_exception(e, self_handle = q_pdu.self_handle, tag = q_pdu.tag))
        cb(r_msg)

      try:
        q_pdu.gctx = gctx
        q_pdu.serve_dispatch(r_msg, iterator, fail)
      except (rpki.async.ExitNow, SystemExit):
        raise
      except Exception, e:
        fail(e)

    def done():
      cb(r_msg)

    rpki.async.iterator(self, loop, done)

class sax_handler(rpki.xml_utils.sax_handler):
  """
  SAX handler for Left-Right protocol.
  """

  pdu = msg
  name = "msg"
  version = "1"

class cms_msg(rpki.x509.XML_CMS_object):
  """
  Class to hold a CMS-signed left-right PDU.
  """

  encoding = "us-ascii"
  schema = rpki.relaxng.left_right
  saxify = sax_handler.saxify
