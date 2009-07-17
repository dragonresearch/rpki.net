"""
RPKI "left-right" protocol.

$Id$

Copyright (C) 2009  Internet Systems Consortium ("ISC")

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
import rpki.https, rpki.up_down, rpki.relaxng, rpki.sundial, rpki.log, rpki.roa
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

  def self(self):
    """Fetch self object to which this object links."""
    return self_elt.sql_fetch(self.gctx, self.self_id)

  def bsc(self):
    """Return BSC object to which this object links."""
    return bsc_elt.sql_fetch(self.gctx, self.bsc_id)

  def make_reply_clone_hook(self, r_pdu):
    """Set self_handle when cloning."""
    r_pdu.self_handle = self.self_handle

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
    """
    for tag, elt in self.handles:
      id_name = tag + "_id"
      if getattr(r_pdu, id_name, None) is None:
        x = elt.serve_fetch_handle(self.gctx, self.self_id, getattr(q_pdu, tag + "_handle"))
        if x is None:
          raise rpki.exceptions.NotFound
        val = getattr(x, id_name)
        setattr(self, id_name, val)
        setattr(r_pdu, id_name, val)
    cb()

  def unimplemented_control(self, *controls):
    """
    Uniform handling for unimplemented control operations.
    """
    unimplemented = [x for x in controls if getattr(self, x, False)]
    if unimplemented:
      raise rpki.exceptions.NotImplementedYet, "Unimplemented control %s" % ", ".join(unimplemented)

class self_elt(data_elt):
  """
  <self/> element.
  """

  element_name = "self"
  attributes = ("action", "tag", "self_handle", "crl_interval", "regen_margin")
  elements = ("bpki_cert", "bpki_glue")
  booleans = ("rekey", "reissue", "revoke", "run_now", "publish_world_now")

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
    """Fetch all BSC objects that link to this self object."""
    return bsc_elt.sql_fetch_where(self.gctx, "self_id = %s", (self.self_id,))

  def repositories(self):
    """Fetch all repository objects that link to this self object."""
    return repository_elt.sql_fetch_where(self.gctx, "self_id = %s", (self.self_id,))

  def parents(self):
    """Fetch all parent objects that link to this self object."""
    return parent_elt.sql_fetch_where(self.gctx, "self_id = %s", (self.self_id,))

  def children(self):
    """Fetch all child objects that link to this self object."""
    return child_elt.sql_fetch_where(self.gctx, "self_id = %s", (self.self_id,))

  def roas(self):
    """Fetch all ROA objects that link to this self object."""
    return rpki.rpki_engine.roa_obj.sql_fetch_where(self.gctx, "self_id = %s", (self.self_id,))

  def serve_post_save_hook(self, q_pdu, r_pdu, cb, eb):
    """
    Extra server actions for self_elt.
    """
    rpki.log.trace()
    if q_pdu.rekey:
      self.serve_rekey(cb, eb)
    elif q_pdu.revoke:
      self.serve_revoke(cb, eb)
    else:
      self.unimplemented_control("reissue", "run_now", "publish_world_now")
      cb()

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

  def client_poll(self, callback):
    """
    Run the regular client poll cycle with each of this self's parents
    in turn.
    """

    rpki.log.trace()

    def parent_loop(parent_iterator, parent):

      def got_list(r_msg):
        ca_map = dict((ca.parent_resource_class, ca) for ca in parent.cas())

        def class_loop(class_iterator, rc):

          def class_update_failed(e):
            rpki.log.traceback()
            rpki.log.warn("Couldn't update class, skipping: %s" % e)
            class_iterator()

          def class_create_failed(e):
            rpki.log.traceback()
            rpki.log.warn("Couldn't create class, skipping: %s" % e)
            class_iterator()

          if rc.class_name in ca_map:
            ca = ca_map[rc.class_name]
            del  ca_map[rc.class_name]
            ca.check_for_updates(parent, rc, class_iterator, class_update_failed)
          else:
            rpki.rpki_engine.ca_obj.create(parent, rc, class_iterator, class_create_failed)

        def class_done():

          def ca_loop(iterator, ca):
            ca.delete(parent, iterator)
            
          def ca_done():
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

    def loop1(iterator1, child):

      def got_resources(irdb_resources):

        def loop2(iterator2, child_cert):

          ca_detail = child_cert.ca_detail()

          if ca_detail.state == "active":
            old_resources = child_cert.cert.get_3779resources()
            new_resources = irdb_resources.intersection(old_resources)

            if old_resources != new_resources or (old_resources.valid_until < rsn  and irdb_resources.valid_until > now):
              rpki.log.debug("Need to reissue child certificate SKI %s" % child_cert.cert.gSKI())

              def reissue_failed(e):
                rpki.log.traceback()
                rpki.log.warn("Couldn't reissue child_cert %r, skipping: %s" % (child_cert, e))
                iterator2()

              child_cert.reissue(
                ca_detail = ca_detail,
                resources = new_resources,
                callback  = iterator2.ignore,
                errback   = reissue_failed)
              return

            if old_resources.valid_until < now:
              rpki.log.debug("Child certificate SKI %s has expired: cert.valid_until %s, irdb.valid_until %s"
                             % (child_cert.cert.gSKI(), old_resources.valid_until, irdb_resources.valid_until))
              ca = ca_detail.ca()
              parent = ca.parent()
              repository = parent.repository()
              child_cert.sql_delete()

              def withdraw():
                repository.withdraw(child_cert.cert, child_cert.uri(ca), iterator2, withdraw_failed)

              def manifest_failed(e):
                rpki.log.traceback()
                rpki.log.warn("Couldn't reissue manifest for %r, skipping: %s" % (ca_detail, e))
                iterator2()

              def withdraw_failed(e):
                rpki.log.traceback()
                rpki.log.warn("Couldn't withdraw old child_cert %r, skipping: %s" % (child_cert, e))
                iterator2()

              ca_detail.generate_manifest(withdraw, manifest_failed)
              return

          iterator2()

        rpki.async.iterator(child_certs, loop2, iterator1)

      def irdb_lookup_failed(e):
        rpki.log.traceback()
        rpki.log.warn("Couldn't look up child's resources in IRDB, skipping child %r: %s" % (child, e))
        iterator1()

      child_certs = child.child_certs()
      if child_certs:
        self.gctx.irdb_query_child_resources(child.self().self_handle, child.child_handle, got_resources, irdb_lookup_failed)
      else:
        iterator1()

    rpki.async.iterator(self.children(), loop1, cb)


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

    def loop1(iterator1, parent):
      repository = parent.repository()

      def loop2(iterator2, ca):

        def fail2(e):
          rpki.log.traceback()
          rpki.log.warn("Couldn't regenerate CRLs and manifests for CA %r, skipping: %s" % (ca, e))
          iterator2()

        def loop3(iterator3, ca_detail):
          ca_detail.delete(ca, repository, iterator3, fail2)

        def done3():

          ca_detail = ca.fetch_active()

          def do_crl():
            ca_detail.generate_crl(do_manifest, fail2)

          def do_manifest():
            ca_detail.generate_manifest(iterator2, fail2)

          if ca_detail is not None and now > ca_detail.latest_crl.getNextUpdate():
            do_crl()
          else:
            iterator2()

        rpki.async.iterator([x for x in ca.fetch_revoked() if now > x.latest_crl.getNextUpdate()], loop3, done3)

      rpki.async.iterator(parent.cas(), loop2, iterator1)

    rpki.async.iterator(self.parents(), loop1, cb)


  def update_roas(self, cb):
    """
    Generate or update ROAs for this self.
    """

    def got_roa_requests(roa_requests):

      roas = dict(((r.asn, str(r.ipv4), str(r.ipv6)), r) for r in self.roas())

      def roa_requests_loop(iterator, roa_request):

        def lose(e):
          rpki.log.traceback()
          rpki.log.warn("Could not update ROA %r, skipping: %s" % (roa, e))
          iterator()

        key = (roa_request.asn, str(roa_request.ipv4), str(roa_request.ipv6))

        if key not in roas:
          # This really should be using a constructor
          roa = rpki.rpki_engine.roa_obj()
          roa.gctx = self.gctx
          roa.self_id = self.self_id
          roa.asn = roa_request.asn
          roa.ipv4 = roa_request.ipv4
          roa.ipv6 = roa_request.ipv6
          return roa.generate_roa(iterator, lose)

        roa = roas[key]
        del roas[key]

        ca_detail = roa.ca_detail()

        if ca_detail is None or ca_detail.state != "active":
          return roa.regenerate_roa(iterator, lose)

        regen_margin = rpki.sundial.timedelta(seconds = self.regen_margin)

        if rpki.sundial.now() + regen_margin > roa.cert.getNotAfter():
          return roa.regenerate_roa(iterator, lose)

        ca_resources = ca_detail.latest_ca_cert.get_3779resources()
        ee_resources = roa.cert.get_3779resources()

        if ee_resources.oversized(ca_resources):
          return roa.regenerate_roa(iterator, lose)

        v4 = roa.ipv4.to_resource_set() if roa.ipv4 is not None else rpki.resource_set.resource_set_ipv4()
        v6 = roa.ipv6.to_resource_set() if roa.ipv6 is not None else rpki.resource_set.resource_set_ipv6()

        if ee_resources.v4 != v4 or ee_resources.v6 != v6:
          return roa.regenerate_roa(iterator, lose)

        iterator()

      def roa_requests_done():

        # Any roa_obj entries still in the dict at this point are
        # orphans that no longer correspond to a roa_request, so clean
        # them up.

        def roa_withdraw_loop(iterator, roa):

          def lose(e):
            rpki.log.traceback()
            rpki.log.warn("Could not withdraw ROA %r: %s" % (roa, e))
            iterator()

          roa.withdraw(iterator, lose)

        rpki.async.iterator(roas.values(), roa_withdraw_loop, cb)

      rpki.async.iterator(roa_requests, roa_requests_loop, roa_requests_done)

    def roa_requests_failed(e):
      rpki.log.traceback()
      rpki.log.warn("Could not fetch ROA requests for %s, skipping: %s" % (self.self_handle, e))
      cb()

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
    """Fetch all repository objects that link to this BSC object."""
    return repository_elt.sql_fetch_where(self.gctx, "bsc_id = %s", (self.bsc_id,))

  def parents(self):
    """Fetch all parent objects that link to this BSC object."""
    return parent_elt.sql_fetch_where(self.gctx, "bsc_id = %s", (self.bsc_id,))

  def children(self):
    """Fetch all child objects that link to this BSC object."""
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
  elements = ("bpki_cms_cert", "bpki_cms_glue", "bpki_https_cert", "bpki_https_glue")

  sql_template = rpki.sql.template("repository", "repository_id", "repository_handle",
                                   "self_id", "bsc_id", "peer_contact_uri",
                                   ("bpki_cms_cert", rpki.x509.X509), ("bpki_cms_glue", rpki.x509.X509),
                                   ("bpki_https_cert", rpki.x509.X509), ("bpki_https_glue", rpki.x509.X509))
  handles = (("self", self_elt), ("bsc", bsc_elt))

  bpki_cms_cert = None
  bpki_cms_glue = None
  bpki_https_cert = None
  bpki_https_glue = None

  def parents(self):
    """Fetch all parent objects that link to this repository object."""
    return parent_elt.sql_fetch_where(self.gctx, "repository_id = %s", (self.repository_id,))

  def call_pubd(self, callback, errback, *pdus):
    """
    Send a message to publication daemon and return the response.
    """
    rpki.log.trace()
    bsc = self.bsc()
    q_msg = rpki.publication.msg.query(pdus)
    q_cms = rpki.publication.cms_msg.wrap(q_msg, bsc.private_key_id, bsc.signing_cert, bsc.signing_cert_crl)
    bpki_ta_path = (self.gctx.bpki_ta, self.self().bpki_cert, self.self().bpki_glue, self.bpki_https_cert, self.bpki_https_glue)

    def done(r_cms):
      try:
        r_msg = rpki.publication.cms_msg.unwrap(r_cms, bpki_ta_path)
        if len(r_msg) != 1 or isinstance(r_msg[0], rpki.publication.report_error_elt):
          raise rpki.exceptions.BadPublicationReply, "Unexpected response from pubd: %s" % msg
        callback()
      except (rpki.async.ExitNow, SystemExit):
        raise
      except Exception, edata:
        errback(edata)

    rpki.https.client(
      client_key   = bsc.private_key_id,
      client_cert  = bsc.signing_cert,
      server_ta    = bpki_ta_path,
      url          = self.peer_contact_uri,
      msg          = q_cms,
      callback     = done,
      errback      = errback)

  def publish(self, obj, uri, callback, errback):
    """
    Publish one object in the repository.
    """
    rpki.log.trace()
    rpki.log.info("Publishing %s as %s" % (repr(obj), repr(uri)))
    self.call_pubd(callback, errback, rpki.publication.obj2elt[type(obj)].make_pdu(action = "publish", uri = uri, payload = obj))

  def withdraw(self, obj, uri, callback, errback):
    """
    Withdraw one object from the repository.
    """
    rpki.log.trace()
    rpki.log.info("Withdrawing %s from at %s" % (repr(obj), repr(uri)))
    self.call_pubd(callback, errback, rpki.publication.obj2elt[type(obj)].make_pdu(action = "withdraw", uri = uri))

class parent_elt(data_elt):
  """
  <parent/> element.
  """

  element_name = "parent"
  attributes = ("action", "tag", "self_handle", "parent_handle", "bsc_handle", "repository_handle",
                "peer_contact_uri", "sia_base", "sender_name", "recipient_name")
  elements = ("bpki_cms_cert", "bpki_cms_glue", "bpki_https_cert", "bpki_https_glue")
  booleans = ("rekey", "reissue", "revoke")

  sql_template = rpki.sql.template("parent", "parent_id", "parent_handle",
                                   "self_id", "bsc_id", "repository_id",
                                   ("bpki_cms_cert", rpki.x509.X509), ("bpki_cms_glue", rpki.x509.X509),
                                   ("bpki_https_cert", rpki.x509.X509), ("bpki_https_glue", rpki.x509.X509),
                                   "peer_contact_uri", "sia_base", "sender_name", "recipient_name")
  handles = (("self", self_elt), ("bsc", bsc_elt), ("repository", repository_elt))

  bpki_cms_cert = None
  bpki_cms_glue = None
  bpki_https_cert = None
  bpki_https_glue = None

  def repository(self):
    """Fetch repository object to which this parent object links."""
    return repository_elt.sql_fetch(self.gctx, self.repository_id)

  def cas(self):
    """Fetch all CA objects that link to this parent object."""
    return rpki.rpki_engine.ca_obj.sql_fetch_where(self.gctx, "parent_id = %s", (self.parent_id,))

  def serve_post_save_hook(self, q_pdu, r_pdu, cb, eb):
    """
    Extra server actions for parent_elt.
    """
    if q_pdu.rekey:
      self.serve_rekey(cb, eb)
    elif q_pdu.revoke:
      self.serve_revoke(cb, eb)
    else:
      self.unimplemented_control("reissue")
      cb()

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
      ca.revoke(iterator, eb)

    rpki.async.iterator(self.cas(), loop, cb)

  def query_up_down(self, q_pdu, cb, eb):
    """
    Client code for sending one up-down query PDU to this parent.
    """

    rpki.log.trace()

    bsc = self.bsc()
    if bsc is None:
      raise rpki.exceptions.BSCNotFound, "Could not find BSC %s" % self.bsc_id

    if bsc.signing_cert is None:
      raise rpki.exceptions.BSCNotReady, "BSC %s is not yet usable" % self.bsc_id

    q_msg = rpki.up_down.message_pdu.make_query(
      payload = q_pdu,
      sender = self.sender_name,
      recipient = self.recipient_name)

    q_cms = rpki.up_down.cms_msg.wrap(q_msg, bsc.private_key_id,
                                      bsc.signing_cert,
                                      bsc.signing_cert_crl)

    def unwrap(der):
      r_msg = rpki.up_down.cms_msg.unwrap(der, (self.gctx.bpki_ta,
                                                self.self().bpki_cert, self.self().bpki_glue,
                                                self.bpki_cms_cert, self.bpki_cms_glue))
      r_msg.payload.check_response()
      cb(r_msg)

    rpki.https.client(server_ta    = (self.gctx.bpki_ta,
                                      self.self().bpki_cert, self.self().bpki_glue,
                                      self.bpki_https_cert, self.bpki_https_glue),
                      client_key   = bsc.private_key_id,
                      client_cert  = bsc.signing_cert,
                      msg          = q_cms,
                      url          = self.peer_contact_uri,
                      callback     = unwrap,
                      errback      = eb)

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
                                   ("bpki_glue", rpki.x509.X509))

  handles = (("self", self_elt), ("bsc", bsc_elt))

  bpki_cert = None
  bpki_glue = None
  clear_https_ta_cache = False

  def child_certs(self, ca_detail = None, ski = None, unique = False):
    """Fetch all child_cert objects that link to this child object."""
    return rpki.rpki_engine.child_cert_obj.fetch(self.gctx, self, ca_detail, ski, unique)

  def parents(self):
    """Fetch all parent objects that link to self object to which this child object links."""
    return parent_elt.sql_fetch_where(self.gctx, "self_id = %s", (self.self_id,))

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

  def serve_post_save_hook(self, q_pdu, r_pdu, cb, eb):
    """
    Extra server actions for child_elt.
    """
    self.unimplemented_control("reissue")
    if self.clear_https_ta_cache:
      self.gctx.clear_https_ta_cache()
      self.clear_https_ta_cache = False
    cb()

  def endElement(self, stack, name, text):
    """
    Handle subelements of <child/> element.  These require special
    handling because modifying them invalidates the HTTPS trust anchor
    cache.
    """
    rpki.xml_utils.data_elt.endElement(self, stack, name, text)
    if name in self.elements:
      self.clear_https_ta_cache = True

  def serve_up_down(self, query, callback):
    """
    Outer layer of server handling for one up-down PDU from this child.
    """

    rpki.log.trace()

    bsc = self.bsc()
    if bsc is None:
      raise rpki.exceptions.BSCNotFound, "Could not find BSC %s" % self.bsc_id
    q_msg = rpki.up_down.cms_msg.unwrap(query, (self.gctx.bpki_ta,
                                                self.self().bpki_cert, self.self().bpki_glue,
                                                self.bpki_cert, self.bpki_glue))
    q_msg.payload.gctx = self.gctx
    if enforce_strict_up_down_xml_sender and q_msg.sender != str(self.child_id):
      raise rpki.exceptions.BadSender, "Unexpected XML sender %s" % q_msg.sender

    def done(r_msg):
      #
      # Exceptions from this point on are problematic, as we have no
      # sane way of reporting errors in the error reporting mechanism.
      # May require refactoring, ignore the issue for now.
      #
      r_cms = rpki.up_down.cms_msg.wrap(r_msg, bsc.private_key_id,
                                        bsc.signing_cert, bsc.signing_cert_crl)
      callback(r_cms)

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

class report_error_elt(rpki.xml_utils.base_elt, left_right_namespace):
  """
  <report_error/> element.
  """

  element_name = "report_error"
  attributes = ("tag", "self_handle", "error_code")

  @classmethod
  def from_exception(cls, e, self_handle = None, tag = None):
    """
    Generate a <report_error/> element from an exception.
    """
    self = cls()
    self.self_handle = self_handle
    self.tag = tag
    self.error_code = e.__class__.__name__
    self.text = str(e)
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
              for x in (self_elt, child_elt, parent_elt, bsc_elt,
                        repository_elt, list_resources_elt,
                        list_roa_requests_elt, report_error_elt))

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
      except Exception, edata:
        fail(edata)

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
