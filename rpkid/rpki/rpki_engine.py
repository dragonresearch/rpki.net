"""Global context for rpkid.

$Id$

Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")

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

import traceback, lxml.etree
import rpki.resource_set, rpki.up_down, rpki.left_right, rpki.x509, rpki.sql
import rpki.https, rpki.config, rpki.exceptions, rpki.relaxng, rpki.log, rpki.async

class rpkid_context(object):
  """A container for various global rpkid parameters."""

  def __init__(self, cfg):

    self.sql = rpki.sql.session(cfg)

    self.bpki_ta    = rpki.x509.X509(Auto_file = cfg.get("bpki-ta"))
    self.irdb_cert  = rpki.x509.X509(Auto_file = cfg.get("irdb-cert"))
    self.irbe_cert  = rpki.x509.X509(Auto_file = cfg.get("irbe-cert"))
    self.rpkid_cert = rpki.x509.X509(Auto_file = cfg.get("rpkid-cert"))
    self.rpkid_key  = rpki.x509.RSA( Auto_file = cfg.get("rpkid-key"))

    self.irdb_url   = cfg.get("irdb-url")

    self.https_server_host = cfg.get("server-host", "")
    self.https_server_port = int(cfg.get("server-port", "4433"))

    self.publication_kludge_base = cfg.get("publication-kludge-base", "publication/")

  def irdb_query(self, self_id, child_id, callback):
    """Perform an IRDB callback query."""

    rpki.log.trace()

    q_msg = rpki.left_right.msg()
    q_msg.type = "query"
    q_msg.append(rpki.left_right.list_resources_elt())
    q_msg[0].self_id = self_id
    q_msg[0].child_id = child_id
    q_cms = rpki.left_right.cms_msg.wrap(q_msg, self.rpkid_key, self.rpkid_cert)

    def unwrap(der):
      r_msg = rpki.left_right.cms_msg.unwrap(der, (self.bpki_ta, self.irdb_cert))
      if len(r_msg) == 0 or not isinstance(r_msg[0], rpki.left_right.list_resources_elt) or r_msg.type != "reply":
        raise rpki.exceptions.BadIRDBReply, "Unexpected response to IRDB query: %s" % lxml.etree.tostring(r_msg.toXML(), pretty_print = True, encoding = "us-ascii")
      callback(rpki.resource_set.resource_bag(
        asn         = r_msg[0].asn,
        v4          = r_msg[0].ipv4,
        v6          = r_msg[0].ipv6,
        valid_until = r_msg[0].valid_until))

    rpki.https.client(
      server_ta    = (self.bpki_ta, self.irdb_cert),
      client_key   = self.rpkid_key,
      client_cert  = self.rpkid_cert,
      url          = self.irdb_url,
      msg          = q_cms,
      callback     = unwrap)

  def left_right_handler(self, query, path, cb):
    """Process one left-right PDU."""
    rpki.log.trace()

    def done(r_msg):
      reply = rpki.left_right.cms_msg.wrap(r_msg, self.rpkid_key, self.rpkid_cert)
      self.sql.sweep()
      cb(200, reply)

    try:
      self.sql.ping()
      q_msg = rpki.left_right.cms_msg.unwrap(query, (self.bpki_ta, self.irbe_cert))
      if q_msg.type != "query":
        raise rpki.exceptions.BadQuery, "Message type is not query"
      q_msg.serve_top_level(self, done)
    except Exception, data:
      rpki.log.error(traceback.format_exc())
      cb(500, "Unhandled exception %s" % data)

  def up_down_handler(self, query, path, cb):
    """Process one up-down PDU."""
    rpki.log.trace()

    def done(reply):
      self.sql.sweep()
      cb(200, reply)

    try:
      self.sql.ping()
      child_id = path.partition("/up-down/")[2]
      if not child_id.isdigit():
        raise rpki.exceptions.BadContactURL, "Bad path: %s" % path
      child = rpki.left_right.child_elt.sql_fetch(self, long(child_id))
      if child is None:
        raise rpki.exceptions.ChildNotFound, "Could not find child %s" % child_id
      child.serve_up_down(query, done)
    except Exception, data:
      rpki.log.error(traceback.format_exc())
      cb(400, "Could not process PDU: %s" % data)

  def cronjob_handler(self, query, path, cb):
    """Periodic tasks.  This will need another rewrite once we have internal timers."""

    rpki.log.trace()
    self.sql.ping()

    def each(iterator, s):

      def one():
        rpki.log.debug("Self %s polling parents" % s.self_id)
        s.client_poll(two)

      def two():
        rpki.log.debug("Self %s updating children" % s.self_id)
        s.update_children(three)

      def three():
        rpki.log.debug("Self %s updating ROAs" % s.self_id)
        s.update_roas(four)

      def four():
        rpki.log.debug("Self %s regenerating CRLs and manifests" % s.self_id)
        s.regenerate_crls_and_manifests(iterator)

      one()

    def done():
      self.sql.sweep()
      cb(200, "OK")

    rpki.async.iterator(rpki.left_right.self_elt.sql_fetch_all(self), each, done)

  ## @var https_ta_cache
  # HTTPS trust anchor cache, to avoid regenerating it for every TLS connection.
  https_ta_cache = None

  def clear_https_ta_cache(self):
    """Clear dynamic TLS trust anchors."""

    if self.https_ta_cache is not None:
      rpki.log.debug("Clearing HTTPS trusted cert cache")
      self.https_ta_cache = None

  def build_https_ta_cache(self):
    """Build dynamic TLS trust anchors."""

    if self.https_ta_cache is None:

      selves = rpki.left_right.self_elt.sql_fetch_all(self)
      children = rpki.left_right.child_elt.sql_fetch_all(self)

      self.https_ta_cache = rpki.https.build_https_ta_cache(
        [c.bpki_cert for c in children if c.bpki_cert is not None] +
        [c.bpki_glue for c in children if c.bpki_glue is not None] +
        [s.bpki_cert for s in selves if s.bpki_cert is not None] +
        [s.bpki_glue for s in selves if s.bpki_glue is not None] +
        [self.irbe_cert, self.irdb_cert, self.bpki_ta])

    return self.https_ta_cache


class ca_obj(rpki.sql.sql_persistant):
  """Internal CA object."""

  sql_template = rpki.sql.template(
    "ca",
    "ca_id",
    "last_crl_sn",
    ("next_crl_update", rpki.sundial.datetime),
    "last_issued_sn", "last_manifest_sn",
    ("next_manifest_update", rpki.sundial.datetime),
    "sia_uri", "parent_id", "parent_resource_class")

  last_crl_sn = 0
  last_issued_sn = 0
  last_manifest_sn = 0

  def parent(self):
    """Fetch parent object to which this CA object links."""
    return rpki.left_right.parent_elt.sql_fetch(self.gctx, self.parent_id)

  def ca_details(self):
    """Fetch all ca_detail objects that link to this CA object."""
    return ca_detail_obj.sql_fetch_where(self.gctx, "ca_id = %s", (self.ca_id,))

  def fetch_pending(self):
    """Fetch the pending ca_details for this CA, if any."""
    return ca_detail_obj.sql_fetch_where(self.gctx, "ca_id = %s AND state = 'pending'", (self.ca_id,))

  def fetch_active(self):
    """Fetch the active ca_detail for this CA, if any."""
    return ca_detail_obj.sql_fetch_where1(self.gctx, "ca_id = %s AND state = 'active'", (self.ca_id,))

  def fetch_deprecated(self):
    """Fetch deprecated ca_details for this CA, if any."""
    return ca_detail_obj.sql_fetch_where(self.gctx, "ca_id = %s AND state = 'deprecated'", (self.ca_id,))

  def fetch_revoked(self):
    """Fetch revoked ca_details for this CA, if any."""
    return ca_detail_obj.sql_fetch_where(self.gctx, "ca_id = %s AND state = 'revoked'", (self.ca_id,))

  def construct_sia_uri(self, parent, rc):
    """Construct the sia_uri value for this CA given configured
    information and the parent's up-down protocol list_response PDU.
    """

    sia_uri = rc.suggested_sia_head and rc.suggested_sia_head.rsync()
    if not sia_uri or not sia_uri.startswith(parent.sia_base):
      sia_uri = parent.sia_base
    elif not sia_uri.endswith("/"):
      raise rpki.exceptions.BadURISyntax, "SIA URI must end with a slash: %s" % sia_uri
    return sia_uri + str(self.ca_id) + "/"

  def check_for_updates(self, parent, rc, cb):
    """Parent has signaled continued existance of a resource class we
    already knew about, so we need to check for an updated
    certificate, changes in resource coverage, revocation and reissue
    with the same key, etc.
    """

    sia_uri = self.construct_sia_uri(parent, rc)
    sia_uri_changed = self.sia_uri != sia_uri
    if sia_uri_changed:
      self.sia_uri = sia_uri
      self.sql_mark_dirty()

    rc_resources = rc.to_resource_bag()
    cert_map = dict((c.cert.get_SKI(), c) for c in rc.certs)

    def loop(iterator, ca_detail):

      ski = ca_detail.latest_ca_cert.get_SKI()

      if ski not in cert_map:
        rpki.log.warn("Certificate in database missing from list_response, class %s, SKI %s, maybe parent certificate went away?"
                      % (repr(rc.class_name), ca_detail.latest_ca_cert.gSKI()))
        return ca_detail.delete(self, parent.repository(), iterator)

      def cleanup():
        del cert_map[ski]
        iterator()

      if ca_detail.state in ("pending", "active"):
        current_resources = ca_detail.latest_ca_cert.get_3779resources()
        if (sia_uri_changed or
            ca_detail.latest_ca_cert != cert_map[ski].cert or
            current_resources.undersized(rc_resources) or
            current_resources.oversized(rc_resources)):
          return ca_detail.update(
            parent           = parent,
            ca               = self,
            rc               = rc,
            sia_uri_changed  = sia_uri_changed,
            old_resources    = current_resources,
            callback         = cleanup)

      cleanup()

    def done():
      if cert_map:
        rpki.log.warn("Certificates in list_response missing from our database, class %s, SKIs %s"
                      % (repr(rc.class_name), ", ".join(c.cert.gSKI() for c in cert_map.values())))
      cb()

    rpki.async.iterator(ca_detail_obj.sql_fetch_where(self.gctx, "ca_id = %s AND latest_ca_cert IS NOT NULL AND state != 'revoked'", (self.ca_id,)), loop, done)

  @classmethod
  def create(cls, parent, rc, cb):
    """Parent has signaled existance of a new resource class, so we
    need to create and set up a corresponding CA object.
    """

    self = cls()
    self.gctx = parent.gctx
    self.parent_id = parent.parent_id
    self.parent_resource_class = rc.class_name
    self.sql_store()
    self.sia_uri = self.construct_sia_uri(parent, rc)
    ca_detail = ca_detail_obj.create(self)

    def done(issue_response):
      ca_detail.activate(
        ca       = self,
        cert     = issue_response.payload.classes[0].certs[0].cert,
        uri      = issue_response.payload.classes[0].certs[0].cert_url,
        callback = cb)

    rpki.up_down.issue_pdu.query(parent, self, ca_detail, done)

  def delete(self, parent):
    """The list of current resource classes received from parent does
    not include the class corresponding to this CA, so we need to
    delete it (and its little dog too...).

    All certs published by this CA are now invalid, so need to
    withdraw them, the CRL, and the manifest from the repository,
    delete all child_cert and ca_detail records associated with this
    CA, then finally delete this CA itself.
    """

    repository = parent.repository()
    for ca_detail in self.ca_details():
      ca_detail.delete(self, repository)
    self.sql_delete()

  def next_serial_number(self):
    """Allocate a certificate serial number."""
    self.last_issued_sn += 1
    self.sql_mark_dirty()
    return self.last_issued_sn

  def next_manifest_number(self):
    """Allocate a manifest serial number."""
    self.last_manifest_sn += 1
    self.sql_mark_dirty()
    return self.last_manifest_sn

  def next_crl_number(self):
    """Allocate a CRL serial number."""
    self.last_crl_sn += 1
    self.sql_mark_dirty()
    return self.last_crl_sn

  def rekey(self, cb):
    """Initiate a rekey operation for this ca.  Generate a new
    keypair.  Request cert from parent using new keypair.  Mark result
    as our active ca_detail.  Reissue all child certs issued by this
    ca using the new ca_detail.
    """

    rpki.log.trace()

    parent = self.parent()
    old_detail = self.fetch_active()
    new_detail = ca_detail_obj.create(self)

    def done(issue_response):
      new_detail.activate(
        ca          = self,
        cert        = issue_response.payload.classes[0].certs[0].cert,
        uri         = issue_response.payload.classes[0].certs[0].cert_url,
        predecessor = old_detail,
        callback    = cb)

    rpki.up_down.issue_pdu.query(parent, self, new_detail, done)

  def revoke(self, cb):
    """Revoke deprecated ca_detail objects associated with this ca."""

    rpki.log.trace()

    def loop(iterator, ca_detail):
      ca_detail.revoke(iterator)

    rpki.async.iterator(self.fetch_deprecated(), loop, cb)

class ca_detail_obj(rpki.sql.sql_persistant):
  """Internal CA detail object."""

  sql_template = rpki.sql.template(
    "ca_detail",
    "ca_detail_id",
    ("private_key_id",          rpki.x509.RSA),
    ("public_key",              rpki.x509.RSApublic),
    ("latest_ca_cert",          rpki.x509.X509),
    ("manifest_private_key_id", rpki.x509.RSA),
    ("manifest_public_key",     rpki.x509.RSApublic),
    ("latest_manifest_cert",    rpki.x509.X509),
    ("latest_manifest",         rpki.x509.SignedManifest),
    ("latest_crl",              rpki.x509.CRL),
    "state",
    "ca_cert_uri",
    "ca_id")
  
  def sql_decode(self, vals):
    """Extra assertions for SQL decode of a ca_detail_obj."""
    rpki.sql.sql_persistant.sql_decode(self, vals)
    assert (self.public_key is None and self.private_key_id is None) or \
           self.public_key.get_DER() == self.private_key_id.get_public_DER()
    assert (self.manifest_public_key is None and self.manifest_private_key_id is None) or \
           self.manifest_public_key.get_DER() == self.manifest_private_key_id.get_public_DER()

  def ca(self):
    """Fetch CA object to which this ca_detail links."""
    return ca_obj.sql_fetch(self.gctx, self.ca_id)

  def child_certs(self, child = None, ski = None, unique = False):
    """Fetch all child_cert objects that link to this ca_detail."""
    return rpki.rpki_engine.child_cert_obj.fetch(self.gctx, child, self, ski, unique)

  def revoked_certs(self):
    """Fetch all revoked_cert objects that link to this ca_detail."""
    return revoked_cert_obj.sql_fetch_where(self.gctx, "ca_detail_id = %s", (self.ca_detail_id,))

  def route_origins(self):
    """Fetch all route_origin objects that link to this ca_detail."""
    return rpki.left_right.route_origin_elt.sql_fetch_where(self.gctx, "ca_detail_id = %s", (self.ca_detail_id,))

  def crl_uri(self, ca):
    """Return publication URI for this ca_detail's CRL."""
    return ca.sia_uri + self.crl_uri_tail()

  def crl_uri_tail(self):
    """Return tail (filename portion) of publication URI for this ca_detail's CRL."""
    return self.public_key.gSKI() + ".crl"

  def manifest_uri(self, ca):
    """Return publication URI for this ca_detail's manifest."""
    return ca.sia_uri + self.public_key.gSKI() + ".mnf"

  def activate(self, ca, cert, uri, predecessor = None, callback = None):
    """Activate this ca_detail."""

    assert callback is not None         # hack to catch positional arguments

    self.latest_ca_cert = cert
    self.ca_cert_uri = uri.rsync()
    self.generate_manifest_cert(ca)

    def did_crl(*ignored):
      self.generate_manifest(callback = did_manifest)

    def did_manifest(*ignored):
      self.state = "active"
      self.sql_mark_dirty()
      if predecessor is None:
        callback()
      else:
        predecessor.state = "deprecated"
        predecessor.sql_mark_dirty()
        rpki.async.iterator(predecessor.child_certs(), do_one_child_cert, done_child_certs)

    def do_one_child_cert(iterator, child_cert):
      child_cert.reissue(self, iterator)

    def done_child_certs():
      rpki.async.iterator(predecessor.route_origins(), do_one_route_origin, callback)

    def do_one_route_origin(iterator, route_origin):
      route_origin.regenerate_roa(iterator)

    self.generate_crl(callback = did_crl)

  def delete(self, ca, repository, cb):
    """Delete this ca_detail and all of the certs it issued."""

    def withdraw_one_child(iterator, child_cert):
      repository.withdraw(child_cert.cert, child_cert.uri(ca), iterator)

    def child_certs_done():
      rpki.async.iterator(self.route_origins(), withdraw_one_roa, withdraw_manifest)

    def withdraw_one_roa(iterator, route_origin):
      route_origin.withdraw_roa(iterator)

    def withdraw_manifest(*ignored):
      repository.withdraw(self.latest_manifest, self.manifest_uri(ca), withdraw_crl)

    def withdraw_crl(*ignored):
      repository.withdraw(self.latest_crl, self.crl_uri(ca), done)

    def done(*ignored):
      for cert in self.child_certs() + self.revoked_certs():
        cert.sql_delete()
      self.sql_delete()
      cb()

    rpki.async.iterator(self.child_certs(), withdraw_one_child, child_certs_done)

  def revoke(self, cb):
    """Request revocation of all certificates whose SKI matches the key for this ca_detail.

    Tasks:

    - Request revocation of old keypair by parent.

    - Revoke all child certs issued by the old keypair.

    - Generate a final CRL, signed with the old keypair, listing all
      the revoked certs, with a next CRL time after the last cert or
      CRL signed by the old keypair will have expired.

    - Generate a corresponding final manifest.

    - Destroy old keypairs.

    - Leave final CRL and manifest in place until their nextupdate time has passed.
    """

    def parent_revoked(r_msg):

      if r_msg.payload.ski != self.latest_ca_cert.gSKI():
        raise rpki.exceptions.SKIMismatch

      ca = self.ca()
      parent = ca.parent()
      crl_interval = rpki.sundial.timedelta(seconds = parent.self().crl_interval)

      self.nextUpdate = rpki.sundial.now()

      if self.latest_manifest is not None:
        self.nextUpdate = self.nextUpdate.later(self.latest_manifest.getNextUpdate())

      if self.latest_crl is not None:
        self.nextUpdate = self.nextUpdate.later(self.latest_crl.getNextUpdate())

      def revoke_one_child(iterator, child_cert):
        self.nextUpdate = self.nextUpdate.later(child_cert.cert.getNotAfter())
        child_cert.revoke(iterator)

      def final_crl():
        self.nextUpdate += crl_interval
        self.generate_crl(callback = final_manifest, nextUpdate = self.nextUpdate)

      def final_manifest(*ignored):
        self.generate_manifest(callback = done, nextUpdate = self.nextUpdate)

      def done(*ignored):
        self.private_key_id = None
        self.manifest_private_key_id = None
        self.manifest_public_key = None
        self.latest_manifest_cert = None
        self.state = "revoked"
        self.sql_mark_dirty()
        cb()

      rpki.async.iterator(self.child_certs(), revoke_one_child, final_crl)

    rpki.up_down.revoke_pdu.query(self, parent_revoked)

  def update(self, parent, ca, rc, sia_uri_changed, old_resources, callback):
    """Need to get a new certificate for this ca_detail and perhaps
    frob children of this ca_detail.
    """

    def issued(issue_response):
      self.latest_ca_cert = issue_response.payload.classes[0].certs[0].cert
      new_resources = self.latest_ca_cert.get_3779resources()

      def loop(iterator, child_cert):
        child_resources = child_cert.cert.get_3779resources()
        if sia_uri_changed or child_resources.oversized(new_resources):
          child_cert.reissue(
            ca_detail = self,
            resources = child_resources.intersection(new_resources),
            callback  = iterator)
        else:
          iterator()

      if sia_uri_changed or old_resources.oversized(new_resources):
        rpki.async.iterator(self.child_certs(), loop, callback)
      else:
        callback()

    rpki.up_down.issue_pdu.query(parent, ca, self, issued)

  @classmethod
  def create(cls, ca):
    """Create a new ca_detail object for a specified CA."""
    self = cls()
    self.gctx = ca.gctx
    self.ca_id = ca.ca_id
    self.state = "pending"

    self.private_key_id = rpki.x509.RSA.generate()
    self.public_key = self.private_key_id.get_RSApublic()

    self.manifest_private_key_id = rpki.x509.RSA.generate()
    self.manifest_public_key = self.manifest_private_key_id.get_RSApublic()

    self.sql_store()
    return self

  def issue_ee(self, ca, resources, subject_key, sia = None):
    """Issue a new EE certificate."""

    return self.latest_ca_cert.issue(
      keypair     = self.private_key_id,
      subject_key = subject_key,
      serial      = ca.next_serial_number(),
      sia         = sia,
      aia         = self.ca_cert_uri,
      crldp       = self.crl_uri(ca),
      resources   = resources,
      notAfter    = self.latest_ca_cert.getNotAfter(),
      is_ca       = False)


  def generate_manifest_cert(self, ca):
    """Generate a new manifest certificate for this ca_detail."""

    resources = rpki.resource_set.resource_bag(
      asn = rpki.resource_set.resource_set_as("<inherit>"),
      v4 = rpki.resource_set.resource_set_ipv4("<inherit>"),
      v6 = rpki.resource_set.resource_set_ipv6("<inherit>"))

    self.latest_manifest_cert = self.issue_ee(ca, resources, self.manifest_public_key)

  def issue(self, ca, child, subject_key, sia, resources, callback, child_cert = None):
    """Issue a new certificate to a child.  Optional child_cert
    argument specifies an existing child_cert object to update in
    place; if not specified, we create a new one.  Returns the
    child_cert object containing the newly issued cert.
    """

    assert child_cert is None or (child_cert.child_id == child.child_id and
                                  child_cert.ca_detail_id == self.ca_detail_id)

    cert = self.latest_ca_cert.issue(
      keypair     = self.private_key_id,
      subject_key = subject_key,
      serial      = ca.next_serial_number(),
      aia         = self.ca_cert_uri,
      crldp       = self.crl_uri(ca),
      sia         = sia,
      resources   = resources,
      notAfter    = resources.valid_until)

    if child_cert is None:
      child_cert = rpki.rpki_engine.child_cert_obj(
        gctx         = child.gctx,
        child_id     = child.child_id,
        ca_detail_id = self.ca_detail_id,
        cert         = cert)
      rpki.log.debug("Created new child_cert %s" % repr(child_cert))
    else:
      child_cert.cert = cert
      rpki.log.debug("Reusing existing child_cert %s" % repr(child_cert))

    child_cert.ski = cert.get_SKI()

    child_cert.sql_store()

    def published(*ignored):
      self.generate_manifest(done)

    def done(*ignored):
      callback(child_cert)
      
    ca.parent().repository().publish(child_cert.cert, child_cert.uri(ca), published)

  def generate_crl(self, callback, nextUpdate = None):
    """Generate a new CRL for this ca_detail.  At the moment this is
    unconditional, that is, it is up to the caller to decide whether a
    new CRL is needed.
    """

    ca = self.ca()
    parent = ca.parent()
    repository = parent.repository()
    crl_interval = rpki.sundial.timedelta(seconds = parent.self().crl_interval)
    now = rpki.sundial.now()

    if nextUpdate is None:
      nextUpdate = now + crl_interval

    certlist = []
    for revoked_cert in self.revoked_certs():
      if now > revoked_cert.expires + crl_interval:
        revoked_cert.sql_delete()
      else:
        certlist.append((revoked_cert.serial, revoked_cert.revoked.toASN1tuple(), ()))
    certlist.sort()

    self.latest_crl = rpki.x509.CRL.generate(
      keypair             = self.private_key_id,
      issuer              = self.latest_ca_cert,
      serial              = ca.next_crl_number(),
      thisUpdate          = now,
      nextUpdate          = nextUpdate,
      revokedCertificates = certlist)

    repository.publish(self.latest_crl, self.crl_uri(ca), callback = callback)

  def generate_manifest(self, callback, nextUpdate = None):
    """Generate a new manifest for this ca_detail."""

    ca = self.ca()
    parent = ca.parent()
    repository = parent.repository()
    crl_interval = rpki.sundial.timedelta(seconds = parent.self().crl_interval)
    now = rpki.sundial.now()

    if nextUpdate is None:
      nextUpdate = now + crl_interval

    route_origins = [r for r in self.route_origins() if r.cert is not None and r.roa is not None]

    if self.latest_manifest_cert is None or self.latest_manifest_cert.getNotAfter() < nextUpdate:
      self.generate_manifest_cert(ca)

    certs = [(c.uri_tail(), c.cert) for c in self.child_certs()] + \
            [(r.roa_uri_tail(), r.roa) for r in route_origins] + \
            [(r.ee_uri_tail(), r.cert) for r in route_origins] + \
            [(self.crl_uri_tail(), self.latest_crl)]

    self.latest_manifest = rpki.x509.SignedManifest.build(
      serial         = ca.next_manifest_number(),
      thisUpdate     = now,
      nextUpdate     = nextUpdate,
      names_and_objs = certs,
      keypair        = self.manifest_private_key_id,
      certs          = self.latest_manifest_cert)

    repository.publish(self.latest_manifest, self.manifest_uri(ca), callback = callback)

class child_cert_obj(rpki.sql.sql_persistant):
  """Certificate that has been issued to a child."""

  sql_template = rpki.sql.template(
    "child_cert",
    "child_cert_id",
    ("cert", rpki.x509.X509),
    "child_id",
    "ca_detail_id",
    "ski")

  def __init__(self, gctx = None, child_id = None, ca_detail_id = None, cert = None):
    """Initialize a child_cert_obj."""
    self.gctx = gctx
    self.child_id = child_id
    self.ca_detail_id = ca_detail_id
    self.cert = cert
    if child_id or ca_detail_id or cert:
      self.sql_mark_dirty()

  def child(self):
    """Fetch child object to which this child_cert object links."""
    return rpki.left_right.child_elt.sql_fetch(self.gctx, self.child_id)

  def ca_detail(self):
    """Fetch ca_detail object to which this child_cert object links."""
    return ca_detail_obj.sql_fetch(self.gctx, self.ca_detail_id)

  def uri_tail(self):
    """Return the tail (filename) portion of the URI for this child_cert."""
    return self.cert.gSKI() + ".cer"

  def uri(self, ca):
    """Return the publication URI for this child_cert."""
    return ca.sia_uri + self.uri_tail()

  def revoke(self, callback):
    """Revoke a child cert."""

    rpki.log.debug("Revoking %s" % repr(self))
    ca_detail = self.ca_detail()
    ca = ca_detail.ca()
    revoked_cert_obj.revoke(cert = self.cert, ca_detail = ca_detail)
    repository = ca.parent().repository()

    def done(*ignored):
      self.gctx.sql.sweep()
      self.sql_delete()
      callback()

    repository.withdraw(self.cert, self.uri(ca), done)

  def reissue(self, ca_detail, callback = None, resources = None, sia = None):
    """Reissue an existing cert, reusing the public key.  If the cert
    we would generate is identical to the one we already have, we just
    return the one we already have.  If we have to revoke the old
    certificate when generating the new one, we have to generate a new
    child_cert_obj, so calling code that needs the updated
    child_cert_obj must use the return value from this method.
    """

    assert callback is not None

    ca = ca_detail.ca()
    child = self.child()

    old_resources = self.cert.get_3779resources()
    old_sia       = self.cert.get_SIA()
    old_ca_detail = self.ca_detail()

    if resources is None:
      resources = old_resources

    if sia is None:
      sia = old_sia

    assert resources.valid_until is not None and old_resources.valid_until is not None

    if resources == old_resources and sia == old_sia and ca_detail == old_ca_detail:
      return callback(self)

    must_revoke = old_resources.oversized(resources) or old_resources.valid_until > resources.valid_until
    new_issuer  = ca_detail != old_ca_detail

    if resources.valid_until != old_resources.valid_until:
      rpki.log.debug("Validity changed: %s %s" % ( old_resources.valid_until, resources.valid_until))

    if must_revoke or new_issuer:
      child_cert = None
    else:
      child_cert = self

    def revoke(child_cert):

      def do_one_cert(iterator, cert):
        cert.revoke(iterator)

      def done():
        callback(child_cert)        

      rpki.async.iterator([x for x in child.child_certs(ca_detail = ca_detail, ski = self.ski) if x is not child_cert], do_one_cert, done)

    child_cert = ca_detail.issue(
      ca          = ca,
      child       = child,
      subject_key = self.cert.getPublicKey(),
      sia         = sia,
      resources   = resources,
      child_cert  = child_cert,
      callback    = revoke if must_revoke else callback)

  @classmethod
  def fetch(cls, gctx = None, child = None, ca_detail = None, ski = None, unique = False):
    """Fetch all child_cert objects matching a particular set of
    parameters.  This is a wrapper to consolidate various queries that
    would otherwise be inline SQL WHERE expressions.  In most cases
    code calls this indirectly, through methods in other classes.
    """

    args = []
    where = []

    if child:
      where.append("child_id = %s")
      args.append(child.child_id)

    if ca_detail:
      where.append("ca_detail_id = %s")
      args.append(ca_detail.ca_detail_id)

    if ski:
      where.append("ski = %s")
      args.append(ski)

    where = " AND ".join(where)

    gctx = gctx or (child and child.gctx) or (ca_detail and ca_detail.gctx) or None

    if unique:
      return cls.sql_fetch_where1(gctx, where, args)
    else:
      return cls.sql_fetch_where(gctx, where, args)

class revoked_cert_obj(rpki.sql.sql_persistant):
  """Tombstone for a revoked certificate."""

  sql_template = rpki.sql.template(
    "revoked_cert",
    "revoked_cert_id",
    "serial",
    "ca_detail_id",
    ("revoked", rpki.sundial.datetime),
    ("expires", rpki.sundial.datetime))

  def __init__(self, gctx = None, serial = None, revoked = None, expires = None, ca_detail_id = None):
    """Initialize a revoked_cert_obj."""
    self.gctx = gctx
    self.serial = serial
    self.revoked = revoked
    self.expires = expires
    self.ca_detail_id = ca_detail_id
    if serial or revoked or expires or ca_detail_id:
      self.sql_mark_dirty()

  def ca_detail(self):
    """Fetch ca_detail object to which this revoked_cert_obj links."""
    return ca_detail_obj.sql_fetch(self.gctx, self.ca_detail_id)

  @classmethod
  def revoke(cls, cert, ca_detail):
    """Revoke a certificate."""
    return cls(
      serial       = cert.getSerial(),
      expires      = cert.getNotAfter(),
      revoked      = rpki.sundial.now(),
      gctx         = ca_detail.gctx,
      ca_detail_id = ca_detail.ca_detail_id)
