"""
Global context for rpkid.

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

import lxml.etree, re, random
import rpki.resource_set, rpki.up_down, rpki.left_right, rpki.x509, rpki.sql
import rpki.https, rpki.config, rpki.exceptions, rpki.relaxng, rpki.log, rpki.async

class rpkid_context(object):
  """
  A container for various global rpkid parameters.
  """

  def __init__(self, cfg):

    self.sql = rpki.sql.session(cfg)

    self.bpki_ta    = rpki.x509.X509(Auto_file = cfg.get("bpki-ta"))
    self.irdb_cert  = rpki.x509.X509(Auto_file = cfg.get("irdb-cert"))
    self.irbe_cert  = rpki.x509.X509(Auto_file = cfg.get("irbe-cert"))
    self.rpkid_cert = rpki.x509.X509(Auto_file = cfg.get("rpkid-cert"))
    self.rpkid_key  = rpki.x509.RSA( Auto_file = cfg.get("rpkid-key"))

    self.irdb_url   = cfg.get("irdb-url")

    self.https_server_host = cfg.get("server-host", "")
    self.https_server_port = cfg.getint("server-port", 4433)

    self.publication_kludge_base = cfg.get("publication-kludge-base", "publication/")

    self.use_internal_cron = cfg.getboolean("use-internal-cron", True)

    self.initial_delay = random.randint(cfg.getint("initial-delay-min", 10),
                                        cfg.getint("initial-delay-max", 120))
    
    self.cron_period = cfg.getint("cron-period", 120) # Should be much longer in production

  def start_cron(self):
    """
    Start clock for rpkid's internal cron process.
    """

    if self.use_internal_cron:
      when = rpki.sundial.now() + rpki.sundial.timedelta(seconds = self.initial_delay)
      rpki.log.debug("Scheduling initial cron pass at %s" % when)
      rpki.async.timer(handler = self.cron).set(when)
    else:
      rpki.log.debug("Not using internal clock, start_cron() call ignored")

  def irdb_query(self, q_pdu, callback, errback):
    """
    Perform an IRDB callback query.
    """

    rpki.log.trace()

    q_msg = rpki.left_right.msg.query()
    q_msg.append(q_pdu)
    q_cms = rpki.left_right.cms_msg.wrap(q_msg, self.rpkid_key, self.rpkid_cert)

    def unwrap(der):
      r_msg = rpki.left_right.cms_msg.unwrap(der, (self.bpki_ta, self.irdb_cert))
      if not r_msg.is_reply() or [r_pdu for r_pdu in r_msg if type(r_pdu) is not type(q_pdu)]:
        raise rpki.exceptions.BadIRDBReply, "Unexpected response to IRDB query: %s" % lxml.etree.tostring(r_msg.toXML(), pretty_print = True, encoding = "us-ascii")
      callback(r_msg)

    rpki.https.client(
      server_ta    = (self.bpki_ta, self.irdb_cert),
      client_key   = self.rpkid_key,
      client_cert  = self.rpkid_cert,
      url          = self.irdb_url,
      msg          = q_cms,
      callback     = unwrap,
      errback      = errback)

  def irdb_query_child_resources(self, self_handle, child_handle, callback, errback):
    """
    Ask IRDB about a child's resources.
    """

    rpki.log.trace()

    q_pdu = rpki.left_right.list_resources_elt()
    q_pdu.self_handle = self_handle
    q_pdu.child_handle = child_handle

    def done(r_msg):
      if len(r_msg) != 1:
        raise rpki.exceptions.BadIRDBReply, "Expected exactly one PDU from IRDB: %s" % lxml.etree.tostring(r_msg.toXML(), pretty_print = True, encoding = "us-ascii")
      callback(rpki.resource_set.resource_bag(
        asn         = r_msg[0].asn,
        v4          = r_msg[0].ipv4,
        v6          = r_msg[0].ipv6,
        valid_until = r_msg[0].valid_until))

    self.irdb_query(q_pdu, done, errback)

  def irdb_query_roa_requests(self, self_handle, callback, errback):
    """
    Ask IRDB about self's ROA requests.
    """

    rpki.log.trace()

    q_pdu = rpki.left_right.list_roa_requests_elt()
    q_pdu.self_handle = self_handle

    self.irdb_query(q_pdu, callback, errback)

  def left_right_handler(self, query, path, cb):
    """
    Process one left-right PDU.
    """

    rpki.log.trace()

    def done(r_msg):
      reply = rpki.left_right.cms_msg.wrap(r_msg, self.rpkid_key, self.rpkid_cert)
      self.sql.sweep()
      cb(200, reply)

    try:
      self.sql.ping()
      q_msg = rpki.left_right.cms_msg.unwrap(query, (self.bpki_ta, self.irbe_cert))
      if not q_msg.is_query():
        raise rpki.exceptions.BadQuery, "Message type is not query"
      q_msg.serve_top_level(self, done)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception, data:
      rpki.log.traceback()
      cb(500, "Unhandled exception %s" % data)

  up_down_url_regexp = re.compile("/up-down/([-A-Z0-9_]+)/([-A-Z0-9_]+)$", re.I)

  def up_down_handler(self, query, path, cb):
    """
    Process one up-down PDU.
    """

    rpki.log.trace()

    def done(reply):
      self.sql.sweep()
      cb(200, reply)

    try:
      self.sql.ping()
      match = self.up_down_url_regexp.search(path)
      if match is None:
        raise rpki.exceptions.BadContactURL, "Bad path: %s" % path
      self_handle, child_handle = match.groups()
      child = rpki.left_right.child_elt.sql_fetch_where1(self, "self.self_handle = %s AND child.child_handle = %s AND child.self_id = self.self_id",
                                                         (self_handle, child_handle), "self")
      if child is None:
        raise rpki.exceptions.ChildNotFound, "Could not find child %s" % child_handle
      child.serve_up_down(query, done)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception, data:
      rpki.log.traceback()
      cb(400, "Could not process PDU: %s" % data)

  def cron(self, cb = None):
    """
    Periodic tasks.
    """

    rpki.log.trace()
    self.sql.ping()

    def loop(iterator, s):

      def one():
        rpki.log.debug("Self %s[%d] polling parents" % (s.self_handle, s.self_id))
        s.client_poll(two)

      def two():
        rpki.log.debug("Self %s[%d] updating children" % (s.self_handle, s.self_id))
        s.update_children(three)

      def three():
        rpki.log.debug("Self %s[%d] updating ROAs" % (s.self_handle, s.self_id))
        s.update_roas(four)

      def four():
        rpki.log.debug("Self %s[%d] regenerating CRLs and manifests" % (s.self_handle, s.self_id))
        s.regenerate_crls_and_manifests(iterator)

      one()

    def sched():
      when = rpki.sundial.now() + rpki.sundial.timedelta(seconds = self.cron_period)
      rpki.log.debug("Scheduling next cron run at %s" % when)
      rpki.async.timer(handler = self.cron).set(when)

    def done():
      self.sql.sweep()
      if self.use_internal_cron:
        sched()
      else:
        cb()

    try:
      rpki.async.iterator(rpki.left_right.self_elt.sql_fetch_all(self), loop, done)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception, data:
      if self.use_internal_cron:
        rpki.log.traceback()
        sched()
      else:
        raise

  def cronjob_handler(self, query, path, cb):
    """
    External trigger for periodic tasks.  This is somewhat obsolete
    now that we have internal timers, but the test framework still
    uses it.
    """

    if self.use_internal_cron:
      cb(500, "Running cron internally")
    else:
      self.cron(lambda: cb(200, "OK"))

  ## @var https_ta_cache
  # HTTPS trust anchor cache, to avoid regenerating it for every TLS connection.
  https_ta_cache = None

  def clear_https_ta_cache(self):
    """
    Clear dynamic TLS trust anchors.
    """

    if self.https_ta_cache is not None:
      rpki.log.debug("Clearing HTTPS trusted cert cache")
      self.https_ta_cache = None

  def build_https_ta_cache(self):
    """
    Build dynamic TLS trust anchors.
    """

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


class ca_obj(rpki.sql.sql_persistent):
  """
  Internal CA object.
  """

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
    """
    Construct the sia_uri value for this CA given configured
    information and the parent's up-down protocol list_response PDU.
    """

    sia_uri = rc.suggested_sia_head and rc.suggested_sia_head.rsync()
    if not sia_uri or not sia_uri.startswith(parent.sia_base):
      sia_uri = parent.sia_base
    if not sia_uri.endswith("/"):
      raise rpki.exceptions.BadURISyntax, "SIA URI must end with a slash: %s" % sia_uri
    return sia_uri + str(self.ca_id) + "/"

  def check_for_updates(self, parent, rc, cb, eb):
    """
    Parent has signaled continued existance of a resource class we
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
        rpki.log.warn("Certificate in database missing from list_response, class %r, SKI %s, maybe parent certificate went away?"
                      % (rc.class_name, ca_detail.latest_ca_cert.gSKI()))
        ca_detail.delete(self, parent.repository(), iterator, eb, allow_failure = True)
        return

      def cleanup():
        del cert_map[ski]
        iterator()

      if ca_detail.state in ("pending", "active"):
        current_resources = ca_detail.latest_ca_cert.get_3779resources()
        if (sia_uri_changed or
            ca_detail.latest_ca_cert != cert_map[ski].cert or
            current_resources.undersized(rc_resources) or
            current_resources.oversized(rc_resources)):
          ca_detail.update(
            parent           = parent,
            ca               = self,
            rc               = rc,
            sia_uri_changed  = sia_uri_changed,
            old_resources    = current_resources,
            callback         = cleanup,
            errback          = eb)
          return

      cleanup()

    def done():
      if cert_map:
        rpki.log.warn("Certificates in list_response missing from our database, class %r, SKIs %s"
                      % (rc.class_name, ", ".join(c.cert.gSKI() for c in cert_map.values())))
      cb()

    ca_details = ca_detail_obj.sql_fetch_where(self.gctx, "ca_id = %s AND latest_ca_cert IS NOT NULL AND state != 'revoked'", (self.ca_id,))

    if True:
      for x in cert_map.itervalues():
        rpki.log.debug("Parent thinks I have %r %s" % (x, x.cert.gSKI()))
      for x in ca_details:
        rpki.log.debug("I think I have %r %s" % (x, x.latest_ca_cert.gSKI()))

    if ca_details:
      rpki.async.iterator(ca_details, loop, done)
    else:
      rpki.log.warn("Existing certificate class %r with no certificates, rekeying" % rc.class_name)
      self.rekey(cb, eb)

  @classmethod
  def create(cls, parent, rc, cb, eb):
    """
    Parent has signaled existance of a new resource class, so we need
    to create and set up a corresponding CA object.
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
        callback = cb,
        errback  = eb)

    rpki.up_down.issue_pdu.query(parent, self, ca_detail, done, eb)

  def delete(self, parent, callback):
    """
    The list of current resource classes received from parent does not
    include the class corresponding to this CA, so we need to delete
    it (and its little dog too...).

    All certs published by this CA are now invalid, so need to
    withdraw them, the CRL, and the manifest from the repository,
    delete all child_cert and ca_detail records associated with this
    CA, then finally delete this CA itself.
    """

    def fail(e):
      rpki.log.traceback()
      rpki.log.warn("Could not delete CA %r, skipping: %s" % (self, e))
      callback()

    def done():
      self.sql_delete()      
      callback()

    repository = parent.repository()

    def loop(iterator, ca_detail):
      ca_detail.delete(self, repository, iterator, fail)

    rpki.async.iterator(self.ca_details(), loop, done)

  def next_serial_number(self):
    """
    Allocate a certificate serial number.
    """
    self.last_issued_sn += 1
    self.sql_mark_dirty()
    return self.last_issued_sn

  def next_manifest_number(self):
    """
    Allocate a manifest serial number.
    """
    self.last_manifest_sn += 1
    self.sql_mark_dirty()
    return self.last_manifest_sn

  def next_crl_number(self):
    """
    Allocate a CRL serial number.
    """
    self.last_crl_sn += 1
    self.sql_mark_dirty()
    return self.last_crl_sn

  def rekey(self, cb, eb):
    """
    Initiate a rekey operation for this ca.  Generate a new keypair.
    Request cert from parent using new keypair.  Mark result as our
    active ca_detail.  Reissue all child certs issued by this ca using
    the new ca_detail.
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
        callback    = cb,
        errback     = eb)

    rpki.up_down.issue_pdu.query(parent, self, new_detail, done, eb)

  def revoke(self, cb, eb):
    """
    Revoke deprecated ca_detail objects associated with this ca.
    """

    rpki.log.trace()

    def loop(iterator, ca_detail):
      ca_detail.revoke(iterator, eb)

    rpki.async.iterator(self.fetch_deprecated(), loop, cb)

class ca_detail_obj(rpki.sql.sql_persistent):
  """
  Internal CA detail object.
  """

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
    """
    Extra assertions for SQL decode of a ca_detail_obj.
    """
    rpki.sql.sql_persistent.sql_decode(self, vals)
    assert self.public_key is None or self.private_key_id is None or self.public_key.get_DER() == self.private_key_id.get_public_DER()
    assert self.manifest_public_key is None or self.manifest_private_key_id is None or self.manifest_public_key.get_DER() == self.manifest_private_key_id.get_public_DER()

  def ca(self):
    """Fetch CA object to which this ca_detail links."""
    return ca_obj.sql_fetch(self.gctx, self.ca_id)

  def child_certs(self, child = None, ski = None, unique = False):
    """Fetch all child_cert objects that link to this ca_detail."""
    return rpki.rpki_engine.child_cert_obj.fetch(self.gctx, child, self, ski, unique)

  def revoked_certs(self):
    """Fetch all revoked_cert objects that link to this ca_detail."""
    return revoked_cert_obj.sql_fetch_where(self.gctx, "ca_detail_id = %s", (self.ca_detail_id,))

  def roas(self):
    """Fetch all ROA objects that link to this ca_detail."""
    return rpki.rpki_engine.roa_obj.sql_fetch_where(self.gctx, "ca_detail_id = %s", (self.ca_detail_id,))

  def crl_uri(self, ca):
    """Return publication URI for this ca_detail's CRL."""
    return ca.sia_uri + self.crl_uri_tail()

  def crl_uri_tail(self):
    """Return tail (filename portion) of publication URI for this ca_detail's CRL."""
    return self.public_key.gSKI() + ".crl"

  def manifest_uri(self, ca):
    """Return publication URI for this ca_detail's manifest."""
    return ca.sia_uri + self.public_key.gSKI() + ".mnf"

  def activate(self, ca, cert, uri, callback, errback, predecessor = None):
    """
    Activate this ca_detail.
    """

    self.latest_ca_cert = cert
    self.ca_cert_uri = uri.rsync()
    self.generate_manifest_cert(ca)

    def did_crl():
      self.generate_manifest(callback = did_manifest, errback = errback)

    def did_manifest():
      self.state = "active"
      self.sql_mark_dirty()
      if predecessor is None:
        callback()
      else:
        predecessor.state = "deprecated"
        predecessor.sql_mark_dirty()
        rpki.async.iterator(predecessor.child_certs(), do_one_child_cert, done_child_certs)

    def do_one_child_cert(iterator, child_cert):
      child_cert.reissue(self, iterator.ignore, errback)

    def done_child_certs():
      rpki.async.iterator(predecessor.roas(), do_one_roa, callback)

    def do_one_roa(iterator, roa):
      roa.regenerate(iterator, errback)

    self.generate_crl(callback = did_crl, errback = errback)

  def delete(self, ca, repository, cb, eb, allow_failure = False):
    """
    Delete this ca_detail and all of the certs it issued.

    If allow_failure is true, we clean up as much as we can but don't
    raise an exception.
    """

    def withdraw_one_child(iterator, child_cert):
      repository.withdraw(child_cert.cert, child_cert.uri(ca), iterator, eb, allow_failure)

    def child_certs_done():
      rpki.async.iterator(self.roas(), revoke_one_roa, withdraw_manifest)

    def revoke_one_roa(iterator, roa):
      roa.revoke(iterator, eb, allow_failure = allow_failure)

    def withdraw_manifest():
      repository.withdraw(self.latest_manifest, self.manifest_uri(ca), withdraw_crl, eb, allow_failure)

    def withdraw_crl():
      repository.withdraw(self.latest_crl, self.crl_uri(ca), done, eb, allow_failure)

    def done():
      for cert in self.child_certs() + self.revoked_certs():
        cert.sql_delete()
      self.sql_delete()
      cb()

    rpki.async.iterator(self.child_certs(), withdraw_one_child, child_certs_done)

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
        child_cert.revoke(iterator, eb)

      def final_crl():
        self.nextUpdate += crl_interval
        self.generate_crl(callback = final_manifest, errback = eb, nextUpdate = self.nextUpdate)

      def final_manifest():
        self.generate_manifest(callback = done, errback = eb, nextUpdate = self.nextUpdate)

      def done():
        self.private_key_id = None
        self.manifest_private_key_id = None
        self.manifest_public_key = None
        self.latest_manifest_cert = None
        self.state = "revoked"
        self.sql_mark_dirty()
        cb()

      rpki.async.iterator(self.child_certs(), revoke_one_child, final_crl)

    rpki.up_down.revoke_pdu.query(self, parent_revoked, eb)

  def update(self, parent, ca, rc, sia_uri_changed, old_resources, callback, errback):
    """
    Need to get a new certificate for this ca_detail and perhaps frob
    children of this ca_detail.
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
            callback  = iterator.ignore,
            errback   = errback)
        else:
          iterator()

      if sia_uri_changed or old_resources.oversized(new_resources):
        rpki.async.iterator(self.child_certs(), loop, callback)
      else:
        callback()

    rpki.up_down.issue_pdu.query(parent, ca, self, issued, errback)

  @classmethod
  def create(cls, ca):
    """
    Create a new ca_detail object for a specified CA.
    """
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
    """
    Issue a new EE certificate.
    """

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
    """
    Generate a new manifest certificate for this ca_detail.
    """

    resources = rpki.resource_set.resource_bag(
      asn = rpki.resource_set.resource_set_as("<inherit>"),
      v4 = rpki.resource_set.resource_set_ipv4("<inherit>"),
      v6 = rpki.resource_set.resource_set_ipv6("<inherit>"))

    self.latest_manifest_cert = self.issue_ee(ca, resources, self.manifest_public_key)

  def issue(self, ca, child, subject_key, sia, resources, callback, errback, child_cert = None):
    """
    Issue a new certificate to a child.  Optional child_cert argument
    specifies an existing child_cert object to update in place; if not
    specified, we create a new one.  Returns the child_cert object
    containing the newly issued cert.
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
      rpki.log.debug("Created new child_cert %r" % child_cert)
    else:
      child_cert.cert = cert
      rpki.log.debug("Reusing existing child_cert %r" % child_cert)

    child_cert.ski = cert.get_SKI()

    child_cert.sql_store()

    def published():
      self.generate_manifest(done, errback)

    def done():
      callback(child_cert)
      
    ca.parent().repository().publish(child_cert.cert, child_cert.uri(ca), published, errback)

  def generate_crl(self, callback, errback, nextUpdate = None):
    """
    Generate a new CRL for this ca_detail.  At the moment this is
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

    repository.publish(self.latest_crl, self.crl_uri(ca), callback = callback, errback = errback)

  def generate_manifest(self, callback, errback, nextUpdate = None):
    """
    Generate a new manifest for this ca_detail.
    """

    ca = self.ca()
    parent = ca.parent()
    repository = parent.repository()
    crl_interval = rpki.sundial.timedelta(seconds = parent.self().crl_interval)
    now = rpki.sundial.now()

    if nextUpdate is None:
      nextUpdate = now + crl_interval

    if self.latest_manifest_cert is None or self.latest_manifest_cert.getNotAfter() < nextUpdate:
      self.generate_manifest_cert(ca)

    objs = [(c.uri_tail(), c.cert) for c in self.child_certs()] + \
           [(r.uri_tail(), r.roa) for r in self.roas() if r.roa is not None] + \
           [(self.crl_uri_tail(), self.latest_crl)]

    self.latest_manifest = rpki.x509.SignedManifest.build(
      serial         = ca.next_manifest_number(),
      thisUpdate     = now,
      nextUpdate     = nextUpdate,
      names_and_objs = objs,
      keypair        = self.manifest_private_key_id,
      certs          = self.latest_manifest_cert)

    repository.publish(self.latest_manifest, self.manifest_uri(ca), callback = callback, errback = errback)

class child_cert_obj(rpki.sql.sql_persistent):
  """
  Certificate that has been issued to a child.
  """

  sql_template = rpki.sql.template(
    "child_cert",
    "child_cert_id",
    ("cert", rpki.x509.X509),
    "child_id",
    "ca_detail_id",
    "ski")

  def __init__(self, gctx = None, child_id = None, ca_detail_id = None, cert = None):
    """
    Initialize a child_cert_obj.
    """
    rpki.sql.sql_persistent.__init__(self)
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

  def revoke(self, callback, errback, withdraw = True):
    """
    Revoke a child cert.
    """

    rpki.log.debug("Revoking %r" % self)
    ca_detail = self.ca_detail()
    ca = ca_detail.ca()
    revoked_cert_obj.revoke(cert = self.cert, ca_detail = ca_detail)

    def done():
      self.gctx.sql.sweep()
      self.sql_delete()
      callback()

    if withdraw:
      ca.parent().repository().withdraw(self.cert, self.uri(ca), done, errback)
    else:
      rpki.log.info("Suppressing withdrawal of %r" % self.cert)
      done()

  def reissue(self, ca_detail, callback, errback, resources = None, sia = None):
    """
    Reissue an existing cert, reusing the public key.  If the cert we
    would generate is identical to the one we already have, we just
    return the one we already have.  If we have to revoke the old
    certificate when generating the new one, we have to generate a new
    child_cert_obj, so calling code that needs the updated
    child_cert_obj must use the return value from this method.
    """

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

    rpki.log.debug("Reissuing %r, must_revoke %s, new_issuer %s" % (self, must_revoke, new_issuer))

    if resources.valid_until != old_resources.valid_until:
      rpki.log.debug("Validity changed: %s %s" % ( old_resources.valid_until, resources.valid_until))

    def revoke(child_cert):

      uri = child_cert.uri(ca)
      rpki.log.debug("New child_cert %r uri %s" % (child_cert, uri))

      def loop(iterator, x):
        rpki.log.debug("Revoking child_cert %r" % x)
        x.revoke(iterator, errback, withdraw = x.uri(ca) != uri)

      def manifest():
        ca_detail.generate_manifest(done, errback)

      def done():
        callback(child_cert)        

      certs_to_revoke = [x for x in child.child_certs(ca_detail = ca_detail, ski = self.ski) if x is not child_cert]

      if certs_to_revoke:
        rpki.async.iterator(certs_to_revoke, loop, manifest)
      else:
        done()

    ca_detail.issue(
      ca          = ca,
      child       = child,
      subject_key = self.cert.getPublicKey(),
      sia         = sia,
      resources   = resources,
      child_cert  = None if must_revoke or new_issuer else self,
      callback    = revoke if must_revoke else callback,
      errback     = errback)

  @classmethod
  def fetch(cls, gctx = None, child = None, ca_detail = None, ski = None, unique = False):
    """
    Fetch all child_cert objects matching a particular set of
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

class revoked_cert_obj(rpki.sql.sql_persistent):
  """
  Tombstone for a revoked certificate.
  """

  sql_template = rpki.sql.template(
    "revoked_cert",
    "revoked_cert_id",
    "serial",
    "ca_detail_id",
    ("revoked", rpki.sundial.datetime),
    ("expires", rpki.sundial.datetime))

  def __init__(self, gctx = None, serial = None, revoked = None, expires = None, ca_detail_id = None):
    """Initialize a revoked_cert_obj."""
    rpki.sql.sql_persistent.__init__(self)
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
    """
    Revoke a certificate.
    """
    return cls(
      serial       = cert.getSerial(),
      expires      = cert.getNotAfter(),
      revoked      = rpki.sundial.now(),
      gctx         = ca_detail.gctx,
      ca_detail_id = ca_detail.ca_detail_id)

class roa_obj(rpki.sql.sql_persistent):
  """
  Route Origin Authorization.
  """

  sql_template = rpki.sql.template(
    "roa",
    "roa_id",
    "ca_detail_id",
    "self_id",
    "asn",
    ("roa", rpki.x509.ROA),
    ("cert", rpki.x509.X509))

  ca_detail_id = None
  cert = None
  roa = None

  def self(self):
    """
    Fetch self object to which this roa_obj links.
    """
    return rpki.left_right.self_elt.sql_fetch(self.gctx, self.self_id)

  def ca_detail(self):
    """
    Fetch ca_detail object to which this roa_obj links.
    """
    return rpki.rpki_engine.ca_detail_obj.sql_fetch(self.gctx, self.ca_detail_id)

  def sql_fetch_hook(self):
    """
    Extra SQL fetch actions for roa_obj -- handle prefix lists.
    """
    for version, datatype, attribute in ((4, rpki.resource_set.roa_prefix_set_ipv4, "ipv4"),
                                         (6, rpki.resource_set.roa_prefix_set_ipv6, "ipv6")):
      setattr(self, attribute, datatype.from_sql(
        self.gctx.sql,
        """
            SELECT prefix, prefixlen, max_prefixlen FROM roa_prefix
            WHERE roa_id = %s AND version = %s
        """,
        (self.roa_id, version)))

  def sql_insert_hook(self):
    """
    Extra SQL insert actions for roa_obj -- handle prefix lists.
    """
    for version, prefix_set in ((4, self.ipv4), (6, self.ipv6)):
      if prefix_set:
        self.gctx.sql.executemany(
          """
            INSERT roa_prefix (roa_id, prefix, prefixlen, max_prefixlen, version)
            VALUES (%s, %s, %s, %s, %s)
          """,
          ((self.roa_id, x.prefix, x.prefixlen, x.max_prefixlen, version)
           for x in prefix_set))

  def sql_delete_hook(self):
    """
    Extra SQL delete actions for roa_obj -- handle prefix lists.
    """
    self.gctx.sql.execute("DELETE FROM roa_prefix WHERE roa_id = %s", (self.roa_id,))

  def __init__(self, gctx = None, self_id = None, asn = None, ipv4 = None, ipv6 = None):
    rpki.sql.sql_persistent.__init__(self)
    self.gctx = gctx
    self.self_id = self_id
    self.asn = asn
    self.ipv4 = ipv4
    self.ipv6 = ipv6
    if self_id or asn or ipv4 or ipv6:
      self.sql_mark_dirty()

  def update(self, callback, errback):
    """
    Bring this roa_obj's ROA up to date if necesssary.
    """

    if self.roa is None:
      return self.generate(callback, errback)

    ca_detail = self.ca_detail()

    if ca_detail is None or ca_detail.state != "active":
      return self.regenerate(callback, errback)

    regen_margin = rpki.sundial.timedelta(seconds = self.self().regen_margin)

    if rpki.sundial.now() + regen_margin > self.cert.getNotAfter():
      return self.regenerate(callback, errback)

    ca_resources = ca_detail.latest_ca_cert.get_3779resources()
    ee_resources = self.cert.get_3779resources()

    if ee_resources.oversized(ca_resources):
      return self.regenerate(callback, errback)

    v4 = self.ipv4.to_resource_set() if self.ipv4 is not None else rpki.resource_set.resource_set_ipv4()
    v6 = self.ipv6.to_resource_set() if self.ipv6 is not None else rpki.resource_set.resource_set_ipv6()

    if ee_resources.v4 != v4 or ee_resources.v6 != v6:
      return self.regenerate(callback, errback)

    callback()

  def generate(self, callback, errback):
    """
    Generate a ROA.

    At present this does not support ROAs with multiple signatures
    (neither does the current CMS code).

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
    """

    if self.ipv4 is None and self.ipv6 is None:
      raise rpki.exceptions.EmptyROAPrefixList

    # Ugly and expensive search for covering ca_detail, there has to
    # be a better way, but it would require the ability to test for
    # resource subsets in SQL.

    v4 = self.ipv4.to_resource_set() if self.ipv4 is not None else rpki.resource_set.resource_set_ipv4()
    v6 = self.ipv6.to_resource_set() if self.ipv6 is not None else rpki.resource_set.resource_set_ipv6()

    ca_detail = self.ca_detail()
    if ca_detail is None or ca_detail.state != "active":
      ca_detail = None
      for parent in self.self().parents():
        for ca in parent.cas():
          ca_detail = ca.fetch_active()
          if ca_detail is not None:
            resources = ca_detail.latest_ca_cert.get_3779resources()
            if v4.issubset(resources.v4) and v6.issubset(resources.v6):
              break
            ca_detail = None
        if ca_detail is not None:
          break

    if ca_detail is None:
      raise rpki.exceptions.NoCoveringCertForROA, "generate() could not find a certificate covering %s %s" % (v4, v6)

    ca = ca_detail.ca()

    resources = rpki.resource_set.resource_bag(v4 = v4, v6 = v6)

    keypair = rpki.x509.RSA.generate()

    self.ca_detail_id = ca_detail.ca_detail_id

    self.cert = ca_detail.issue_ee(ca, resources, keypair.get_RSApublic(),
                                   sia = ((rpki.oids.name2oid["id-ad-signedObject"],
                                           ("uri", self.uri(keypair))),))

    self.roa = rpki.x509.ROA.build(self.asn, self.ipv4, self.ipv6, keypair, (self.cert,))

    self.sql_store()

    def done():
      ca_detail.generate_manifest(callback, errback)

    ca.parent().repository().publish(self.roa, self.uri(), done, errback)

  def revoke(self, callback, errback, regenerate = False, allow_failure = False):
    """
    Withdraw ROA associated with this roa_obj.

    In order to preserve make-before-break properties without
    duplicating code, this method also handles generating a
    replacement ROA when requested.
    """

    ca_detail = self.ca_detail()
    cert = self.cert
    roa = self.roa
    uri = self.uri()

    if ca_detail.state != 'active':
      self.ca_detail_id = None

    def one():
      rpki.log.debug("Withdrawing ROA and revoking its EE cert")
      rpki.rpki_engine.revoked_cert_obj.revoke(cert = cert, ca_detail = ca_detail)
      ca_detail.ca().parent().repository().withdraw(roa, uri, two, errback, allow_failure)

    def two():
      self.gctx.sql.sweep()
      ca_detail.generate_crl(three, errback)

    def three():
      ca_detail.generate_manifest(four, errback)

    def four():
      self.sql_delete()
      callback()

    if regenerate:
      self.generate(one, errback)
    else:
      one()

  def regenerate(self, callback, errback):
    """
    Reissue ROA associated with this roa_obj.
    """
    if self.ca_detail() is None:
      self.generate(callback, errback)
    else:
      self.revoke(callback, errback, regenerate = True)

  def uri(self, key = None):
    """
    Return the publication URI for this roa_obj's ROA.
    """
    return self.ca_detail().ca().sia_uri + self.uri_tail(key)

  def uri_tail(self, key = None):
    """
    Return the tail (filename portion) of the publication URI for this
    roa_obj's ROA.
    """
    return (key or self.cert).gSKI() + ".roa"
