# $Id$

# Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""RPKI "left-right" protocol."""

import base64, lxml.etree, time, traceback, os
import rpki.resource_set, rpki.x509, rpki.sql, rpki.exceptions, rpki.xml_utils
import rpki.https, rpki.up_down, rpki.relaxng, rpki.sundial, rpki.log, rpki.roa
import rpki.publication

# Enforce strict checking of XML "sender" field in up-down protocol
enforce_strict_up_down_xml_sender = False

class left_right_namespace(object):
  """XML namespace parameters for left-right protocol."""

  xmlns = "http://www.hactrn.net/uris/rpki/left-right-spec/"
  nsmap = { None : xmlns }

class data_elt(rpki.xml_utils.data_elt, rpki.sql.sql_persistant, left_right_namespace):
  """Virtual class for top-level left-right protocol data elements."""

  def self(this):
    """Fetch self object to which this object links."""
    return self_elt.sql_fetch(this.gctx, this.self_id)

  def bsc(self):
    """Return BSC object to which this object links."""
    return bsc_elt.sql_fetch(self.gctx, self.bsc_id)

  def make_reply_clone_hook(self, r_pdu):
    """Set self_id when cloning."""
    r_pdu.self_id = self.self_id

  def serve_fetch_one(self):
    """Find the object on which a get, set, or destroy method should
    operate.
    """
    where = self.sql_template.index + " = %s AND self_id = %s"
    args = (getattr(self, self.sql_template.index), self.self_id)
    r = self.sql_fetch_where1(self.gctx, where, args)
    if r is None:
      raise rpki.exceptions.NotFound, "Lookup failed where %s" + (where % args)
    return r

  def serve_fetch_all(self):
    """Find the objects on which a list method should operate."""
    return self.sql_fetch_where(self.gctx, "self_id = %s", (self.self_id,))
  
  def unimplemented_control(self, *controls):
    """Uniform handling for unimplemented control operations."""
    unimplemented = [x for x in controls if getattr(self, x, False)]
    if unimplemented:
      raise rpki.exceptions.NotImplementedYet, "Unimplemented control %s" % ", ".join(unimplemented)

class self_elt(data_elt):
  """<self/> element."""

  element_name = "self"
  attributes = ("action", "tag", "self_id", "crl_interval", "regen_margin")
  elements = ("bpki_cert", "bpki_glue")
  booleans = ("rekey", "reissue", "revoke", "run_now", "publish_world_now")

  sql_template = rpki.sql.template("self", "self_id", "use_hsm", "crl_interval", "regen_margin",
                                   ("bpki_cert", rpki.x509.X509), ("bpki_glue", rpki.x509.X509))

  self_id = None
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

  def route_origins(self):
    """Fetch all route_origin objects that link to this self object."""
    return route_origin_elt.sql_fetch_where(self.gctx, "self_id = %s", (self.self_id,))

  def serve_post_save_hook(self, q_pdu, r_pdu):
    """Extra server actions for self_elt."""
    rpki.log.trace()
    if q_pdu.rekey:
      self.serve_rekey()
    if q_pdu.revoke:
      self.serve_revoke()
    self.unimplemented_control("reissue", "run_now", "publish_world_now")

  def serve_rekey(self):
    """Handle a left-right rekey action for this self."""
    rpki.log.trace()
    for parent in self.parents():
      parent.serve_rekey()

  def serve_revoke(self):
    """Handle a left-right revoke action for this self."""
    rpki.log.trace()
    for parent in self.parents():
      parent.serve_revoke()

  def serve_fetch_one(self):
    """Find the self object upon which a get, set, or destroy action
    should operate.
    """
    r = self.sql_fetch(self.gctx, self.self_id)
    if r is None:
      raise rpki.exceptions.NotFound
    return r

  def serve_fetch_all(self):
    """Find the self objects upon which a list action should operate.
    This is different from the list action for all other objects,
    where list only works within a given self_id context.
    """
    return self.sql_fetch_all(self.gctx)

  def client_poll(self):
    """Run the regular client poll cycle with each of this self's parents in turn."""

    rpki.log.trace()

    for parent in self.parents():

      # This will need a callback when we go event-driven
      r_msg = rpki.up_down.list_pdu.query(parent)

      ca_map = dict((ca.parent_resource_class, ca) for ca in parent.cas())
      for rc in r_msg.payload.classes:
        if rc.class_name in ca_map:
          ca = ca_map[rc.class_name]
          del  ca_map[rc.class_name]
          ca.check_for_updates(parent, rc)
        else:
          rpki.rpki_engine.ca_obj.create(parent, rc)
      for ca in ca_map.values():
        ca.delete(parent)               # CA not listed by parent
      self.gctx.sql_sweep()

  def update_children(self):
    """Check for updated IRDB data for all of this self's children and
    issue new certs as necessary.  Must handle changes both in
    resources and in expiration date.
    """

    rpki.log.trace()

    now = rpki.sundial.now()

    for child in self.children():
      child_certs = child.child_certs()
      if not child_certs:
        continue

      # This will require a callback when we go event-driven
      irdb_resources = self.gctx.irdb_query(child.self_id, child.child_id)

      for child_cert in child_certs:
        ca_detail = child_cert.ca_detail()
        if ca_detail.state != "active":
          continue
        old_resources = child_cert.cert.get_3779resources()
        new_resources = irdb_resources.intersection(old_resources)
        if old_resources != new_resources:
          rpki.log.debug("Need to reissue %s" % repr(child_cert))
          child_cert.reissue(
            ca_detail = ca_detail,
            resources = new_resources)
        elif old_resources.valid_until < now:
          ca = ca_detail.ca()
          parent = ca.parent()
          repository = parent.repository()
          child_cert.sql_delete()
          ca_detail.generate_manifest()
          repository.withdraw(child_cert.cert, child_cert.uri(ca))

  def regenerate_crls_and_manifests(self):
    """Generate new CRLs and manifests as necessary for all of this
    self's CAs.  Extracting nextUpdate from a manifest is hard at the
    moment due to implementation silliness, so for now we generate a
    new manifest whenever we generate a new CRL

    This method also cleans up tombstones left behind by revoked
    ca_detail objects, since we're walking through the relevant
    portions of the database anyway.
    """

    rpki.log.trace()

    now = rpki.sundial.now()
    for parent in self.parents():
      repository = parent.repository()
      for ca in parent.cas():
        for ca_detail in ca.fetch_revoked():
          if now > ca_detail.latest_crl.getNextUpdate():
            ca_detail.delete(ca, repository)
        ca_detail = ca.fetch_active()
        if now > ca_detail.latest_crl.getNextUpdate():
          ca_detail.generate_crl()
          ca_detail.generate_manifest()

  def update_roas(self):
    """Generate or update ROAs for this self's route_origin objects."""

    for route_origin in self.route_origins():
      route_origin.update_roa()

class bsc_elt(data_elt):
  """<bsc/> (Business Signing Context) element."""
  
  element_name = "bsc"
  attributes = ("action", "tag", "self_id", "bsc_id", "key_type", "hash_alg", "key_length")
  elements = ("signing_cert", "signing_cert_crl", "pkcs10_request")
  booleans = ("generate_keypair",)

  sql_template = rpki.sql.template("bsc", "bsc_id", "self_id", "hash_alg",
                                   ("private_key_id", rpki.x509.RSA),
                                   ("pkcs10_request", rpki.x509.PKCS10),
                                   ("signing_cert", rpki.x509.X509),
                                   ("signing_cert_crl", rpki.x509.CRL))

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

  def serve_pre_save_hook(self, q_pdu, r_pdu):
    """Extra server actions for bsc_elt -- handle key generation.
    For now this only allows RSA with SHA-256.
    """
    if q_pdu.generate_keypair:
      assert q_pdu.key_type in (None, "rsa") and q_pdu.hash_alg in (None, "sha256")
      keypair = rpki.x509.RSA()
      keypair.generate(keylength = q_pdu.key_length or 2048)
      self.private_key_id = keypair
      self.pkcs10_request = rpki.x509.PKCS10.create(keypair)
      r_pdu.pkcs10_request = self.pkcs10_request

class parent_elt(data_elt):
  """<parent/> element."""

  element_name = "parent"
  attributes = ("action", "tag", "self_id", "parent_id", "bsc_id", "repository_id",
                "peer_contact_uri", "sia_base", "sender_name", "recipient_name")
  elements = ("bpki_cms_cert", "bpki_cms_glue", "bpki_https_cert", "bpki_https_glue")
  booleans = ("rekey", "reissue", "revoke")

  sql_template = rpki.sql.template("parent", "parent_id", "self_id", "bsc_id", "repository_id",
                                   ("bpki_cms_cert", rpki.x509.X509), ("bpki_cms_glue", rpki.x509.X509),
                                   ("bpki_https_cert", rpki.x509.X509), ("bpki_https_glue", rpki.x509.X509),
                                   "peer_contact_uri", "sia_base", "sender_name", "recipient_name")

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

  def serve_post_save_hook(self, q_pdu, r_pdu):
    """Extra server actions for parent_elt."""
    if q_pdu.rekey:
      self.serve_rekey()
    if q_pdu.revoke:
      self.serve_revoke()
    self.unimplemented_control("reissue")

  def serve_rekey(self):
    """Handle a left-right rekey action for this parent."""
    for ca in self.cas():
      ca.rekey()

  def serve_revoke(self):
    """Handle a left-right revoke action for this parent."""
    for ca in self.cas():
      ca.revoke()

  def query_up_down(self, q_pdu):
    """Client code for sending one up-down query PDU to this parent.

    I haven't figured out yet whether this method should do something
    clever like dispatching via a method in the response PDU payload,
    or just hand back the whole response to the caller.  In the long
    run this will have to become event driven with a context object
    that has methods of its own, but as this method is common code for
    several different queries and I don't yet know what the response
    processing looks like, it's too soon to tell what will make sense.

    For now, keep this dead simple lock step, rewrite it later.
    """

    rpki.log.trace()

    bsc = self.bsc()
    if bsc is None:
      raise rpki.exceptions.BSCNotFound, "Could not find BSC %s" % self.bsc_id

    q_msg = rpki.up_down.message_pdu.make_query(
      payload = q_pdu,
      sender = self.sender_name,
      recipient = self.recipient_name)

    q_cms = rpki.up_down.cms_msg.wrap(q_msg, bsc.private_key_id,
                                      bsc.signing_cert,
                                      bsc.signing_cert_crl)

    der = rpki.https.client(server_ta    = (self.gctx.bpki_ta,
                                            self.self().bpki_cert, self.self().bpki_glue,
                                            self.bpki_https_cert, self.bpki_https_glue),
                            client_key   = bsc.private_key_id,
                            client_cert  = bsc.signing_cert,
                            msg          = q_cms,
                            url          = self.peer_contact_uri)

    r_msg = rpki.up_down.cms_msg.unwrap(der, (self.gctx.bpki_ta,
                                              self.self().bpki_cert, self.self().bpki_glue,
                                              self.bpki_cms_cert, self.bpki_cms_glue))

    r_msg.payload.check_response()
    return r_msg


class child_elt(data_elt):
  """<child/> element."""

  element_name = "child"
  attributes = ("action", "tag", "self_id", "child_id", "bsc_id")
  elements = ("bpki_cert", "bpki_glue")
  booleans = ("reissue", )

  sql_template = rpki.sql.template("child", "child_id", "self_id", "bsc_id",
                                   ("bpki_cert", rpki.x509.X509),
                                   ("bpki_glue", rpki.x509.X509))

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
    """Fetch the CA corresponding to an up-down class_name."""
    if not class_name.isdigit():
      raise rpki.exceptions.BadClassNameSyntax, "Bad class name %s" % class_name
    ca = rpki.rpki_engine.ca_obj.sql_fetch(self.gctx, long(class_name))
    parent = ca.parent()
    if self.self_id != parent.self_id:
      raise rpki.exceptions.ClassNameMismatch, "child.self_id = %d, parent.self_id = %d" % (self.self_id, parent.self_id)
    return ca

  def serve_post_save_hook(self, q_pdu, r_pdu):
    """Extra server actions for child_elt."""
    self.unimplemented_control("reissue")
    if self.clear_https_ta_cache:
      self.gctx.clear_https_ta_cache()
      self.clear_https_ta_cache = False

  def endElement(self, stack, name, text):
    """Handle subelements of <child/> element.  These require special
    handling because modifying them invalidates the HTTPS trust anchor
    cache.
    """
    rpki.xml_utils.data_elt.endElement(self, stack, name, text)
    if name in self.elements:
      self.clear_https_ta_cache = True

  def serve_up_down(self, query):
    """Outer layer of server handling for one up-down PDU from this child."""

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
    try:
      r_msg = q_msg.serve_top_level(self)
    except Exception, data:
      rpki.log.error(traceback.format_exc())
      r_msg = q_msg.serve_error(data)
    #
    # Exceptions from this point on are problematic, as we have no
    # sane way of reporting errors in the error reporting mechanism.
    # May require refactoring, ignore the issue for now.
    #
    r_cms = rpki.up_down.cms_msg.wrap(r_msg, bsc.private_key_id,
                                      bsc.signing_cert, bsc.signing_cert_crl)
    return r_cms

class repository_elt(data_elt):
  """<repository/> element."""

  element_name = "repository"
  attributes = ("action", "tag", "self_id", "repository_id", "bsc_id", "peer_contact_uri")
  elements = ("bpki_cms_cert", "bpki_cms_glue", "bpki_https_cert", "bpki_https_glue")

  sql_template = rpki.sql.template("repository", "repository_id", "self_id", "bsc_id", "peer_contact_uri",
                                   ("bpki_cms_cert", rpki.x509.X509), ("bpki_cms_glue", rpki.x509.X509),
                                   ("bpki_https_cert", rpki.x509.X509), ("bpki_https_glue", rpki.x509.X509))

  bpki_cms_cert = None
  bpki_cms_glue = None
  bpki_https_cert = None
  bpki_https_glue = None

  use_pubd = True

  def parents(self):
    """Fetch all parent objects that link to this repository object."""
    return parent_elt.sql_fetch_where(self.gctx, "repository_id = %s", (self.repository_id,))

  @staticmethod
  def uri_to_filename(base, uri):
    """Convert a URI to a filename. [TEMPORARY]"""
    if not uri.startswith("rsync://"):
      raise rpki.exceptions.BadURISyntax
    filename = base + uri[len("rsync://"):]
    if filename.find("//") >= 0 or filename.find("/../") >= 0 or filename.endswith("/.."):
      raise rpki.exceptions.BadURISyntax
    return filename

  @classmethod
  def object_write(cls, base, uri, obj):
    """Write an object to disk. [TEMPORARY]"""
    rpki.log.trace()
    filename = cls.uri_to_filename(base, uri)
    dirname = os.path.dirname(filename)
    if not os.path.isdir(dirname):
      os.makedirs(dirname)
    f = open(filename, "wb")
    f.write(obj.get_DER())
    f.close()

  @classmethod
  def object_delete(cls, base, uri):
    """Delete an object from disk. [TEMPORARY]"""
    rpki.log.trace()
    os.remove(cls.uri_to_filename(base, uri))

  def call_pubd(self, *pdus):
    """Send a message to publication daemon and return the response."""
    rpki.log.trace()
    bsc = self.bsc()
    q_msg = rpki.publication.msg(pdus)
    q_msg.type = "query"
    q_cms = rpki.publication.cms_msg.wrap(q_msg, bsc.private_key_id, bsc.signing_cert, bsc.signing_cert_crl)
    bpki_ta_path = (self.gctx.bpki_ta, self.self().bpki_cert, self.self().bpki_glue, self.bpki_https_cert, self.bpki_https_glue)
    r_cms = rpki.https.client(
      client_key   = bsc.private_key_id,
      client_cert  = bsc.signing_cert,
      server_ta    = bpki_ta_path,
      url          = self.peer_contact_uri,
      msg          = q_cms)
    r_msg = rpki.publication.cms_msg.unwrap(r_cms, bpki_ta_path)
    assert len(r_msg) == 1
    return r_msg[0]

  def publish(self, obj, uri):
    """Placeholder for publication operation. [TEMPORARY]"""
    rpki.log.trace()
    rpki.log.info("Publishing %s as %s" % (repr(obj), repr(uri)))
    if self.use_pubd:
      self.call_pubd(rpki.publication.obj2elt[type(obj)].make_pdu(action = "publish", uri = uri, payload = obj))
    else:
      self.object_write(self.gctx.publication_kludge_base, uri, obj)

  def withdraw(self, obj, uri):
    """Placeholder for publication withdrawal operation. [TEMPORARY]"""
    rpki.log.trace()
    rpki.log.info("Withdrawing %s from at %s" % (repr(obj), repr(uri)))
    if self.use_pubd:
      self.call_pubd(rpki.publication.obj2elt[type(obj)].make_pdu(action = "withdraw", uri = uri))
    else:
      self.object_delete(self.gctx.publication_kludge_base, uri)

class route_origin_elt(data_elt):
  """<route_origin/> element."""

  element_name = "route_origin"
  attributes = ("action", "tag", "self_id", "route_origin_id", "as_number", "ipv4", "ipv6")
  booleans = ("suppress_publication",)

  sql_template = rpki.sql.template("route_origin", "route_origin_id", "ca_detail_id",
                                   "self_id", "as_number",
                                   ("roa", rpki.x509.ROA),
                                   ("cert", rpki.x509.X509))

  ca_detail_id = None
  cert = None
  roa = None

  def sql_fetch_hook(self):
    """Extra SQL fetch actions for route_origin_elt -- handle prefix list."""
    self.ipv4 = rpki.resource_set.roa_prefix_set_ipv4.from_sql(self.gctx.cur, """
                SELECT address, prefixlen, max_prefixlen FROM route_origin_prefix
                WHERE route_origin_id = %s AND address NOT LIKE '%:%'
                """, (self.route_origin_id,))
    self.ipv6 = rpki.resource_set.roa_prefix_set_ipv6.from_sql(self.gctx.cur, """
                SELECT address, prefixlen, max_prefixlen FROM route_origin_prefix
                WHERE route_origin_id = %s AND address LIKE '%:%'
                """, (self.route_origin_id,))

  def sql_insert_hook(self):
    """Extra SQL insert actions for route_origin_elt -- handle address ranges."""
    if self.ipv4 or self.ipv6:
      self.gctx.cur.executemany("""
                INSERT route_origin_prefix (route_origin_id, address, prefixlen, max_prefixlen)
                VALUES (%s, %s, %s, %s)""",
                           ((self.route_origin_id, x.address, x.prefixlen, x.max_prefixlen)
                            for x in (self.ipv4 or []) + (self.ipv6 or [])))
  
  def sql_delete_hook(self):
    """Extra SQL delete actions for route_origin_elt -- handle address ranges."""
    self.gctx.cur.execute("DELETE FROM route_origin_prefix WHERE route_origin_id = %s", (self.route_origin_id,))

  def ca_detail(self):
    """Fetch all ca_detail objects that link to this route_origin object."""
    return rpki.rpki_engine.ca_detail_obj.sql_fetch(self.gctx, self.ca_detail_id)

  def serve_post_save_hook(self, q_pdu, r_pdu):
    """Extra server actions for route_origin_elt."""
    self.unimplemented_control("suppress_publication")

  def startElement(self, stack, name, attrs):
    """Handle <route_origin/> element.  This requires special
    processing due to the data types of some of the attributes.
    """
    assert name == "route_origin", "Unexpected name %s, stack %s" % (name, stack)
    self.read_attrs(attrs)
    if self.as_number is not None:
      self.as_number = long(self.as_number)
    if self.ipv4 is not None:
      self.ipv4 = rpki.resource_set.roa_prefix_set_ipv4(self.ipv4)
    if self.ipv6 is not None:
      self.ipv6 = rpki.resource_set.roa_prefix_set_ipv6(self.ipv6)

  def update_roa(self):
    """Bring this route_origin's ROA up to date if necesssary."""

    if self.roa is None:
      return self.generate_roa()

    ca_detail = self.ca_detail()

    if ca_detail.state != "active":
      return self.regenerate_roa()

    regen_margin = rpki.sundial.timedelta(seconds = self.self().regen_margin)

    if rpki.sundial.now() + regen_margin > self.cert.getNotAfter():
      return self.regenerate_roa()

    ca_resources = ca_detail.latest_ca_cert.get_3779resources()
    ee_resources = self.cert.get_3779resources()

    if ee_resources.oversized(ca_resources):
      return self.regenerate_roa()

    v4 = self.ipv4.to_resource_set() if self.ipv4 is not None else rpki.resource_set.resource_set_ipv4()
    v6 = self.ipv6.to_resource_set() if self.ipv6 is not None else rpki.resource_set.resource_set_ipv6()

    if ee_resources.v4 != v4 or ee_resources.v6 != v6:
      return self.regenerate_roa()

  def generate_roa(self):
    """Generate a ROA based on this <route_origin/> object.

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
      rpki.log.warn("Can't generate ROA for empty prefix list")
      return

    # Ugly and expensive search for covering ca_detail, there has to
    # be a better way.
    #
    # If we're reissuing (not handled yet) we can optimize this by 
    # first checking the ca_detail we used last time, but it may not
    # be active, in which we have to check the ca_detail that replaced it.

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
      rpki.log.warn("generate_roa() could not find a covering certificate")
      return

    resources = rpki.resource_set.resource_bag(v4 = v4, v6 = v6)

    keypair = rpki.x509.RSA()
    keypair.generate()

    sia = ((rpki.oids.name2oid["id-ad-signedObject"], ("uri", self.roa_uri(ca, keypair))),)

    self.cert = ca_detail.issue_ee(ca, resources, keypair.get_RSApublic(), sia = sia)
    self.roa = rpki.x509.ROA.build(self.as_number, self.ipv4, self.ipv6, keypair, (self.cert,))
    self.ca_detail_id = ca_detail.ca_detail_id
    self.sql_store()

    repository = parent.repository()
    repository.publish(self.roa, self.roa_uri(ca))
    repository.publish(self.cert, self.ee_uri(ca))
    ca_detail.generate_manifest()

  def withdraw_roa(self, regenerate = False):
    """Withdraw ROA associated with this route_origin.

    In order to preserve make-before-break properties without
    duplicating code, this method also handles generating a
    replacement ROA when requested.
    """

    ca_detail = self.ca_detail()
    ca = ca_detail.ca()
    repository = ca.parent().repository()
    cert = self.cert
    roa = self.roa
    roa_uri = self.roa_uri(ca)
    ee_uri = self.ee_uri(ca)

    if ca_detail.state != 'active':
      self.ca_detail_id = None
    if regenerate:
      self.generate_roa()

    rpki.log.debug("Withdrawing ROA and revoking its EE cert")
    rpki.rpki_engine.revoked_cert_obj.revoke(cert = cert, ca_detail = ca_detail)
    repository.withdraw(roa, roa_uri)
    repository.withdraw(cert, ee_uri)
    self.gctx.sql_sweep()
    ca_detail.generate_crl()
    ca_detail.generate_manifest()

  def regenerate_roa(self):
    """Reissue ROA associated with this route_origin."""
    self.withdraw_roa(regenerate = True)

  def roa_uri(self, ca, key = None):
    """Return the publication URI for this route_origin's ROA."""
    return ca.sia_uri + (key or self.cert).gSKI() + ".roa"

  def ee_uri_tail(self):
    """Return the tail (filename) portion of the URI for this route_origin's ROA's EE certificate."""
    return self.cert.gSKI() + ".cer"

  def ee_uri(self, ca):
    """Return the publication URI for this route_origin's ROA's EE certificate."""
    return ca.sia_uri + self.ee_uri_tail()

class list_resources_elt(rpki.xml_utils.base_elt, left_right_namespace):
  """<list_resources/> element."""

  element_name = "list_resources"
  attributes = ("self_id", "tag", "child_id", "valid_until", "asn", "ipv4", "ipv6", "subject_name")
  valid_until = None

  def startElement(self, stack, name, attrs):
    """Handle <list_resources/> element.  This requires special
    handling due to the data types of some of the attributes.
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
    """Generate <list_resources/> element.  This requires special
    handling due to the data types of some of the attributes.
    """
    elt = self.make_elt()
    if isinstance(self.valid_until, int):
      elt.set("valid_until", self.valid_until.toXMLtime())
    return elt

class report_error_elt(rpki.xml_utils.base_elt, left_right_namespace):
  """<report_error/> element."""

  element_name = "report_error"
  attributes = ("tag", "self_id", "error_code")

  @classmethod
  def from_exception(cls, exc, self_id = None):
    """Generate a <report_error/> element from an exception."""
    self = cls()
    self.self_id = self_id
    self.error_code = exc.__class__.__name__
    return self

class msg(rpki.xml_utils.msg, left_right_namespace):
  """Left-right PDU."""

  ## @var version
  # Protocol version
  version = 1

  ## @var pdus
  # Dispatch table of PDUs for this protocol.
  pdus = dict((x.element_name, x)
              for x in (self_elt, child_elt, parent_elt, bsc_elt, repository_elt,
                        route_origin_elt, list_resources_elt, report_error_elt))

  def serve_top_level(self, gctx):
    """Serve one msg PDU."""
    r_msg = self.__class__()
    r_msg.type = "reply"
    for q_pdu in self:
      q_pdu.gctx = gctx
      q_pdu.serve_dispatch(r_msg)
    return r_msg

class sax_handler(rpki.xml_utils.sax_handler):
  """SAX handler for Left-Right protocol."""

  pdu = msg
  name = "msg"
  version = "1"

class cms_msg(rpki.x509.XML_CMS_object):
  """Class to hold a CMS-signed left-right PDU."""

  encoding = "us-ascii"
  schema = rpki.relaxng.left_right
  saxify = sax_handler.saxify
