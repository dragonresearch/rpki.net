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
import rpki.resource_set, rpki.x509, rpki.sql, rpki.exceptions, rpki.sax_utils
import rpki.https, rpki.up_down, rpki.relaxng, rpki.sundial, rpki.log, rpki.roa

xmlns = "http://www.hactrn.net/uris/rpki/left-right-spec/"

nsmap = { None : xmlns }

# Enforce strict checking of XML "sender" field in up-down protocol
enforce_strict_up_down_xml_sender = False

class base_elt(object):
  """Virtual base type for left-right message elements."""

  attributes = ()
  elements = ()
  booleans = ()

  def startElement(self, stack, name, attrs):
    """Default startElement() handler: just process attributes."""
    self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    """Default endElement() handler: just pop the stack."""
    stack.pop()

  def read_attrs(self, attrs):
    """Template-driven attribute reader."""
    for key in self.attributes:
      val = attrs.get(key, None)
      if isinstance(val, str) and val.isdigit():
        val = long(val)
      setattr(self, key, val)
    for key in self.booleans:
      setattr(self, key, attrs.get(key, False))

  def make_elt(self):
    """XML element constructor."""
    elt = lxml.etree.Element("{%s}%s" % (xmlns, self.element_name), nsmap = nsmap)
    for key in self.attributes:
      val = getattr(self, key, None)
      if val is not None:
        elt.set(key, str(val))
    for key in self.booleans:
      if getattr(self, key, False):
        elt.set(key, "yes")
    return elt

  def make_b64elt(self, elt, name, value = None):
    """Constructor for Base64-encoded subelement."""
    if value is None:
      value = getattr(self, name, None)
    if value is not None:
      lxml.etree.SubElement(elt, "{%s}%s" % (xmlns, name), nsmap = nsmap).text = base64.b64encode(value)

  def __str__(self):
    """Convert a base_elt object to string format."""
    lxml.etree.tostring(self.toXML(), pretty_print = True, encoding = "us-ascii")

class data_elt(base_elt, rpki.sql.sql_persistant):
  """Virtual class for top-level left-right protocol data elements."""

  def self(this):
    """Fetch self object to which this object links."""
    return self_elt.sql_fetch(this.gctx, this.self_id)

  def bsc(self):
    """Return BSC object to which this object links."""
    return bsc_elt.sql_fetch(self.gctx, self.bsc_id)

  @classmethod
  def make_pdu(cls, **kargs):
    """Generic left-right PDU constructor."""
    self = cls()
    for k,v in kargs.items():
      if isinstance(v, bool):
        v = 1 if v else 0
      setattr(self, k, v)
    return self

  def make_reply(self, r_pdu = None):
    """Construct a reply PDU."""
    if r_pdu is None:
      r_pdu = self.__class__()
      r_pdu.self_id = self.self_id
      setattr(r_pdu, self.sql_template.index, getattr(self, self.sql_template.index))
    else:
      for b in r_pdu.booleans:
        setattr(r_pdu, b, False)
    r_pdu.action = self.action
    r_pdu.type = "reply"
    r_pdu.tag = self.tag
    return r_pdu

  def serve_pre_save_hook(self, q_pdu, r_pdu):
    """Overridable hook."""
    pass

  def serve_post_save_hook(self, q_pdu, r_pdu):
    """Overridable hook."""
    pass

  def serve_create(self, r_msg):
    """Handle a create action."""
    r_pdu = self.make_reply()
    self.serve_pre_save_hook(self, r_pdu)
    self.sql_store()
    setattr(r_pdu, self.sql_template.index, getattr(self, self.sql_template.index))
    self.serve_post_save_hook(self, r_pdu)
    r_msg.append(r_pdu)

  def serve_fetch_one(self):
    """Find the object on which a get, set, or destroy method should
    operate.  This is a separate method because the self_elt object
    needs to override it.
    """
    where = self.sql_template.index + " = %s AND self_id = %s"
    args = (getattr(self, self.sql_template.index), self.self_id)
    r = self.sql_fetch_where1(self.gctx, where, args)
    if r is None:
      raise rpki.exceptions.NotFound, "Lookup failed where %s" + (where % args)
    return r

  def serve_set(self, r_msg):
    """Handle a set action."""
    db_pdu = self.serve_fetch_one()
    r_pdu = self.make_reply()
    for a in db_pdu.sql_template.columns[1:]:
      v = getattr(self, a)
      if v is not None:
        setattr(db_pdu, a, v)
    db_pdu.sql_mark_dirty()
    db_pdu.serve_pre_save_hook(self, r_pdu)
    db_pdu.sql_store()
    db_pdu.serve_post_save_hook(self, r_pdu)
    r_msg.append(r_pdu)

  def serve_get(self, r_msg):
    """Handle a get action."""
    r_pdu = self.serve_fetch_one()
    self.make_reply(r_pdu)
    r_msg.append(r_pdu)

  def serve_list(self, r_msg):
    """Handle a list action for non-self objects."""
    for r_pdu in self.sql_fetch_where(self.gctx, "self_id = %s", (self.self_id,)):
      self.make_reply(r_pdu)
      r_msg.append(r_pdu)

  def serve_destroy(self, r_msg):
    """Handle a destroy action."""
    db_pdu = self.serve_fetch_one()
    db_pdu.sql_delete()
    r_msg.append(self.make_reply())

  def serve_dispatch(self, r_msg):
    """Action dispatch handler."""
    dispatch = { "create"  : self.serve_create,
                 "set"     : self.serve_set,
                 "get"     : self.serve_get,
                 "list"    : self.serve_list,
                 "destroy" : self.serve_destroy }
    if self.type != "query" or self.action not in dispatch:
      raise rpki.exceptions.BadQuery, "Unexpected query: type %s, action %s" % (self.type, self.action)
    dispatch[self.action](r_msg)
  
  def unimplemented_control(self, *controls):
    """Uniform handling for unimplemented control operations."""
    unimplemented = [x for x in controls if getattr(self, x, False)]
    if unimplemented:
      raise rpki.exceptions.NotImplementedYet, "Unimplemented control %s" % ", ".join(unimplemented)

class extension_preference_elt(base_elt):
  """Container for extension preferences."""

  element_name = "extension_preference"
  attributes = ("name",)

  def startElement(self, stack, name, attrs):
    """Handle <extension_preference/> elements."""
    assert name == "extension_preference", "Unexpected name %s, stack %s" % (name, stack)
    self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    """Handle <extension_preference/> elements."""
    self.value = text
    stack.pop()

  def toXML(self):
    """Generate <extension_preference/> elements."""
    elt = self.make_elt()
    elt.text = self.value
    return elt

class self_elt(data_elt):
  """<self/> element."""

  element_name = "self"
  attributes = ("action", "type", "tag", "self_id", "crl_interval", "regen_margin")
  elements = ("extension_preference",)
  booleans = ("rekey", "reissue", "revoke", "run_now", "publish_world_now", "clear_extension_preferences")

  sql_template = rpki.sql.template("self", "self_id", "use_hsm", "crl_interval", "regen_margin")

  self_id = None
  use_hsm = False
  crl_interval = None
  regen_margin = None

  def __init__(self):
    """Initialize a self_elt."""
    self.prefs = []

  def sql_fetch_hook(self):
    """Extra SQL fetch actions for self_elt -- handle extension preferences."""
    self.gctx.cur.execute("SELECT pref_name, pref_value FROM self_pref WHERE self_id = %s", (self.self_id,))
    for name, value in self.gctx.cur.fetchall():
      e = extension_preference_elt()
      e.name = name
      e.value = value
      self.prefs.append(e)

  def sql_insert_hook(self):
    """Extra SQL insert actions for self_elt -- handle extension preferences."""
    if self.prefs:
      self.gctx.cur.executemany("INSERT self_pref (self_id, pref_name, pref_value) VALUES (%s, %s, %s)",
                                ((e.name, e.value, self.self_id) for e in self.prefs))
  
  def sql_delete_hook(self):
    """Extra SQL delete actions for self_elt -- handle extension preferences."""
    self.gctx.cur.execute("DELETE FROM self_pref WHERE self_id = %s", (self.self_id,))

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
  
  def serve_pre_save_hook(self, q_pdu, r_pdu):
    """Extra server actions for self_elt -- handle extension preferences."""
    rpki.log.trace()
    if self is not q_pdu:
      if q_pdu.clear_extension_preferences:
        self.prefs = []
      self.prefs.extend(q_pdu.prefs)

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
    """Find the self object on which a get, set, or destroy method
    should operate.
    """
    r = self.sql_fetch(self.gctx, self.self_id)
    if r is None:
      raise rpki.exceptions.NotFound
    return r

  def serve_list(self, r_msg):
    """Handle a list action for self objects.  This is different from
    the list action for all other objects, where list only works
    within a given self_id context.
    """
    for r_pdu in self.sql_fetch_all(self.gctx):
      self.make_reply(r_pdu)
      r_msg.append(r_pdu)

  def startElement(self, stack, name, attrs):
    """Handle <self/> element."""
    if name == "extension_preference":
      pref = extension_preference_elt()
      self.prefs.append(pref)
      stack.append(pref)
      pref.startElement(stack, name, attrs)
    else:
      assert name == "self", "Unexpected name %s, stack %s" % (name, stack)
      self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    """Handle <self/> element."""
    assert name == "self", "Unexpected name %s, stack %s" % (name, stack)
    stack.pop()

  def toXML(self):
    """Generate <self/> element."""
    elt = self.make_elt()
    elt.extend([i.toXML() for i in self.prefs])
    return elt

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
          rpki.sql.ca_obj.create(parent, rc)
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
  attributes = ("action", "type", "tag", "self_id", "bsc_id", "key_type", "hash_alg", "key_length")
  elements = ('signing_cert',)
  booleans = ("generate_keypair", "clear_signing_certs")

  sql_template = rpki.sql.template("bsc", "bsc_id", "self_id", "hash_alg",
                                   ("private_key_id", rpki.x509.RSA),
                                   ("pkcs10_request", rpki.x509.PKCS10))

  private_key_id = None
  pkcs10_request = None

  def __init__(self):
    """Initialize bsc_elt.""" 
    self.signing_cert = rpki.x509.X509_chain()

  def sql_fetch_hook(self):
    """Extra SQL fetch actions for bsc_elt -- handle signing certs."""
    self.gctx.cur.execute("SELECT cert FROM bsc_cert WHERE bsc_id = %s", (self.bsc_id,))
    self.signing_cert[:] = [rpki.x509.X509(DER = x) for (x,) in self.gctx.cur.fetchall()]

  def sql_insert_hook(self):
    """Extra SQL insert actions for bsc_elt -- handle signing certs."""
    if self.signing_cert:
      self.gctx.cur.executemany("INSERT bsc_cert (cert, bsc_id) VALUES (%s, %s)",
                                ((x.get_DER(), self.bsc_id) for x in self.signing_cert))

  def sql_delete_hook(self):
    """Extra SQL delete actions for bsc_elt -- handle signing certs."""
    self.gctx.cur.execute("DELETE FROM bsc_cert WHERE bsc_id = %s", (self.bsc_id,))

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
    """Extra server actions for bsc_elt -- handle signing certs and key generation."""
    if self is not q_pdu:
      if q_pdu.clear_signing_certs:
        self.signing_cert[:] = []
      self.signing_cert.extend(q_pdu.signing_cert)
    if q_pdu.generate_keypair:
      #
      # For the moment we only support 2048-bit RSA with SHA-256, no
      # HSM.  Assertion just checks that the schema hasn't changed out
      # from under this code.
      #
      assert (q_pdu.key_type is None or q_pdu.key_type == "rsa") and \
             (q_pdu.hash_alg is None or q_pdu.hash_alg == "sha256") and \
             (q_pdu.key_length is None or q_pdu.key_length == 2048)
      keypair = rpki.x509.RSA()
      keypair.generate()
      self.private_key_id = keypair
      self.pkcs10_request = rpki.x509.PKCS10.create(keypair)
      r_pdu.pkcs10_request = self.pkcs10_request

  def startElement(self, stack, name, attrs):
    """Handle <bsc/> element."""
    if not name in ("signing_cert", "pkcs10_request"):
      assert name == "bsc", "Unexpected name %s, stack %s" % (name, stack)
      self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    """Handle <bsc/> element."""
    if name == "signing_cert":
      self.signing_cert.append(rpki.x509.X509(Base64 = text))
    elif name == "pkcs10_request":
      self.pkcs10_request = rpki.x509.PKCS10(Base64 = text)
    else:
      assert name == "bsc", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def toXML(self):
    """Generate <bsc/> element."""
    elt = self.make_elt()
    for cert in self.signing_cert:
      self.make_b64elt(elt, "signing_cert", cert.get_DER())
    if self.pkcs10_request is not None:
      self.make_b64elt(elt, "pkcs10_request", self.pkcs10_request.get_DER())
    return elt

class parent_elt(data_elt):
  """<parent/> element."""

  element_name = "parent"
  attributes = ("action", "type", "tag", "self_id", "parent_id", "bsc_id", "repository_id",
                "peer_contact_uri", "sia_base", "sender_name", "recipient_name")
  elements = ("peer_biz_cert", "peer_biz_glue")
  booleans = ("rekey", "reissue", "revoke")

  sql_template = rpki.sql.template("parent", "parent_id", "self_id", "bsc_id", "repository_id",
                                   ("peer_biz_cert", rpki.x509.X509), ("peer_biz_glue", rpki.x509.X509),
                                   "peer_contact_uri", "sia_base", "sender_name", "recipient_name")

  peer_biz_cert = None
  peer_biz_glue = None

  def repository(self):
    """Fetch repository object to which this parent object links."""
    return repository_elt.sql_fetch(self.gctx, self.repository_id)

  def cas(self):
    """Fetch all CA objects that link to this parent object."""
    return rpki.sql.ca_obj.sql_fetch_where(self.gctx, "parent_id = %s", (self.parent_id,))

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

  def startElement(self, stack, name, attrs):
    """Handle <parent/> element."""
    if name not in ("peer_biz_cert", "peer_biz_glue"):
      assert name == "parent", "Unexpected name %s, stack %s" % (name, stack)
      self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    """Handle <parent/> element."""
    if name == "peer_biz_cert":
      self.peer_biz_cert = rpki.x509.X509(Base64 = text)
    elif name == "peer_biz_glue":
      self.peer_biz_glue = rpki.x509.X509(Base64 = text)
    else:
      assert name == "parent", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def toXML(self):
    """Generate <parent/> element."""
    elt = self.make_elt()
    if self.peer_biz_cert and not self.peer_biz_cert.empty():
      self.make_b64elt(elt, "peer_biz_cert", self.peer_biz_cert.get_DER())
    if self.peer_biz_glue and not self.peer_biz_glue.empty():
      self.make_b64elt(elt, "peer_biz_glue", self.peer_biz_glue.get_DER())
    return elt

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
    q_cms = rpki.up_down.cms_msg.wrap(q_msg, bsc.private_key_id, bsc.signing_cert)

    der = rpki.https.client(server_ta    = self.peer_biz_cert,
                            client_key   = bsc.private_key_id,
                            client_certs = bsc.signing_cert,
                            msg          = q_cms,
                            url          = self.peer_contact_uri)

    r_msg = rpki.up_down.cms_msg.unwrap(der, self.peer_biz_cert)
    r_msg.payload.check_response()
    return r_msg


class child_elt(data_elt):
  """<child/> element."""

  element_name = "child"
  attributes = ("action", "type", "tag", "self_id", "child_id", "bsc_id")
  elements = ("peer_biz_cert", "peer_biz_glue")
  booleans = ("reissue", )

  sql_template = rpki.sql.template("child", "child_id", "self_id", "bsc_id", ("peer_biz_cert", rpki.x509.X509))

  peer_biz_cert = None
  peer_biz_glue = None
  clear_https_ta_cache = False

  def child_certs(self, ca_detail = None, ski = None, unique = False):
    """Fetch all child_cert objects that link to this child object."""
    return rpki.sql.child_cert_obj.fetch(self.gctx, self, ca_detail, ski, unique)

  def parents(self):
    """Fetch all parent objects that link to self object to which this child object links."""
    return parent_elt.sql_fetch_where(self.gctx, "self_id = %s", (self.self_id,))

  def ca_from_class_name(self, class_name):
    """Fetch the CA corresponding to an up-down class_name."""
    if not class_name.isdigit():
      raise rpki.exceptions.BadClassNameSyntax, "Bad class name %s" % class_name
    ca = rpki.sql.ca_obj.sql_fetch(self.gctx, long(class_name))
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

  def startElement(self, stack, name, attrs):
    """Handle <child/> element."""
    if name not in ("peer_biz_cert", "peer_biz_glue"):
      assert name == "child", "Unexpected name %s, stack %s" % (name, stack)
      self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    """Handle <child/> element."""
    if name == "peer_biz_cert":
      self.peer_biz_cert = rpki.x509.X509(Base64 = text)
      self.clear_https_ta_cache = True
    elif name == "peer_biz_glue":
      self.peer_biz_glue = rpki.x509.X509(Base64 = text)
      self.clear_https_ta_cache = True
    else:
      assert name == "child", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def toXML(self):
    """Generate <child/> element."""
    elt = self.make_elt()
    if self.peer_biz_cert and not self.peer_biz_cert.empty():
      self.make_b64elt(elt, "peer_biz_cert", self.peer_biz_cert.get_DER())
    if self.peer_biz_glue and not self.peer_biz_glue.empty():
      self.make_b64elt(elt, "peer_biz_glue", self.peer_biz_glue.get_DER())
    return elt

  def serve_up_down(self, query):
    """Outer layer of server handling for one up-down PDU from this child."""

    rpki.log.trace()

    bsc = self.bsc()
    if bsc is None:
      raise rpki.exceptions.BSCNotFound, "Could not find BSC %s" % self.bsc_id
    q_msg = rpki.up_down.cms_msg.unwrap(query, self.peer_biz_cert)
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
    r_cms = rpki.up_down.cms_msg.wrap(r_msg, bsc.private_key_id, bsc.signing_cert)
    return r_cms

class repository_elt(data_elt):
  """<repository/> element."""

  element_name = "repository"
  attributes = ("action", "type", "tag", "self_id", "repository_id", "bsc_id", "peer_contact_uri")
  elements = ("peer_biz_cert", "peer_biz_glue")

  sql_template = rpki.sql.template("repository", "repository_id", "self_id", "bsc_id",
                                   ("peer_biz_cert", rpki.x509.X509), "peer_contact_uri",
                                   ("peer_biz_glue", rpki.x509.X509))

  peer_biz_cert = None
  peer_biz_glue = None

  def parents(self):
    """Fetch all parent objects that link to this repository object."""
    return parent_elt.sql_fetch_where(self.gctx, "repository_id = %s", (self.repository_id,))

  def startElement(self, stack, name, attrs):
    """Handle <repository/> element."""
    if name not in ("peer_biz_cert", "peer_biz_glue"):
      assert name == "repository", "Unexpected name %s, stack %s" % (name, stack)
      self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    """Handle <repository/> element."""
    if name == "peer_biz_cert":
      self.peer_biz_cert = rpki.x509.X509(Base64 = text)
    elif name == "peer_biz_glue":
      self.peer_biz_glue = rpki.x509.X509(Base64 = text)
    else:
      assert name == "repository", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def toXML(self):
    """Generate <repository/> element."""
    elt = self.make_elt()
    if self.peer_biz_cert:
      self.make_b64elt(elt, "peer_biz_cert", self.peer_biz_cert.get_DER())
    if self.peer_biz_glue:
      self.make_b64elt(elt, "peer_biz_glue", self.peer_biz_glue.get_DER())
    return elt

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

  def publish(self, obj, uri):
    """Placeholder for publication operation. [TEMPORARY]"""
    rpki.log.trace()
    rpki.log.info("Publishing %s as %s" % (repr(obj), repr(uri)))
    self.object_write(self.gctx.publication_kludge_base, uri, obj)

  def withdraw(self, obj, uri):
    """Placeholder for publication withdrawal operation. [TEMPORARY]"""
    rpki.log.trace()
    rpki.log.info("Withdrawing %s from at %s" % (repr(obj), repr(uri)))
    self.object_delete(self.gctx.publication_kludge_base, uri)

class route_origin_elt(data_elt):
  """<route_origin/> element."""

  element_name = "route_origin"
  attributes = ("action", "type", "tag", "self_id", "route_origin_id", "as_number", "exact_match", "ipv4", "ipv6")
  booleans = ("suppress_publication",)

  sql_template = rpki.sql.template("route_origin", "route_origin_id", "ca_detail_id",
                                   "self_id", "as_number", "exact_match",
                                   ("roa", rpki.x509.ROA),
                                   ("cert", rpki.x509.X509))

  ca_detail_id = None
  cert = None
  roa = None

  def sql_fetch_hook(self):
    """Extra SQL fetch actions for route_origin_elt -- handle address ranges."""
    self.ipv4 = rpki.resource_set.resource_set_ipv4.from_sql(self.gctx.cur, """
                SELECT start_ip, end_ip FROM route_origin_range
                WHERE route_origin_id = %s AND start_ip NOT LIKE '%:%'
                """, (self.route_origin_id,))
    self.ipv6 = rpki.resource_set.resource_set_ipv6.from_sql(self.gctx.cur, """
                SELECT start_ip, end_ip FROM route_origin_range
                WHERE route_origin_id = %s AND start_ip LIKE '%:%'
                """, (self.route_origin_id,))

  def sql_insert_hook(self):
    """Extra SQL insert actions for route_origin_elt -- handle address ranges."""
    if self.ipv4 or self.ipv6:
      self.gctx.cur.executemany("""
                INSERT route_origin_range (route_origin_id, start_ip, end_ip)
                VALUES (%s, %s, %s)""",
                           ((self.route_origin_id, x.min, x.max)
                            for x in (self.ipv4 or []) + (self.ipv6 or [])))
  
  def sql_delete_hook(self):
    """Extra SQL delete actions for route_origin_elt -- handle address ranges."""
    self.gctx.cur.execute("DELETE FROM route_origin_range WHERE route_origin_id = %s", (self.route_origin_id,))

  def ca_detail(self):
    """Fetch all ca_detail objects that link to this route_origin object."""
    return rpki.sql.ca_detail_obj.sql_fetch(self.gctx, self.ca_detail_id)

  def serve_post_save_hook(self, q_pdu, r_pdu):
    """Extra server actions for route_origin_elt."""
    self.unimplemented_control("suppress_publication")

  def startElement(self, stack, name, attrs):
    """Handle <route_origin/> element."""
    assert name == "route_origin", "Unexpected name %s, stack %s" % (name, stack)
    self.read_attrs(attrs)
    if self.as_number is not None:
      self.as_number = long(self.as_number)
    if self.ipv4 is not None:
      self.ipv4 = rpki.resource_set.resource_set_ipv4(self.ipv4)
    if self.ipv6 is not None:
      self.ipv6 = rpki.resource_set.resource_set_ipv6(self.ipv4)

  def endElement(self, stack, name, text):
    """Handle <route_origin/> element."""
    assert name == "route_origin", "Unexpected name %s, stack %s" % (name, stack)
    stack.pop()

  def toXML(self):
    """Generate <route_origin/> element."""
    return self.make_elt()

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

    v4 = self.ipv4 if self.ipv4 is not None else rpki.resource_set.resource_set_ipv4()
    v6 = self.ipv6 if self.ipv6 is not None else rpki.resource_set.resource_set_ipv6()

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

    if self.exact_match is None:
      rpki.log.warn("Can't generate ROA with undefined exactMatch")
      return

    if self.ipv4 is None and self.ipv6 is None:
      rpki.log.warn("Can't generate ROA for empty address list")
      return

    # Ugly and expensive search for covering ca_detail, there has to
    # be a better way.
    #
    # If we're reissuing (not handled yet) we can optimize this by 
    # first checking the ca_detail we used last time, but it may not
    # be active, in which we have to check the ca_detail that replaced it.

    ca_detail = self.ca_detail()
    if ca_detail is None or ca_detail.state != "active":
      ca_detail = None
      for parent in self.self().parents():
        for ca in parent.cas():
          ca_detail = ca.fetch_active()
          if ca_detail is not None:
            resources = ca_detail.latest_ca_cert.get_3779resources()
            if ((self.ipv4 is None or self.ipv4.issubset(resources.v4)) and
                (self.ipv6 is None or self.ipv6.issubset(resources.v6))):
              break
            ca_detail = None
        if ca_detail is not None:
          break

    if ca_detail is None:
      rpki.log.warn("generate_roa() could not find a covering certificate")
      return

    resources = rpki.resource_set.resource_bag(v4 = self.ipv4, v6 = self.ipv6)

    keypair = rpki.x509.RSA()
    keypair.generate()

    sia = ((rpki.oids.name2oid["id-ad-signedObject"], ("uri", self.roa_uri(ca, keypair))),)

    self.cert = ca_detail.issue_ee(ca, resources, keypair.get_RSApublic(), sia = sia)
    self.roa = rpki.x509.ROA.build(self.as_number, self.exact_match, self.ipv4, self.ipv6, keypair, (self.cert,))
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
    rpki.sql.revoked_cert_obj.revoke(cert = cert, ca_detail = ca_detail)
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

class list_resources_elt(base_elt):
  """<list_resources/> element."""

  element_name = "list_resources"
  attributes = ("type", "self_id", "tag", "child_id", "valid_until", "as", "ipv4", "ipv6", "subject_name")
  valid_until = None

  def startElement(self, stack, name, attrs):
    """Handle <list_resources/> element."""
    assert name == "list_resources", "Unexpected name %s, stack %s" % (name, stack)
    self.read_attrs(attrs)
    if isinstance(self.valid_until, str):
      self.valid_until = rpki.sundial.datetime.fromXMLtime(self.valid_until)
    if self.as is not None:
      self.as = rpki.resource_set.resource_set_as(self.as)
    if self.ipv4 is not None:
      self.ipv4 = rpki.resource_set.resource_set_ipv4(self.ipv4)
    if self.ipv6 is not None:
      self.ipv6 = rpki.resource_set.resource_set_ipv6(self.ipv6)

  def toXML(self):
    """Generate <list_resources/> element."""
    elt = self.make_elt()
    if isinstance(self.valid_until, int):
      elt.set("valid_until", self.valid_until.toXMLtime())
    return elt

class report_error_elt(base_elt):
  """<report_error/> element."""

  element_name = "report_error"
  attributes = ("tag", "self_id", "error_code")

  def startElement(self, stack, name, attrs):
    """Handle <report_error/> element."""
    assert name == self.element_name, "Unexpected name %s, stack %s" % (name, stack)
    self.read_attrs(attrs)

  def toXML(self):
    """Generate <report_error/> element."""
    return self.make_elt()

  @classmethod
  def from_exception(cls, exc, self_id = None):
    """Generate a <report_error/> element from an exception."""
    self = cls()
    self.self_id = self_id
    self.error_code = exc.__class__.__name__
    return self

class msg(list):
  """Left-right PDU."""

  ## @var version
  # Protocol version
  version = 1

  ## @var pdus
  # Dispatch table of PDUs for this protocol.
  pdus = dict((x.element_name, x)
              for x in (self_elt, child_elt, parent_elt, bsc_elt, repository_elt,
                        route_origin_elt, list_resources_elt, report_error_elt))

  def startElement(self, stack, name, attrs):
    """Handle left-right PDU."""
    if name == "msg":
      assert self.version == int(attrs["version"])
    else:
      elt = self.pdus[name]()
      self.append(elt)
      stack.append(elt)
      elt.startElement(stack, name, attrs)

  def endElement(self, stack, name, text):
    """Handle left-right PDU."""
    assert name == "msg", "Unexpected name %s, stack %s" % (name, stack)
    assert len(stack) == 1
    stack.pop()

  def __str__(self):
    """Convert msg object to string."""
    lxml.etree.tostring(self.toXML(), pretty_print = True, encoding = "us-ascii")

  def toXML(self):
    """Generate left-right PDU."""
    elt = lxml.etree.Element("{%s}msg" % (xmlns), nsmap = nsmap, version = str(self.version))
    elt.extend([i.toXML() for i in self])
    return elt

  def serve_top_level(self, gctx):
    """Serve one msg PDU."""
    r_msg = self.__class__()
    for q_pdu in self:
      q_pdu.gctx = gctx
      q_pdu.serve_dispatch(r_msg)
    return r_msg

class sax_handler(rpki.sax_utils.handler):
  """SAX handler for Left-Right protocol."""

  pdu = msg
  name = "msg"
  version = "1"

class cms_msg(rpki.x509.XML_CMS_object):
  """Class to hold a CMS-signed left-right PDU."""

  encoding = "us-ascii"
  schema = rpki.relaxng.left_right
  saxify = sax_handler.saxify
