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
import rpki.sax_utils, rpki.resource_set, rpki.x509, rpki.sql, rpki.exceptions
import rpki.https, rpki.up_down, rpki.relaxng, rpki.sundial, rpki.log

xmlns = "http://www.hactrn.net/uris/rpki/left-right-spec/"

nsmap = { None : xmlns }

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

  def self(this, gctx):
    """Fetch self object to which this object links."""
    return self_elt.sql_fetch(gctx, this.self_id)

  def bsc(self, gctx):
    """Return BSC object to which this object links."""
    return bsc_elt.sql_fetch(gctx, self.bsc_id)

  @classmethod
  def make_pdu(cls, **kargs):
    """Generic left-right PDU constructor."""
    self = cls()
    for k,v in kargs.items():
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

  def serve_pre_save_hook(self, gctx, q_pdu, r_pdu):
    """Overridable hook."""
    pass

  def serve_post_save_hook(self, gctx, q_pdu, r_pdu):
    """Overridable hook."""
    pass

  def serve_create(self, gctx, r_msg):
    """Handle a create action."""
    r_pdu = self.make_reply()
    self.serve_pre_save_hook(gctx, self, r_pdu)
    self.sql_store(gctx)
    setattr(r_pdu, self.sql_template.index, getattr(self, self.sql_template.index))
    self.serve_post_save_hook(gctx, self, r_pdu)
    r_msg.append(r_pdu)

  def serve_fetch_one(self, gctx):
    """Find the object on which a get, set, or destroy method should
    operate.  This is a separate method because the self object needs
    to override it.
    """
    where = self.sql_template.index + " = %s AND self_id = %s"
    args = (getattr(self, self.sql_template.index), self.self_id)
    r = self.sql_fetch_where1(gctx, where, args)
    if r is None:
      raise rpki.exceptions.NotFound, "Lookup failed where %s" + (where % args)
    return r

  def serve_set(self, gctx, r_msg):
    """Handle a set action."""
    db_pdu = self.serve_fetch_one(gctx)
    r_pdu = self.make_reply()
    for a in db_pdu.sql_template.columns[1:]:
      v = getattr(self, a)
      if v is not None:
        setattr(db_pdu, a, v)
    db_pdu.sql_mark_dirty()
    db_pdu.serve_pre_save_hook(gctx, self, r_pdu)
    db_pdu.sql_store(gctx)
    db_pdu.serve_post_save_hook(gctx, self, r_pdu)
    r_msg.append(r_pdu)

  def serve_get(self, gctx, r_msg):
    """Handle a get action."""
    r_pdu = self.serve_fetch_one(gctx)
    self.make_reply(r_pdu)
    r_msg.append(r_pdu)

  def serve_list(self, gctx, r_msg):
    """Handle a list action for non-self objects."""
    for r_pdu in self.sql_fetch_where(gctx, "self_id = %s", (self.self_id,)):
      self.make_reply(r_pdu)
      r_msg.append(r_pdu)

  def serve_destroy(self, gctx, r_msg):
    """Handle a destroy action."""
    db_pdu = self.serve_fetch_one(gctx)
    db_pdu.sql_delete(gctx)
    r_msg.append(self.make_reply())

  def serve_dispatch(self, gctx, r_msg):
    """Action dispatch handler."""
    dispatch = { "create"  : self.serve_create,
                 "set"     : self.serve_set,
                 "get"     : self.serve_get,
                 "list"    : self.serve_list,
                 "destroy" : self.serve_destroy }
    if self.type != "query" or self.action not in dispatch:
      raise rpki.exceptions.BadQuery, "Unexpected query: type %s, action %s" % (self.type, self.action)
    dispatch[self.action](gctx, r_msg)
  
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
  attributes = ("action", "type", "tag", "self_id", "crl_interval")
  elements = ("extension_preference",)
  booleans = ("rekey", "reissue", "revoke", "run_now", "publish_world_now", "clear_extension_preferences")

  sql_template = rpki.sql.template("self", "self_id", "use_hsm", "crl_interval")

  self_id = None
  use_hsm = False
  crl_interval = None

  def __init__(self):
    """Initialize a self_elt."""
    self.prefs = []

  def sql_fetch_hook(self, gctx):
    """Extra SQL fetch actions for self_elt -- handle extension preferences."""
    gctx.cur.execute("SELECT pref_name, pref_value FROM self_pref WHERE self_id = %s", (self.self_id,))
    for name, value in gctx.cur.fetchall():
      e = extension_preference_elt()
      e.name = name
      e.value = value
      self.prefs.append(e)

  def sql_insert_hook(self, gctx):
    """Extra SQL insert actions for self_elt -- handle extension preferences."""
    if self.prefs:
      gctx.cur.executemany("INSERT self_pref (self_id, pref_name, pref_value) VALUES (%s, %s, %s)",
                           ((e.name, e.value, self.self_id) for e in self.prefs))
  
  def sql_delete_hook(self, gctx):
    """Extra SQL delete actions for self_elt -- handle extension preferences."""
    gctx.cur.execute("DELETE FROM self_pref WHERE self_id = %s", (self.self_id,))

  def bscs(self, gctx):
    """Fetch all BSC objects that link to this self object."""
    return bsc_elt.sql_fetch_where(gctx, "self_id = %s", (self.self_id,))

  def repositories(self, gctx):
    """Fetch all repository objects that link to this self object."""
    return repository_elt.sql_fetch_where(gctx, "self_id = %s", (self.self_id,))

  def parents(self, gctx):
    """Fetch all parent objects that link to this self object."""
    return parent_elt.sql_fetch_where(gctx, "self_id = %s", (self.self_id,))

  def children(self, gctx):
    """Fetch all child objects that link to this self object."""
    return child_elt.sql_fetch_where(gctx, "self_id = %s", (self.self_id,))

  def route_origins(self, gctx):
    """Fetch all route_origin objects that link to this self object."""
    return route_origin_elt.sql_fetch_where(gctx, "self_id = %s", (self.self_id,))
  
  def serve_pre_save_hook(self, gctx, q_pdu, r_pdu):
    """Extra server actions for self_elt -- handle extension preferences."""
    if self is not q_pdu:
      if q_pdu.clear_extension_preferences:
        self.prefs = []
      self.prefs.extend(pdu.prefs)

  def serve_post_save_hook(self, gctx, q_pdu, r_pdu):
    """Extra server actions for self_elt."""
    if self.rekey:
      self.serve_rekey(gctx)
    if self.reissue:
      self.serve_reissue(gctx)
    if self.revoke:
      self.serve_revoke(gctx)
    self.unimplemented_control("run_now", "publish_world_now")

  def serve_rekey(self, gctx):
    """Handle a left-right rekey action for this self."""
    for parent in self.parents(gctx):
      parent.serve_rekey(gctx)

  def serve_revoke(self, gctx):
    """Handle a left-right revoke action for this self."""
    for parent in self.parents(gctx):
      parent.serve_revoke(gctx)

  def serve_reissue(self, gctx):
    """Handle a left-right reissue action for this self."""
    for parent in self.parents(gctx):
      parent.serve_reissue(gctx)

  def serve_fetch_one(self, gctx):
    """Find the self object on which a get, set, or destroy method
    should operate.
    """
    r = self.sql_fetch(gctx, self.self_id)
    if r is None:
      raise rpki.exceptions.NotFound
    return r

  def serve_list(self, gctx, r_msg):
    """Handle a list action for self objects.  This is different from
    the list action for all other objects, where list only works
    within a given self_id context.
    """
    for r_pdu in self.sql_fetch_all(gctx):
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

  def client_poll(self, gctx):
    """Run the regular client poll cycle with each of this self's parents in turn."""

    rpki.log.trace()

    for parent in self.parents(gctx):

      # This will need a callback when we go event-driven
      r_msg = rpki.up_down.list_pdu.query(gctx, parent)

      ca_map = dict((ca.parent_resource_class, ca) for ca in parent.cas(gctx))
      for rc in r_msg.payload.classes:
        if rc.class_name in ca_map:
          ca = ca_map[rc.class_name]
          del  ca_map[rc.class_name]
          ca.check_for_updates(gctx, parent, rc)
        else:
          rpki.sql.ca_obj.create(gctx, parent, rc)
      for ca in ca_map.values():
        ca.delete(gctx, parent)         # CA not listed by parent
      rpki.sql.sql_sweep(gctx)

  def update_children(self, gctx):
    """Check for updated IRDB data for all of this self's children and
    issue new certs as necessary.  Must handle changes both in
    resources and in expiration date.
    """

    rpki.log.trace()

    now = rpki.sundial.datetime.utcnow()

    for child in self.children(gctx):
      child_certs = child.child_certs(gctx)
      if not child_certs:
        continue

      # This will require a callback when we go event-driven
      irdb_resources = rpki.left_right.irdb_query(gctx, child.self_id, child.child_id)

      for child_cert in child_certs:
        ca_detail = child_cert.ca_detail(gctx)
        if ca_detail.state != "active":
          continue
        old_resources = child_cert.cert.get_3779resources()
        new_resources = irdb_resources.intersection(old_resources)
        if old_resources != new_resources:
          rpki.log.debug("Need to reissue %s" % repr(child_cert))
          child_cert.reissue(
            gctx      = gctx,
            ca_detail = ca_detail,
            resources = new_resources,
            sia       = ca_detail.ca(gctx).sia_uri)
        elif old_resources.valid_until < now:
          parent = ca.parent(gctx)
          repository = parent.repository(gctx)
          child_cert.sql_delete(gctx)
          ca_detail.generate_manifest(gctx)
          repository.publish(gctx,  (ca_detail.latest_manifest, ca_detail.manifest_uri(ca)))
          repository.withdraw(gctx, (child_cert.cert, child_cert.uri(ca)))

  def regenerate_crls_and_manifests(self, gctx):
    """Generate new CRLs and manifests as necessary for all of this
    self's CAs.  Extracting nextUpdate from a manifest is hard at the
    moment due to implementation silliness, so for now we generate a
    new manifest whenever we generate a new CRL
    """

    rpki.log.trace()

    now = rpki.sundial.datetime.utcnow()
    for parent in self.parents(gctx):
      repository = parent.repository(gctx)
      for ca in parent.cas(gctx):
        ca_detail = ca.fetch_active(gctx)
        #
        # Temporary kludge until I sort out initial publication.
        #
        if True or now > ca_detail.latest_crl.getNextUpdate():
          ca_detail.generate_crl(gctx)
          ca_detail.generate_manifest(gctx)
          repository.publish(gctx,
                             (ca_detail.latest_crl,      ca_detail.crl_uri(ca)),
                             (ca_detail.latest_manifest, ca_detail.manifest_uri(ca)))

class bsc_elt(data_elt):
  """<bsc/> (Business Signing Context) element."""
  
  element_name = "bsc"
  attributes = ("action", "type", "tag", "self_id", "bsc_id", "key_type", "hash_alg", "key_length")
  elements = ('signing_cert',)
  booleans = ("generate_keypair", "clear_signing_certs")

  sql_template = rpki.sql.template("bsc", "bsc_id", "self_id",
                                   ("public_key", rpki.x509.RSApublic),
                                   ("private_key_id", rpki.x509.RSA), "hash_alg")

  pkcs10_cert_request = None
  public_key = None
  private_key_id = None

  def __init__(self):
    """Initialize bsc_elt.""" 
    self.signing_cert = rpki.x509.X509_chain()

  def sql_fetch_hook(self, gctx):
    """Extra SQL fetch actions for bsc_elt -- handle signing certs."""
    gctx.cur.execute("SELECT cert FROM bsc_cert WHERE bsc_id = %s", (self.bsc_id,))
    self.signing_cert[:] = [rpki.x509.X509(DER = x) for (x,) in gctx.cur.fetchall()]

  def sql_insert_hook(self, gctx):
    """Extra SQL insert actions for bsc_elt -- handle signing certs."""
    if self.signing_cert:
      gctx.cur.executemany("INSERT bsc_cert (cert, bsc_id) VALUES (%s, %s)",
                           ((x.get_DER(), self.bsc_id) for x in self.signing_cert))

  def sql_delete_hook(self, gctx):
    """Extra SQL delete actions for bsc_elt -- handle signing certs."""
    gctx.cur.execute("DELETE FROM bsc_cert WHERE bsc_id = %s", (self.bsc_id,))

  def repositories(self, gctx):
    """Fetch all repository objects that link to this BSC object."""
    return repository_elt.sql_fetch_where(gctx, "bsc_id = %s", (self.bsc_id,))

  def parents(self, gctx):
    """Fetch all parent objects that link to this BSC object."""
    return parent_elt.sql_fetch_where(gctx, "bsc_id = %s", (self.bsc_id,))

  def children(self, gctx):
    """Fetch all child objects that link to this BSC object."""
    return child_elt.sql_fetch_where(gctx, "bsc_id = %s", (self.bsc_id,))

  def serve_pre_save_hook(self, gctx, q_pdu, r_pdu):
    """Extra server actions for bsc_elt -- handle signing certs and key generation."""
    if self is not q_pdu:
      if q_pdu.clear_signing_certs:
        self.signing_cert[:] = []
      self.signing_cert.extend(q_pdu.signing_cert)
    if q_pdu.generate_keypair:
      #
      # Hard wire 2048-bit RSA with SHA-256 in schema for now.
      # Assume no HSM for now.
      #
      keypair = rpki.x509.RSA()
      keypair.generate()
      self.private_key_id = keypair
      self.public_key = keypair.get_RSApublic()
      r_pdu.pkcs10_cert_request = rpki.x509.PKCS10.create(keypair)

  def startElement(self, stack, name, attrs):
    """Handle <bsc/> element."""
    if not name in ("signing_cert", "public_key", "pkcs10_cert_request"):
      assert name == "bsc", "Unexpected name %s, stack %s" % (name, stack)
      self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    """Handle <bsc/> element."""
    if name == "signing_cert":
      self.signing_cert.append(rpki.x509.X509(Base64 = text))
    elif name == "public_key":
      self.public_key = rpki.x509.RSApublic(Base64 = text)
    elif name == "pkcs10_cert_request":
      self.pkcs10_cert_request = rpki.x509.PKCS10(Base64 = text)
    else:
      assert name == "bsc", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def toXML(self):
    """Generate <bsc/> element."""
    elt = self.make_elt()
    for cert in self.signing_cert:
      self.make_b64elt(elt, "signing_cert", cert.get_DER())
    if self.pkcs10_cert_request is not None:
      self.make_b64elt(elt, "pkcs10_cert_request", self.pkcs10_cert_request.get_DER())
    if self.public_key is not None:
      self.make_b64elt(elt, "public_key", self.public_key.get_DER())
    return elt

class parent_elt(data_elt):
  """<parent/> element."""

  element_name = "parent"
  attributes = ("action", "type", "tag", "self_id", "parent_id", "bsc_id", "repository_id",
                "peer_contact_uri", "sia_base", "sender_name", "recipient_name")
  elements = ("cms_ta", "https_ta")
  booleans = ("rekey", "reissue", "revoke")

  sql_template = rpki.sql.template("parent", "parent_id", "self_id", "bsc_id", "repository_id",
                                   ("cms_ta", rpki.x509.X509), ("https_ta", rpki.x509.X509),
                                   "peer_contact_uri", "sia_base", "sender_name", "recipient_name")

  cms_ta = None
  https_ta = None

  def repository(self, gctx):
    """Fetch repository object to which this parent object links."""
    return repository_elt.sql_fetch(gctx, self.repository_id)

  def cas(self, gctx):
    """Fetch all CA objects that link to this parent object."""
    return rpki.sql.ca_obj.sql_fetch_where(gctx, "parent_id = %s", (self.parent_id,))

  def serve_post_save_hook(self, gctx, q_pdu, r_pdu):
    """Extra server actions for parent_elt."""
    if self.rekey:
      self.serve_rekey(gctx)
    if self.reissue:
      self.serve_reissue(gctx)
    if self.revoke:
      self.serve_revoke(gctx)

  def serve_rekey(self, gctx):
    """Handle a left-right rekey action for this parent."""
    for ca in self.cas(gctx):
      ca.rekey(gctx)

  def serve_revoke(self, gctx):
    """Handle a left-right revoke action for this parent."""
    for ca in self.cas(gctx):
      for ca_detail in ca.ca_details(gctx):
        ca_detail.revoke(gctx)

  def serve_reissue(self, gctx):
    """Handle a left-right reissue action for this parent."""
    for ca in self.cas(gctx):
      for ca_detail in ca.ca_details(gctx):
        for child_certs in ca_detail.child_certs(gctx):
          #
          # I guess this reuses existing SIA and resources.  Should
          # child_cert.reissue() allow defaults for those?  At present
          # that would be a no-op, so what was the point?
          #
          raise rpki.exceptions.NotImplementedYet

  def startElement(self, stack, name, attrs):
    """Handle <parent/> element."""
    if name not in ("cms_ta", "https_ta"):
      assert name == "parent", "Unexpected name %s, stack %s" % (name, stack)
      self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    """Handle <parent/> element."""
    if name == "cms_ta":
      self.cms_ta = rpki.x509.X509(Base64 = text)
    elif name == "https_ta":
      self.https_ta = rpki.x509.X509(Base64 = text)
    else:
      assert name == "parent", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def toXML(self):
    """Generate <parent/> element."""
    elt = self.make_elt()
    if self.cms_ta and not self.cms_ta.empty():
      self.make_b64elt(elt, "cms_ta", self.cms_ta.get_DER())
    if self.https_ta and not self.https_ta.empty():
      self.make_b64elt(elt, "https_ta", self.https_ta.get_DER())
    return elt

  def query_up_down(self, gctx, q_pdu):
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

    bsc = self.bsc(gctx)
    if bsc is None:
      raise rpki.exceptions.BSCNotFound, "Could not find BSC %s" % self.bsc_id
    q_msg = rpki.up_down.message_pdu.make_query(
      payload = q_pdu,
      sender = self.sender_name,
      recipient = self.recipient_name)
    q_elt = q_msg.toXML()
    try:
      rpki.relaxng.up_down.assertValid(q_elt)
    except lxml.etree.DocumentInvalid:
      rpki.log.error("Message does not pass schema check: " + lxml.etree.tostring(q_elt, pretty_print = True))
      raise
    q_cms = rpki.cms.xml_sign(q_elt, bsc.private_key_id, bsc.signing_cert, encoding = "UTF-8")
    r_cms = rpki.https.client(x509TrustList = rpki.x509.X509_chain(self.https_ta),
                              privateKey = gctx.https_key,
                              certChain = gctx.https_certs,
                              msg = q_cms,
                              url = self.peer_contact_uri)
    r_elt = rpki.cms.xml_verify(r_cms, self.cms_ta)
    rpki.relaxng.up_down.assertValid(r_elt)
    r_msg = rpki.up_down.sax_handler.saxify(r_elt)
    r_msg.payload.check_response()
    return r_msg


class child_elt(data_elt):
  """<child/> element."""

  element_name = "child"
  attributes = ("action", "type", "tag", "self_id", "child_id", "bsc_id")
  elements = ("cms_ta",)
  booleans = ("reissue", )

  sql_template = rpki.sql.template("child", "child_id", "self_id", "bsc_id", ("cms_ta", rpki.x509.X509))

  cms_ta = None

  def child_certs(self, gctx, ca_detail = None, ski = None, revoked = False, unique = False):
    """Fetch all child_cert objects that link to this child object."""
    return rpki.sql.child_cert_obj.fetch(gctx, self, ca_detail, ski, revoked, unique)

  def parents(self, gctx):
    """Fetch all parent objects that link to self object to which this child object links."""
    return parent_elt.sql_fetch_where(gctx, "self_id = %s", (self.self_id,))

  def ca_from_class_name(self, gctx, class_name):
    """Fetch the CA corresponding to an up-down class_name."""
    if not class_name.isdigit():
      raise rpki.exceptions.BadClassNameSyntax, "Bad class name %s" % class_name
    ca = rpki.sql.ca_obj.sql_fetch(gctx, long(class_name))
    parent = ca.parent(gctx)
    if self.self_id != parent.self_id:
      raise rpki.exceptions.ClassNameMismatch, "child.self_id = %d, parent.self_id = %d" % (self.self_id, parent.self_id)
    return ca

  def serve_post_save_hook(self, gctx, q_pdu, r_pdu):
    """Extra server actions for child_elt."""
    self.unimplemented_control("reissue")

  def startElement(self, stack, name, attrs):
    """Handle <child/> element."""
    if name != "cms_ta":
      assert name == "child", "Unexpected name %s, stack %s" % (name, stack)
      self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    """Handle <child/> element."""
    if name == "cms_ta":
      self.cms_ta = rpki.x509.X509(Base64 = text)
    else:
      assert name == "child", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def toXML(self):
    """Generate <child/> element."""
    elt = self.make_elt()
    if self.cms_ta:
      self.make_b64elt(elt, "cms_ta", self.cms_ta.get_DER())
    return elt

  def serve_up_down(self, gctx, query):
    """Outer layer of server handling for one up-down PDU from this child."""

    rpki.log.trace()

    bsc = self.bsc(gctx)
    if bsc is None:
      raise rpki.exceptions.BSCNotFound, "Could not find BSC %s" % self.bsc_id
    q_elt = rpki.cms.xml_verify(query, self.cms_ta)
    rpki.relaxng.up_down.assertValid(q_elt)
    q_msg = rpki.up_down.sax_handler.saxify(q_elt)
    #if q_msg.sender != str(self.child_id):
    #  raise rpki.exceptions.BadSender, "Unexpected XML sender %s" % q_msg.sender
    try:
      r_msg = q_msg.serve_top_level(gctx, self)
    except Exception, data:
      rpki.log.error(traceback.format_exc())
      r_msg = q_msg.serve_error(data)
    #
    # Exceptions from this point on are problematic, as we have no
    # sane way of reporting errors in the error reporting mechanism.
    # May require refactoring, ignore the issue for now.
    #
    r_elt = r_msg.toXML()
    try:
      rpki.relaxng.up_down.assertValid(r_elt)
    except:
      rpki.log.debug(lxml.etree.tostring(r_elt, pretty_print = True, encoding = "UTF-8"))
      rpki.log.error(traceback.format_exc())
      raise
    return rpki.cms.xml_sign(r_elt, bsc.private_key_id, bsc.signing_cert, encoding = "UTF-8")

class repository_elt(data_elt):
  """<repository/> element."""

  element_name = "repository"
  attributes = ("action", "type", "tag", "self_id", "repository_id", "bsc_id", "peer_contact_uri")
  elements = ("cms_ta", "https_ta")

  sql_template = rpki.sql.template("repository", "repository_id", "self_id", "bsc_id",
                                   ("cms_ta", rpki.x509.X509), "peer_contact_uri",
                                   ("https_ta", rpki.x509.X509))

  cms_ta = None
  https_ta = None

  def parents(self, gctx):
    """Fetch all parent objects that link to this repository object."""
    return parent_elt.sql_fetch_where(gctx, "repository_id = %s", (self.repository_id,))

  def startElement(self, stack, name, attrs):
    """Handle <repository/> element."""
    if name not in ("cms_ta", "https_ta"):
      assert name == "repository", "Unexpected name %s, stack %s" % (name, stack)
      self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    """Handle <repository/> element."""
    if name == "cms_ta":
      self.cms_ta = rpki.x509.X509(Base64 = text)
    elif name == "https_ta":
      self.https_ta = rpki.x509.X509(Base64 = text)
    else:
      assert name == "repository", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def toXML(self):
    """Generate <repository/> element."""
    elt = self.make_elt()
    if self.cms_ta:
      self.make_b64elt(elt, "cms_ta", self.cms_ta.get_DER())
    if self.https_ta:
      self.make_b64elt(elt, "https_ta", self.https_ta.get_DER())
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

  def publish(self, gctx, *things):
    """Placeholder for publication operation. [TEMPORARY]"""
    rpki.log.trace()
    for obj, uri in things:
      rpki.log.info("Pretending to publish %s to repository %s at %s" % (repr(obj), repr(self), repr(uri)))
      self.object_write(gctx.publication_kludge_base, uri, obj)

  def withdraw(self, gctx, *things):
    """Placeholder for publication withdrawal operation. [TEMPORARY]"""
    rpki.log.trace()
    for obj, uri in things:
      rpki.log.info("Pretending to withdraw %s from repository %s at %s" % (repr(obj), repr(self), repr(uri)))
      self.object_delete(gctx.publication_kludge_base, uri)

class route_origin_elt(data_elt):
  """<route_origin/> element."""

  element_name = "route_origin"
  attributes = ("action", "type", "tag", "self_id", "route_origin_id", "as_number", "ipv4", "ipv6")
  booleans = ("suppress_publication",)

  sql_template = rpki.sql.template("route_origin", "route_origin_id", "self_id", "as_number",
                                   "ca_detail_id", "roa")

  ca_detail_id = None
  roa = None

  def sql_fetch_hook(self, gctx):
    """Extra SQL fetch actions for route_origin_elt -- handle address ranges."""
    self.ipv4 = rpki.resource_set.resource_set_ipv4.from_sql(gctx.cur, """
                SELECT start_ip, end_ip FROM route_origin_range
                WHERE route_origin_id = %s AND start_ip NOT LIKE '%:%'
                """, (self.route_origin_id,))
    self.ipv6 = rpki.resource_set.resource_set_ipv6.from_sql(gctx.cur, """
                SELECT start_ip, end_ip FROM route_origin_range
                WHERE route_origin_id = %s AND start_ip LIKE '%:%'
                """, (self.route_origin_id,))

  def sql_insert_hook(self, gctx):
    """Extra SQL insert actions for route_origin_elt -- handle address ranges."""
    if self.ipv4 + self.ipv6:
      gctx.cur.executemany("""
                INSERT route_origin_range (route_origin_id, start_ip, end_ip)
                VALUES (%s, %s, %s)""",
                           ((self.route_origin_id, x.min, x.max) for x in self.ipv4 + self.ipv6))
  
  def sql_delete_hook(self, gctx):
    """Extra SQL delete actions for route_origin_elt -- handle address ranges."""
    gctx.cur.execute("DELETE FROM route_origin_range WHERE route_origin_id = %s", (self.route_origin_id,))

  def ca_detail(self, gctx):
    """Fetch all ca_detail objects that link to this route_origin object."""
    return rpki.sql.ca_detail_obj.sql_fetch(gctx, self.ca_detail_id)

  def serve_post_save_hook(self, gctx, q_pdu, r_pdu):
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
      q_pdu.serve_dispatch(gctx, r_msg)
    return r_msg

class sax_handler(rpki.sax_utils.handler):
  """SAX handler for Left-Right protocol."""

  ## @var pdu
  # Top-level PDU class
  pdu = msg

  def create_top_level(self, name, attrs):
    """Top-level PDU for this protocol is <msg/>."""
    assert name == "msg" and attrs["version"] == "1"
    return self.pdu()

def irdb_query(gctx, self_id, child_id = None):
  """Perform an IRDB callback query.  In the long run this should not
  be a blocking routine, it should instead issue a query and set up a
  handler to receive the response.  For the moment, though, we are
  doing simple lock step and damn the torpedos.  Not yet doing
  anything useful with subject name.  Most likely this function should
  really be wrapped up in a class that carries both the query result
  and also the intermediate state needed for the event-driven code
  that this function will need to become.
  """

  rpki.log.trace()

  q_msg = msg()
  q_msg.append(list_resources_elt())
  q_msg[0].type = "query"
  q_msg[0].self_id = self_id
  q_msg[0].child_id = child_id
  q_elt = q_msg.toXML()
  rpki.relaxng.left_right.assertValid(q_elt)
  q_cms = rpki.cms.xml_sign(q_elt, gctx.cms_key, gctx.cms_certs)
  r_cms = rpki.https.client(
    privateKey    = gctx.https_key,
    certChain     = gctx.https_certs,
    x509TrustList = gctx.https_ta,
    url           = gctx.irdb_url,
    msg           = q_cms)
  r_elt = rpki.cms.xml_verify(r_cms, gctx.cms_ta_irdb)
  rpki.relaxng.left_right.assertValid(r_elt)
  r_msg = rpki.left_right.sax_handler.saxify(r_elt)
  if len(r_msg) == 0 or not isinstance(r_msg[0], list_resources_elt) or r_msg[0].type != "reply":
    raise rpki.exceptions.BadIRDBReply, "Unexpected response to IRDB query: %s" % lxml.etree.tostring(r_msg.toXML(), pretty_print = True, encoding = "us-ascii")
  return rpki.resource_set.resource_bag(
    as          = r_msg[0].as,
    v4          = r_msg[0].ipv4,
    v6          = r_msg[0].ipv6,
    valid_until = r_msg[0].valid_until)
