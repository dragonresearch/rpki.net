# $Id$

"""RPKI "left-right" protocol."""

import base64, rpki.sax_utils, rpki.resource_set, lxml.etree, rpki.x509, rpki.sql

xmlns = "http://www.hactrn.net/uris/rpki/left-right-spec/"

nsmap = { None : xmlns }

class base_elt(object):
  """Virtual base type for left-right message elements."""

  attributes = ()
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
    elt = lxml.etree.Element("{%s}%s" % (xmlns, self.element_name), nsmap=nsmap)
    for key in self.attributes:
      val = getattr(self, key, None)
      if val is not None:
        elt.set(key, str(val))
    for key in self.booleans:
      if getattr(self, key, False):
        elt.set(key, "yes")
    return elt

  def make_b64elt(self, elt, name, value=None):
    """Constructor for Base64-encoded subelement."""
    if value is None:
      value = getattr(self, name, None)
    if value is not None:
      lxml.etree.SubElement(elt, "{%s}%s" % (xmlns, name), nsmap=nsmap).text = base64.b64encode(value)

  def __str__(self):
    lxml.etree.tostring(self.toXML(), pretty_print=True, encoding="us-ascii")

class data_elt(base_elt, rpki.sql.sql_persistant):
  """Virtual class for top-level  left-right protocol data elements."""

  def sql_decode(self, vals):
    rpki.sql.sql_persistant.sql_decode(self, vals)
    if "peer_ta" in vals:
      self.peer_ta = rpki.x509.X509(DER=vals["peer_ta"])

  def sql_encode(self):
    d = rpki.sql.sql_persistant.sql_encode(self)
    if "peer_id" in d:
      d["peer_ta"] = self.peer_ta.get_DER()
    return d

  def make_reply(self, r_pdu=None):
    if r_pdu is None:
      r_pdu = self.__class__()
      r_pdu.self_id = self.self_id
      setattr(r_pdu, self.sql_template.index, getattr(self, self.sql_template.index))
    r_pdu.action = self.action
    r_pdu.type = "reply"
    return r_pdu

  def serve_create(self, db, cur, r_msg):
    r_pdu = self.make_reply()
    self.sql_store(db, cur)
    setattr(r_pdu, self.sql_template.index, getattr(self, self.sql_template.index))
    r_msg.append(r_pdu)

  def serve_copy_hook(self, db_pdu):
    pass

  def serve_set(self, db, cur, r_msg):
    db_pdu = self.sql_fetch(db, cur, getattr(self, self.sql_template.index))
    if db_pdu is not None:
      for a in db_pdu.sql_template.columns[1:]:
        v = getattr(self, a)
        if v is not None:
          setattr(db_pdu, a, v)
      db_pdu.sql_dirty = True
      self.serve_copy_hook(db_pdu)
      db_pdu.sql_store(db, cur)
      r_pdu = self.make_reply()
      r_msg.append(r_pdu)
    else:
      r_msg.append(make_error_report(self))

  def serve_get(self, db, cur, r_msg):
    r_pdu = self.sql_fetch(db, cur, getattr(self, self.sql_template.index))
    if r_pdu is not None:
      self.make_reply(r_pdu)
      r_msg.append(r_pdu)
    else:
      r_msg.append(make_error_report(self))

  def serve_list(self, db, cur, r_msg):
    for r_pdu in self.sql_fetch_all(db, cur):
      self.make_reply(r_pdu)
      r_msg.append(r_pdu)

  def serve_destroy(self, db, cur, r_msg):
    db_pdu = self.sql_fetch(db, cur, getattr(self, self.sql_template.index))
    if db_pdu is not None:
      db_pdu.sql_delete(db, cur)
      r_msg.append(self.make_reply())
    else:
      r_msg.append(make_error_report(self))

  def serve_dispatch(self, db, cur, r_msg):
    assert self.type == "query"
    { "create"  : self.serve_create,
      "set"     : self.serve_set,
      "get"     : self.serve_get,
      "list"    : self.serve_list,
      "destroy" : self.serve_destroy }[self.action](db, cur, r_msg)
  
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

class bsc_elt(data_elt):
  """<bsc/> (Business Signing Context) element."""
  
  element_name = "bsc"
  attributes = ("action", "type", "self_id", "bsc_id", "key_type", "hash_alg", "key_length")
  booleans = ("generate_keypair",)

  sql_template = rpki.sql.template("bsc", "bsc_id", "self_id", "public_key", "private_key_id")

  pkcs10_cert_request = None
  public_key = None
  private_key_id = None

  def __init__(self):
    self.signing_cert = []

  def sql_fetch_hook(self, db, cur):
    cur.execute("SELECT cert FROM bsc_cert WHERE bsc_id = %s", self.bsc_id)
    self.signing_cert = [rpki.x509.X509(DER=x) for (x,) in cur.fetchall()]

  def sql_insert_hook(self, db, cur):
    if self.signing_cert:
      cur.executemany("INSERT bsc_cert (cert, bsc_id) VALUES (%s, %s)", ((x.get_DER(), self.bsc_id) for x in self.signing_cert))

  def sql_delete_hook(self, db, cur):
    cur.execute("DELETE FROM bsc_cert WHERE bsc_id = %s", self.bsc_id)

  def serve_copy_hook(self, db_pdu):
    if self.signing_cert is not None:
      #
      # If we had a flag telling us to reset the signing_cert list, we'd
      # check for it here.  For the moment, assume we always concatenate
      # and never overwrite.
      #
      if False:
        db_pdu.signing_cert = self.signing_cert
      else:
        db_pdu.signing_cert = db_pdu.signing_cert + self.signing_cert

  def startElement(self, stack, name, attrs):
    """Handle <bsc/> element."""
    if not name in ("signing_cert", "public_key", "pkcs10_cert_request"):
      assert name == "bsc", "Unexpected name %s, stack %s" % (name, stack)
      self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    """Handle <bsc/> element."""
    if name == "signing_cert":
      self.signing_cert.append(rpki.x509.X509(Base64=text))
    elif name == "public_key":
      self.public_key = base64.b64decode(text)
    elif name == "pkcs10_cert_request":
      self.pkcs10_cert_request = rpki.x509.PKCS10_Request(Base64=text)
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
    self.make_b64elt(elt, "public_key")
    return elt

class parent_elt(data_elt):
  """<parent/> element."""

  element_name = "parent"
  attributes = ("action", "type", "self_id", "parent_id", "bsc_id", "repository_id", "peer_contact_uri", "sia_base")
  booleans = ("rekey", "reissue", "revoke")

  sql_template = rpki.sql.template("parent", "parent_id", "self_id", "bsc_id", "repository_id", "peer_ta", "peer_contact_uri", "sia_base")

  peer_ta = None

  def startElement(self, stack, name, attrs):
    """Handle <bsc/> element."""
    if name != "peer_ta":
      assert name == "parent", "Unexpected name %s, stack %s" % (name, stack)
      self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    """Handle <bsc/> element."""
    if name == "peer_ta":
      self.peer_ta = rpki.x509.X509(Base64=text)
    else:
      assert name == "parent", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def toXML(self):
    """Generate <bsc/> element."""
    elt = self.make_elt()
    if self.peer_ta and not self.peer_ta.empty():
      self.make_b64elt(elt, "peer_ta", self.peer_ta.get_DER())
    return elt

class child_elt(data_elt):
  """<child/> element."""

  element_name = "child"
  attributes = ("action", "type", "self_id", "child_id", "bsc_id")
  booleans = ("reissue", )

  sql_template = rpki.sql.template("child", "child_id", "self_id", "bsc_id", "peer_ta")

  def sql_fetch_hook(self, db, cur):
    self.cas = rpki.sql.get_column(db, cur, "SELECT ca_id FROM child_ca_link WHERE child_id = %s", self.child_id)
    cur.execute("SELECT ca_detail_id, cert FROM child_ca_certificate WHERE child_id = %s", self.child_id)
    self.certs = dict((ca_detail_id, rpki.x509.X509(DER=cert)) for (ca_detail_id, cert) in cur.fetchall())

  def sql_insert_hook(self, db, cur):
    if self.cas:
      cur.executemany("INSERT child_ca_link (ca_id, child_id) VALUES (%s, %s)",
                      ((x.ca_id, self.child_id) for x in self.cas))
    if self.certs:
      cur.executemany("INSERT child_ca_certificate (child_id, ca_detail_id, cert) VALUES (%s, %s, %s)",
                      ((self.child_id, ca_detail_id, cert.get_DER()) for (ca_detail_id, cert) in self.certs))
  
  def sql_delete_hook(self, db, cur):
    cur.execute("DELETE FROM child_ca_link where child_id = %s", self.child_id)
    cur.execute("DELETE FROM child_ca_certificate where child_id = %s", self.child_id)
    
  peer_ta = None

  def startElement(self, stack, name, attrs):
    """Handle <child/> element."""
    if name != "peer_ta":
      assert name == "child", "Unexpected name %s, stack %s" % (name, stack)
      self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    """Handle <child/> element."""
    if name == "peer_ta":
      self.peer_ta = rpki.x509.X509(Base64=text)
    else:
      assert name == "child", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def toXML(self):
    """Generate <child/> element."""
    elt = self.make_elt()
    if self.peer_ta:
      self.make_b64elt(elt, "peer_ta", self.peer_ta.get_DER())
    return elt

class repository_elt(data_elt):
  """<repository/> element."""

  element_name = "repository"
  attributes = ("action", "type", "self_id", "repository_id", "bsc_id", "peer_contact_uri")

  sql_template = rpki.sql.template("repository", "repository_id", "self_id", "bsc_id", "peer_ta", "peer_contact_uri")

  peer_ta = None

  def startElement(self, stack, name, attrs):
    """Handle <repository/> element."""
    if name != "peer_ta":
      assert name == "repository", "Unexpected name %s, stack %s" % (name, stack)
      self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    """Handle <repository/> element."""
    if name == "peer_ta":
      self.peer_ta = rpki.x509.X509(Base64=text)
    else:
      assert name == "repository", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def toXML(self):
    """Generate <repository/> element."""
    elt = self.make_elt()
    if self.peer_ta:
      self.make_b64elt(elt, "peer_ta", self.peer_ta.get_DER())
    return elt

class route_origin_elt(data_elt):
  """<route_origin/> element."""

  element_name = "route_origin"
  attributes = ("action", "type", "self_id", "route_origin_id", "as_number", "ipv4", "ipv6")
  booleans = ("suppress_publication",)

  sql_template = rpki.sql.template("route_origin", "route_origin_id", "self_id", "as_number")

  ca_detail_id = None
  roa = None

  def sql_fetch_hook(self, db, cur):
    self.ipv4 = rpki.resource_set.resource_set_ipv4()
    self.ipv4.from_sql(cur, "SELECT start_ip, end_ip FROM route_origin_range WHERE route_origin_id = %s AND start_ip NOT LIKE '%:%'", self.route_origin_id)
    self.ipv6 = rpki.resource_set.resource_set_ipv6()
    self.ipv4.from_sql(cur, "SELECT start_ip, end_ip FROM route_origin_range WHERE route_origin_id = %s AND start_ip LIKE '%:%'", self.route_origin_id)
    cur.execute("SELECT roa, ca_detail_id FROM roa WHERE route_origin_id = %s", self.route_origin_id)
    roas = cur.fetchall()
    if len(roas) == 1:
      roa = roas[0][0]
      ca_detail_id = roas[0][1]
    elif len(roas) > 0:
      raise RunTimeError, "Multiple ROAs found, mapping should be one-to-one"
    
  def sql_insert_hook(self, db, cur):
    if self.ipv4 + self.ipv6:
      cur.executemany("INSERT route_origin_range (route_origin_id, start_ip, end_ip) VALUES (%s, %s, %s)",
                      ((self.route_origin_id, x.min, x.max) for x in self.ipv4 + self.ipv6))
    if self.roa:
      cur.execute("INSERT roa (route_origin_id, roa, ca_detail_id) VALUES (%s, %s, %s)",
                  self.route_origin_id, self.roa, self.ca_detail_id)
  
  def sql_delete_hook(self, db, cur):
    cur.execute("DELETE FROM route_origin_range WHERE route_origin_id = %s", self.route_origin_id)
    cur.execute("DELETE FROM roa WHERE route_origin_id = %s", self.route_origin_id)

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

class self_elt(data_elt):
  """<self/> element."""

  element_name = "self"
  attributes = ("action", "type", "self_id")
  booleans = ("rekey", "reissue", "revoke", "run_now", "publish_world_now")

  sql_template = rpki.sql.template("self", "self_id", "use_hsm")

  self_id = None
  use_hsm = False

  def __init__(self):
    self.prefs = []

  def sql_fetch_hook(self, db, cur):
    cur.execute("SELECT pref_name, pref_value FROM self_pref WHERE self_id = %s", self.self_id)
    for name, value in cur.fetchall():
      e = extension_preference_elt()
      e.name = name
      e.value = value
      self.prefs.append(e)

  def sql_insert_hook(self, db, cur):
    if self.prefs:
      cur.executemany("INSERT self_pref (self_id, pref_name, pref_value) VALUES (%s, %s, %s)",
                      ((e.name, e.value, self.self_id) for e in self.prefs))
  
  def sql_delete_hook(self, db, cur):
    cur.execute("DELETE FROM self_pref WHERE self_id = %s", self.self_id)

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

class resource_class_elt(base_elt):
  """<resource_class/> element."""

  element_name = "resource_class"
  attributes = ("as", "req_as", "ipv4", "req_ipv4", "ipv6", "req_ipv6", "subject_name")

  def startElement(self, stack, name, attrs):
    """Handle <resource_class/> element."""
    assert name == "resource_class", "Unexpected name %s, stack %s" % (name, stack)
    self.read_attrs(attrs)
    if self.as is not None:
      self.as = rpki.resource_set.resource_set_as(self.as)
    if self.req_as is not None:
      self.req_as = rpki.resource_set.resource_set_as(self.req_as)
    if self.ipv4 is not None:
      self.ipv4 = rpki.resource_set.resource_set_ipv4(self.ipv4)
    if self.req_ipv4 is not None:
      self.req_ipv4 = rpki.resource_set.resource_set_ipv4(self.req_ipv4)
    if self.ipv6 is not None:
      self.ipv6 = rpki.resource_set.resource_set_ipv6(self.ipv6)
    if self.req_ipv6 is not None:
      self.req_ipv6 = rpki.resource_set.resource_set_ipv6(self.req_ipv6)

  def endElement(self, stack, name, text):
    """Handle <resource_class/> element."""
    assert name == "resource_class", "Unexpected name %s, stack %s" % (name, stack)
    stack.pop()

  def toXML(self):
    """Generate <resource_class/> element."""
    return self.make_elt()

class list_resources_elt(base_elt):
  """<list_resources/> element."""

  element_name = "list_resources"
  attributes = ("type", "self_id", "child_id", "valid_until")

  def __init__(self):
    self.resources = []

  def startElement(self, stack, name, attrs):
    """Handle <list_resources/> element."""
    if name == "resource_class":
      rc = resource_class_elt()
      self.resources.append(rc)
      stack.append(rc)
      rc.startElement(stack, name, attrs)
    else:
      assert name == "list_resources", "Unexpected name %s, stack %s" % (name, stack)
      self.read_attrs(attrs)

  def toXML(self):
    """Generate <list_resources/> element."""
    elt = self.make_elt()
    elt.extend([i.toXML() for i in self.resources])
    return elt

class report_error_elt(base_elt):
  """<report_error/> element."""

  element_name = "report_error"
  attributes = ("self_id", "error_code")

  def startElement(self, stack, name, attrs):
    """Handle <report_error/> element."""
    assert name == self.element_name, "Unexpected name %s, stack %s" % (name, stack)
    self.read_attrs(attrs)

  def toXML(self):
    """Generate <report_error/> element."""
    return self.make_elt()

## Dispatch table of PDUs for this protocol.
pdus = dict((x.element_name, x)
            for x in (self_elt, child_elt, parent_elt, bsc_elt, repository_elt,
                       route_origin_elt, list_resources_elt, report_error_elt))

class msg(list):
  """Left-right PDU."""

  version = 1

  def startElement(self, stack, name, attrs):
    """Handle left-right PDU."""
    if name == "msg":
      assert self.version == int(attrs["version"])
    else:
      elt = pdus[name]()
      self.append(elt)
      stack.append(elt)
      elt.startElement(stack, name, attrs)

  def endElement(self, stack, name, text):
    """Handle left-right PDU."""
    assert name == "msg", "Unexpected name %s, stack %s" % (name, stack)
    assert len(stack) == 1
    stack.pop()

  def __str__(self):
    lxml.etree.tostring(self.toXML(), pretty_print=True, encoding="us-ascii")

  def toXML(self):
    """Generate left-right PDU."""
    elt = lxml.etree.Element("{%s}msg" % (xmlns), nsmap=nsmap, version=str(self.version))
    elt.extend([i.toXML() for i in self])
    return elt

class sax_handler(rpki.sax_utils.handler):
  """SAX handler for Left-Right protocol."""

  def create_top_level(self, name, attrs):
    """Top-level PDU for this protocol is <msg/>."""
    assert name == "msg" and attrs["version"] == "1"
    return msg()
