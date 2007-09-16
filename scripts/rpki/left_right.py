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
      setattr(self, key, attrs.get(key, None))
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
  """Virtual type for a left-right protocol message elements representing
  top-level persistant data elements.
  """

  pass

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

  sql_template = rpki.sql.template("bsc", "bsc_id", "self_id", "pub_key", "priv_key_id")

  pkcs10_cert_request = None
  public_key = None
  private_key_id = None

  def __init__(self):
    self.signing_cert = []

  def sql_decode(self, vals):
    self.self_id = vals["self_id"]
    self.public_key = vals["pub_key"]
    self.private_key_id = vals["priv_key_id"]

  def sql_encode(self):
    return { "self_id"     : self.self_id,
             "pub_key"     : self.public_key,
             "priv_key_id" : self.private_key_id }

  def sql_fetch_hook(self, db, cur):
    cur.execute("SELECT cert FROM bsc_cert WHERE bsc_id = %s", self.bsc_id)
    self.signing_cert = [rpki.x509.X509(DER=x) for (x,) in cur.fetchall()]

  def sql_insert_hook(self, db, cur):
    if self.signing_cert:
      cur.executemany("INSERT bsc_cert (cert, bsc_id) VALUES (%s, %s)", ((x.get_DER(), self.bsc_id) for x in self.signing_cert))

  def sql_delete_hook(self, db, cur):
    cur.execute("DELETE FROM bsc_cert WHERE bsc_id = %s", self.bsc_id)

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
  attributes = ("action", "type", "self_id", "parent_id", "bsc_id", "repository_id", "peer_contact", "sia_base")
  booleans = ("rekey", "reissue", "revoke")

  sql_template = rpki.sql.template("parent", "parent_id", "self_id", "bsc_id", "repos_id", "ta", "uri", "sia_base")

  def sql_decode(self, vals):
    self.self_id       = vals["self_id"]
    self.bsc_id        = vals["bsc_id"]
    self.repository_id = vals["repos_id"]
    self.parent_id     = vals["parent_id"]
    self.peer_contact  = vals["uri"]
    self.peer_ta       = rpki.x509.X509(DER=vals["ta"])

  def sql_encode(self):
    return { "self_id"   : self.self_id,
             "bsc_id"    : self.bsc_id,
             "repos_id"  : self.repository_id,
             "parent_id" : self.parent_id,
             "uri"       : self.peer_contact,
             "ta"        : self.peer_ta.get_DER(),
             "sia_head"  : self.sia_head }

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
    if self.peer_ta:
      self.make_b64elt(elt, "peer_ta", self.peer_ta.get_DER())
    return elt

class child_elt(data_elt):
  """<child/> element."""

  element_name = "child"
  attributes = ("action", "type", "self_id", "child_id", "bsc_id", "child_db_id")
  booleans = ("reissue", )

  sql_template = rpki.sql.template("child", "child_id", "self_id", "bsc_id", "ta")

  def sql_decode(self, vals):
    self.self_id = vals["self_id"]
    self.bsc_id = vals["bsc_id"]
    self.child_id = vals["child_id"]
    self.peer_ta = rpki.x509.X509(DER=vals["ta"])

  def sql_encode(self):
    return { "self_id"  : self.self_id,
             "bsc_id"   : self.bsc_id,
             "child_id" : self.child_id,
             "ta"       : self.peer_ta.get_DER() }

  def sql_fetch_hook(self, db, cur):
    self.cas = rpki.sql.get_column(db, cur, "SELECT ca_id FROM child_ca_link WHERE child_id = %s", self.child_id)
    #
    # This next bit is nasty, but I don't know how to do better with the current SQL structure.
    # This is a normalization problem, I think.
    #
    cur.execute("""SELECT ca_detail_id, cert FROM child_ca_certificate WHERE child_id = %s""", self.child_id)
    self.certs = []
    for (ca_detail_id, cert) in cur.fetchall():
      ca_detail = rpki.sql.ca_detail.sql_cache_find(ca_detail_id)
      c = rpki.x509.X509(DER=cert)
      c.child_id = self.child_id
      c.ca_detail_id = ca_detail_id
      self.certs.append(c)
      ca_detail.certs.append(c)

  def sql_insert_hook(self, db, cur):
    if self.cas:
      cur.executemany("INSERT child_ca_link (ca_id, child_id) VALUES (%s, %s)",
                      ((x.ca_id, self.child_id) for x in self.cas))
    if self.certs:
      cur.executemany("INSERT child_ca_certificate (child_id, ca_detail_id, cert) VALUES (%s, %s, %s)",
                      ((self.child_id, c.ca_detail_id, c) for c in self.certs))
  
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
  attributes = ("action", "type", "self_id", "repository_id", "bsc_id", "peer_contact")

  sql_template = rpki.sql.template("repository", "repos_id", "self_id", "bsc_id", "ta", "uri")

  def sql_decode(self, vals):
    self.self_id = vals["self_id"]
    self.bsc_id = vals["bsc_id"]
    self.repository_id = vals["repos_id"]
    self.peer_contact = vals["uri"]
    self.peer_ta = rpki.x509.X509(DER=vals["ta"])

  def sql_encode(self):
    return { "self_id"  : self.self_id,
             "bsc_id"   : self.bsc_id,
             "repos_id" : self.repository_id,
             "uri"      : self.peer_contact,
             "ta"       : self.peer_ta.get_DER() }

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
  attributes = ("action", "type", "self_id", "route_origin_id", "asn", "ipv4", "ipv6")
  booleans = ("suppress_publication",)

  sql_template = rpki.sql.template("route_origin", "route_origin_id", "self_id", "as_number")

  def sql_decode(self, vals):
    self.self_id = vals["self_id"]
    self.asn = vals["as_number"]
    self.route_origin = vals["route_origin_id"]

  def sql_encode(self):
    return { "self_id"         : self.self_id,
             "route_origin_id" : self.route_origin_id,
             "as_number"       : self.asn }

  def sql_fetch_hook(self, db, cur):
    self.ipv4 = rpki.resource_set.resource_set_ipv4()
    self.ipv4.from_sql(cur, "SELECT start_ip, end_ip FROM route_origin_prefix WHERE route_origin_id = %s AND start_ip NOT LIKE '%:%'", self.route_origin_id)
    self.ipv6 = rpki.resource_set.resource_set_ipv6()
    self.ipv4.from_sql(cur, "SELECT start_ip, end_ip FROM route_origin_prefix WHERE route_origin_id = %s AND start_ip LIKE '%:%'", self.route_origin_id)

    raise NotImplementedError, "ROA modeling still broken"
    cur.execute("SELECT roa, ca_detail_id FROM roa WHERE route_origin_id = %s", self.route_origin_id)
    self.roas = cur.fetchall()
    
  def sql_insert_hook(self, db, cur):
    if self.ipv4 + self.ipv6:
      cur.executemany("INSERT route_origin_prefix (route_origin_id, start_ip, end_ip) VALUES (%s, %s, %s)",
                      ((self.route_origin_id, x.min, x.max) for x in self.ipv4 + self.ipv6))

    raise NotImplementedError, "ROA modeling still broken"
    if self.roas:
      cur.executemany("INSERT roa (route_origin_id, roa, ca_detail_id) VALUES (%s, %s, %s)",
                      ((self.route_origin_id, x[0], x[1]) for x in self.roas))
  
  def sql_delete_hook(self, db, cur):
    cur.execute("DELETE FROM route_origin_prefix WHERE route_origin_id = %s", self.route_origin_id)
    cur.execute("DELETE FROM roa WHERE route_origin_id = %s", self.route_origin_id)

  def startElement(self, stack, name, attrs):
    """Handle <route_origin/> element."""
    assert name == "route_origin", "Unexpected name %s, stack %s" % (name, stack)
    self.read_attrs(attrs)
    if self.asn is not None:
      self.asn = long(self.asn)
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
