# $Id$

"""RPKI "up-down" protocol."""

import base64, lxml.etree, time
import rpki.sax_utils, rpki.resource_set, rpki.x509, rpki.exceptions

xmlns="http://www.apnic.net/specs/rescerts/up-down/"

nsmap = { None : xmlns }

class base_elt(object):
  """Generic PDU object.

  Virtual class, just provides some default methods.
  """

  def startElement(self, stack, name, attrs):
    """Ignore startElement() if there's no specific handler.

    Some elements have no attributes and we only care about their
    text content.
    """
    pass

  def endElement(self, stack, name, text):
    """Ignore endElement() if there's no specific handler.

    If we don't need to do anything else, just pop the stack.
    """
    stack.pop()

  def make_elt(self, name, *attrs):
    """Construct a element, copying over a set of attributes."""
    elt = lxml.etree.Element("{%s}%s" % (xmlns, name), nsmap=nsmap)
    for key in attrs:
      val = getattr(self, key, None)
      if val is not None:
        elt.set(key, str(val))
    return elt

  def make_b64elt(self, elt, name, value=None):
    """Construct a sub-element with Base64 text content."""
    if value is None:
      value = getattr(self, name, None)
    if value is not None:
      lxml.etree.SubElement(elt, "{%s}%s" % (xmlns, name), nsmap=nsmap).text = base64.b64encode(value)

  def serve_pdu(self, gctx, q_msg, r_msg, child):
    """Default PDU handler to catch unexpected types."""
    raise rpki.exceptions.BadQuery, "Unexpected query type %s" % q_msg.type

  def check_response(self):
    """Placeholder for response checking."""
    pass

class multi_uri(list):
  """Container for a set of URIs."""

  def __init__(self, ini):
    """Initialize a set of URIs, which includes basic some syntax checking."""
    if isinstance(ini, (list, tuple)):
      self[:] = ini
    elif isinstance(ini, str):
      self[:] = ini.split(",")
      for s in self:
        if s.strip() != s or s.find("://") < 0:
          raise rpki.exceptions.BadURISyntax, "Bad URI \"%s\"" % s
    else:
      raise TypeError

  def __str__(self):
    """Convert a multi_uri back to a string representation."""
    return ",".join(self)

  def rsync(self):
    """Find first rsync://... URI in self."""
    for s in self:
      if s.startswith("rsync://"):
        return s
    return None

class certificate_elt(base_elt):
  """Up-Down protocol representation of an issued certificate."""

  def startElement(self, stack, name, attrs):
    """Handle attributes of <certificate/> element."""
    assert name == "certificate", "Unexpected name %s, stack %s" % (name, stack)
    self.cert_url = multi_uri(attrs["cert_url"])
    self.req_resource_set_as   = rpki.resource_set.resource_set_as(attrs.get("req_resource_set_as"))
    self.req_resource_set_ipv4 = rpki.resource_set.resource_set_ipv4(attrs.get("req_resource_set_ipv4"))
    self.req_resource_set_ipv6 = rpki.resource_set.resource_set_ipv6(attrs.get("req_resource_set_ipv6"))

  def endElement(self, stack, name, text):
    """Handle text content of a <certificate/> element."""
    assert name == "certificate", "Unexpected name %s, stack %s" % (name, stack)
    self.cert = rpki.x509.X509(Base64=text)
    stack.pop()

  def toXML(self):
    """Generate a <certificate/> element."""
    elt = self.make_elt("certificate", "cert_url",
                        "req_resource_set_as", "req_resource_set_ipv4", "req_resource_set_ipv6")
    elt.text = self.cert.get_Base64()
    return elt

class class_elt(base_elt):
  """Up-Down protocol representation of a resource class."""

  issuer = None

  def __init__(self):
    """Initialize class_elt."""
    self.certs = []

  def startElement(self, stack, name, attrs):
    """Handle <class/> elements and their children."""
    if name == "certificate":
      cert = certificate_elt()
      self.certs.append(cert)
      stack.append(cert)
      cert.startElement(stack, name, attrs)
    elif name != "issuer":
      assert name == "class", "Unexpected name %s, stack %s" % (name, stack)
      self.class_name = attrs["class_name"]
      self.cert_url = multi_uri(attrs["cert_url"])
      self.suggested_sia_head = attrs.get("suggested_sia_head")
      self.resource_set_as   = rpki.resource_set.resource_set_as(attrs["resource_set_as"])
      self.resource_set_ipv4 = rpki.resource_set.resource_set_ipv4(attrs["resource_set_ipv4"])
      self.resource_set_ipv6 = rpki.resource_set.resource_set_ipv6(attrs["resource_set_ipv6"])

  def endElement(self, stack, name, text):
    """Handle <class/> elements and their children."""
    if name == "issuer":
      self.issuer = rpki.x509.X509(Base64=text)
    else:
      assert name == "class", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def toXML(self):
    """Generate a <class/> element."""
    elt = self.make_elt("class", "class_name", "cert_url",
                        "resource_set_as", "resource_set_ipv4", "resource_set_ipv6", "suggested_sia_head")
    elt.extend([i.toXML() for i in self.certs])
    if self.issuer is not None:
      self.make_b64elt(elt, "issuer", self.issuer.get_DER())
    return elt

  def to_resource_bag(self):
    """Build a resource_bag from from this <class/> element."""
    return rpki.resource_set.resource_bag(self.resource_set_as,
                                          self.resource_set_ipv4,
                                          self.resource_set_ipv6)

  def from_resource_bag(self, bag):
    """Set resources of this class element from a resource_bag."""
    self.resource_set_as   = bag.as
    self.resource_set_ipv4 = bag.v4
    self.resource_set_ipv6 = bag.v6

class list_pdu(base_elt):
  """Up-Down protocol "list" PDU."""

  def toXML(self):
    """Generate (empty) payload of "list" PDU."""
    return []

  def serve_pdu(self, gctx, q_msg, r_msg, child):
    """Serve one "list" PDU."""
    r_msg.payload = list_response_pdu()

    # This will require a callback when we go event-driven
    irdb_resources = rpki.left_right.irdb_query(gctx, child.self_id, child.child_id)

    for parent in child.parents(gctx):
      for ca in parent.cas(gctx):
        ca_detail = ca.fetch_active(gctx)
        if not ca_detail:
          continue
        resources = ca_detail.latest_ca_cert.get_3779resources().intersection(irdb_resources)
        if resources.empty():
          continue
        rc = class_elt()
        rc.class_name = str(ca.ca_id)
        rc.cert_url = multi_uri(ca_detail.ca_cert_uri)
        rc.from_resource_bag(resources)
        for child_cert in rpki.sql.child_cert_obj.sql_fetch_where(gctx, """
                  child_id = %s AND ca_detail_id = %s
                  """ % (child.child_id, ca_detail.ca_detail_id)):
          c = certificate_elt()
          c.cert_url = multi_uri(child_cert.uri(ca))
          c.cert = child_cert.cert
          rc.certs.append(c)
        rc.issuer = ca_detail.latest_ca_cert
        r_msg.payload.classes.append(rc)

  @classmethod
  def query(cls, gctx, parent):
    """Send a "list" query to parent."""
    return parent.query_up_down(gctx, cls())

class class_response_syntax(base_elt):
  """Syntax for Up-Down protocol "list_response" and "issue_response" PDUs."""

  def __init__(self):
    """Initialize class_response_syntax."""
    self.classes = []

  def startElement(self, stack, name, attrs):
    """Handle "list_response" and "issue_response" PDUs."""
    assert name == "class", "Unexpected name %s, stack %s" % (name, stack)
    c = class_elt()
    self.classes.append(c)
    stack.append(c)
    c.startElement(stack, name, attrs)
      
  def toXML(self):
    """Generate payload of "list_response" and "issue_response" PDUs."""
    return [c.toXML() for c in self.classes]

class list_response_pdu(class_response_syntax):
    """Up-Down protocol "list_response" PDU."""

    pass

class issue_pdu(base_elt):
  """Up-Down protocol "issue" PDU."""

  def startElement(self, stack, name, attrs):
    """Handle "issue" PDU."""
    assert name == "request", "Unexpected name %s, stack %s" % (name, stack)
    self.class_name = attrs["class_name"]
    self.req_resource_set_as   = rpki.resource_set.resource_set_as(attrs.get("req_resource_set_as"))
    self.req_resource_set_ipv4 = rpki.resource_set.resource_set_ipv4(attrs.get("req_resource_set_ipv4"))
    self.req_resource_set_ipv6 = rpki.resource_set.resource_set_ipv6(attrs.get("req_resource_set_ipv6"))

  def endElement(self, stack, name, text):
    """Handle "issue" PDU."""
    assert name == "request", "Unexpected name %s, stack %s" % (name, stack)
    self.pkcs10 = rpki.x509.PKCS10(Base64=text)
    stack.pop()

  def toXML(self):
    """Generate payload of "issue" PDU."""
    elt = self.make_elt("request", "class_name", "req_resource_set_as",
                        "req_resource_set_ipv4", "req_resource_set_ipv6")
    elt.text = self.pkcs10.get_Base64()
    return [elt]

  def serve_pdu(self, gctx, q_msg, r_msg, child):
    """Serve one issue request PDU."""

    # Check the request
    if not self.class_name.isdigit():
      raise rpki.exceptions.BadClassNameSyntax, "Bad class name %s" % self.class_name
    ca = rpki.sql.ca_obj.sql_fetch(gctx, long(self.class_name))
    ca_detail = ca.fetch_active(gctx)
    if ca is None or ca_detail is None:
      raise rpki.exceptions.NotInDatabase
    self.pkcs10.check_valid_rpki()

    # Check current cert, if any

    # This will require a callback when we go event-driven
    irdb_resources = rpki.left_right.irdb_query(gctx, child.self_id, child.child_id)

    resources = irdb_resources.intersection(ca_detail.latest_ca_cert.get_3779resources())
    req_key = self.pkcs10.getPublicKey()
    req_sia = self.pkcs10.get_SIA()
    child_cert = rpki.sql.child_cert_obj.sql_fetch_where1(gctx, """
                child_id = %s AND ca_detail_id = %s AND ski = "%s"
                """ % (child.child_id, ca_detail.ca_detail_id, req_key.get_SKI()))

    # Generate new cert or regenerate old one if necessary

    if child_cert is None:
      child_cert = ca_detail.issue(
        gctx        = gctx,
        ca          = ca,
        child       = child,
        subject_key = req_key,
        sia         = req_sia,
        resources   = resources)
    else:
      child_cert = child_cert.reissue(
        gctx      = gctx,
        ca_detail = ca_detail,
        sia       = req_sia,
        resources = resources)

    # Save anything we modified and generate response
    rpki.sql.sql_sweep(gctx)
    assert child_cert and child_cert.sql_in_db
    c = certificate_elt()
    c.cert_url = multi_uri(child_cert.uri(ca))
    c.cert = child_cert.cert
    rc = class_elt()
    rc.class_name = self.class_name
    rc.cert_url = multi_uri(ca_detail.ca_cert_uri)
    rc.from_resource_bag(resources)
    rc.certs.append(c)
    rc.issuer = ca_detail.latest_ca_cert
    r_msg.payload = issue_response_pdu()
    r_msg.payload.classes.append(rc)

  @classmethod
  def query(cls, gctx, parent, ca, ca_detail):
    """Send an "issue" request to parent associated with ca."""
    assert ca_detail is not None and ca_detail.state not in ("deprecated", "revoked")
    sia = ((rpki.oids.name2oid["id-ad-caRepository"], ("uri", ca.sia_uri)),
           (rpki.oids.name2oid["id-ad-rpkiManifest"], ("uri", ca_detail.manifest_uri(ca))))
    self = cls()
    self.class_name = ca.parent_resource_class
    self.pkcs10 = rpki.x509.PKCS10.create_ca(ca_detail.private_key_id, sia)
    return parent.query_up_down(gctx, self)

class issue_response_pdu(class_response_syntax):
  """Up-Down protocol "issue_response" PDU."""

  def check_response(self):
    """Check whether this looks like a reasonable issue_response PDU.
    XML schema should be tighter for this response.
    """
    if len(self.classes) != 1 or len(self.classes[0].certs) != 1:
      raise rpki.exceptions.BadIssueResponse

class revoke_syntax(base_elt):
  """Syntax for Up-Down protocol "revoke" and "revoke_response" PDUs."""

  def startElement(self, stack, name, attrs):
    """Handle "revoke" PDU."""
    self.class_name = attrs["class_name"]
    self.ski = attrs["ski"]

  def toXML(self):
    """Generate payload of "revoke" PDU."""
    return [self.make_elt("key", "class_name", "ski")]

class revoke_pdu(revoke_syntax):
  """Up-Down protocol "revoke" PDU."""
    
  def get_SKI(self):
    """Convert g(SKI) encoding from PDU back to raw SKI."""
    return base64.b64decode(self.ski.replace("_", "/").replace("-", "+"))

  def serve_pdu(self, gctx, q_msg, r_msg, child):
    """Serve one revoke request PDU."""
    if not self.class_name.isdigit():
      raise rpki.exceptions.BadClassNameSyntax, "Bad class name %s" % self.class_name
    ca_id = long(self.class_name)
    ski = self.get_SKI()
    for ca_detail in rpki.sql.ca_detail_obj.sql_fetch_where(gctx, "ca_id = %s AND state != 'revoked'" % ca_id):
      for child_cert in rpki.sql.child_cert_obj.sql_fetch_where(gctx, """
                child_id = %s AND ca_detail_id = %s AND ski = '%s'
                """ % (child.child_id, ca_detail.ca_detail_id, ski)):
        child_cert.revoke()
    rpki.sql.sql_sweep(gctx)
    r_msg.payload = revoke_response_pdu()
    r_msg.payload.class_name = self.class_name
    r_msg.payload.ski = self.ski

  @classmethod
  def query(cls, gctx, ca_detail):
    """Send a "revoke" request to parent associated with ca_detail."""
    ca = ca_detail.ca(gctx)
    parent = ca.parent(gctx)
    self = cls()
    self.class_name = ca.parent_resource_class
    self.ski = ca_detail.latest_ca_cert.gSKI()
    return parent.query_up_down(gctx, self)

class revoke_response_pdu(revoke_syntax):
  """Up-Down protocol "revoke_response" PDU."""

  pass

class error_response_pdu(base_elt):
  """Up-Down protocol "error_response" PDU."""

  codes = {
    1101 : "Already processing request",
    1102 : "Version number error",
    1103 : "Unrecognised request type",
    1201 : "Request - no such resource class",
    1202 : "Request - no resources allocated in resource class",
    1203 : "Request - badly formed certificate request",
    1301 : "Revoke - no such resource class",
    1302 : "Revoke - no such key",
    2001 : "Internal Server Error - Request not performed" }

  exceptions = {}

  def __init__(self, exception = None):
    """Initialize an error_response PDU from an exception object."""
    if exception is not None:
      if exception in self.exceptions:
        self.status = exceptions[exception]
      else:
        self.status = 2001
      self.description = str(exception)

  def endElement(self, stack, name, text):
    """Handle "error_response" PDU."""
    if name == "status":
      code = int(text)
      if code not in self.codes:
        raise rpki.exceptions.BadStatusCode, "%s is not a known status code"
      self.status = code
    elif name == "description":
      self.description = text
    else:
      assert name == "message", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()
      stack[-1].endElement(stack, name, text)

  def toXML(self):
    """Generate payload of "error_response" PDU."""
    assert self.status in self.codes
    elt = self.make_elt("status")
    elt.text = str(self.status)
    payload = [elt]
    if self.description:
      elt = self.make_elt("description")
      elt.text = str(self.description)
      elt.set("xml:lang", "en-US")
      payload.append(elt)
    return payload

  def check_response(self):
    """Handle an error response.  For now, just raise an exception,
    perhaps figure out something more clever to do later.
    """
    raise rpki.exceptions.UpstreamError, self.codes[self.status]

class message_pdu(base_elt):
  """Up-Down protocol message wrapper PDU."""

  version = 1

  name2type = {
    "list"            : list_pdu,
    "list_response"   : list_response_pdu,
    "issue"           : issue_pdu,
    "issue_response"  : issue_response_pdu,
    "revoke"          : revoke_pdu,
    "revoke_response" : revoke_response_pdu,
    "error_response"  : error_response_pdu }

  type2name = dict((v,k) for k,v in name2type.items())

  def toXML(self):
    """Generate payload of message PDU."""
    elt = self.make_elt("message", "version", "sender", "recipient", "type")
    elt.extend(self.payload.toXML())
    return elt

  def startElement(self, stack, name, attrs):
    """Handle message PDU.

    Payload of the <message/> element varies depending on the "type"
    attribute, so after some basic checks we have to instantiate the
    right class object to handle whatever kind of PDU this is.
    """
    assert name == "message", "Unexpected name %s, stack %s" % (name, stack)
    assert self.version == int(attrs["version"])
    self.sender = attrs["sender"]
    self.recipient = attrs["recipient"]
    self.type = attrs["type"]
    self.payload = self.name2type[attrs["type"]]()
    stack.append(self.payload)

  def __str__(self):
    """Convert a message PDU to a string."""
    lxml.etree.tostring(self.toXML(), pretty_print = True, encoding = "UTF-8")

  def serve_top_level(self, gctx, child):
    """Serve one message request PDU."""
    r_msg = message_pdu()
    r_msg.sender = self.recipient
    r_msg.recipient = self.sender
    self.payload.serve_pdu(gctx, self, r_msg, child)
    r_msg.type = self.type2name[type(r_msg.payload)]
    return r_msg

  def serve_error(self, exception):
    """Generate an error_response message PDU."""
    r_msg = message_pdu()
    r_msg.sender = self.recipient
    r_msg.recipient = self.sender
    r_msg.payload = error_response_pdu(exception)
    r_msg.type = self.type2name[type(r_msg.payload)]
    return r_msg

  @classmethod
  def make_query(cls, payload, sender = "tweedledee", recipient = "tweedledum"):
    """Construct one message PDU."""
    assert not cls.type2name[type(payload)].endswith("_response")
    self = cls()
    self.sender = sender
    self.recipient = recipient
    self.payload = payload
    self.type = self.type2name[type(payload)]
    return self

class sax_handler(rpki.sax_utils.handler):
  """SAX handler for Up-Down protocol."""

  def create_top_level(self, name, attrs):
    """Top-level PDU for this protocol is <message/>."""
    return message_pdu()
