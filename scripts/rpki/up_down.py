# $Id$

"""RPKI "up-down" protocol."""

import base64, rpki.sax_utils, rpki.resource_set, lxml.etree, x509, rpki.exceptions

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
    self.cert = x509.X509(Base64=text)
    stack.pop()

  def toXML(self):
    """Generate a <certificate/> element."""
    elt = self.make_elt("certificate", "cert_url", "req_resource_set_as", "req_resource_set_ipv4", "req_resource_set_ipv6")
    elt.text = self.cert.get_Base64()
    return elt

class class_elt(base_elt):
  """Up-Down protocol representation of a resource class."""

  def __init__(self):
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
      self.issuer = x509.X509(Base64=text)
    else:
      assert name == "class", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def toXML(self):
    """Generate a <class/> element."""
    elt = self.make_elt("class", "class_name", "cert_url", "resource_set_as", "resource_set_ipv4", "resource_set_ipv6", "suggested_sia_head")
    elt.extend([i.toXML() for i in self.certs])
    self.make_b64elt(elt, "issuer", self.issuer.get_DER())
    return elt

class list_pdu(base_elt):
  """Up-Down protocol "list" PDU."""

  def toXML(self):
    """Generate (empty) payload of "list" PDU."""
    return []

class list_response_pdu(base_elt):
  """Up-Down protocol "list_response" PDU."""

  def __init__(self):
    self.classes = []

  def startElement(self, stack, name, attrs):
    """Handle "list_response" PDU."""
    assert name == "class", "Unexpected name %s, stack %s" % (name, stack)
    klass = class_elt()
    self.classes.append(klass)
    stack.append(klass)
    klass.startElement(stack, name, attrs)
      
  def toXML(self):
    """Generate payload of "list_response" PDU."""
    return [i.toXML() for i in self.classes]

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
    self.pkcs10 = x509.PKCS10_Request(Base64=text)
    stack.pop()

  def toXML(self):
    """Generate payload of "issue" PDU."""
    elt = self.make_elt("request", "class_name", "req_resource_set_as", "req_resource_set_ipv4", "req_resource_set_ipv6")
    elt.text = self.pkcs10.get_Base64()
    return [elt]

class issue_response_pdu(list_response_pdu):
  """Up-Down protocol "issue_response" PDU."""

  def toXML(self):
    """Generate payload of "issue_response" PDU."""
    assert len(self.classes) == 1
    return list_response_pdu.toXML(self)

class revoke_pdu(base_elt):
  """Up-Down protocol "revoke" PDU."""

  def startElement(self, stack, name, attrs):
    """Handle "revoke" PDU."""
    self.class_name = attrs["class_name"]
    self.ski = attrs["ski"]

  def toXML(self):
    """Generate payload of "revoke" PDU."""
    return [self.make_elt("key", "class_name", "ski")]

class revoke_response_pdu(revoke_pdu):
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

  def endElement(self, stack, name, text):
    """Handle "error_response" PDU."""
    if name == "status":
      code = int(text)
      if code not in self.codes:
        raise rpki.exceptions.BadStatusCode, "%s is not a known status code"
      self.status = code
    elif name == "last_message_processed":
      self.last_message_processed = text
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
    return [elt]

class message_pdu(base_elt):
  """Up-Down protocol message wrapper PDU."""

  version = 1

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
    self.payload = {
      "list"            : list_pdu,
      "list_response"   : list_response_pdu,
      "issue"           : issue_pdu,
      "issue_response"  : issue_response_pdu,
      "revoke"          : revoke_pdu,
      "revoke_response" : revoke_response_pdu,
      "error_response"  : error_response_pdu
      }[attrs["type"]]()
    stack.append(self.payload)

  def __str__(self):
    lxml.etree.tostring(self.toXML(), pretty_print=True, encoding="UTF-8")

class sax_handler(rpki.sax_utils.handler):
  """SAX handler for Up-Down protocol."""

  def create_top_level(self, name, attrs):
    """Top-level PDU for this protocol is <message/>."""
    return message_pdu()
