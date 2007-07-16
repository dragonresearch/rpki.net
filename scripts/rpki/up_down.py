# $Id$

import base64, sax_utils, resource_set

class generic_pdu(object):
  """
  Generic PDU object, just provides some default methods.
  """

  def startElement(self, stack, name, attrs):
    pass

  def endElement(self, stack, name, text):
    stack.pop()

class certificate_elt(generic_pdu):
  """
  Up-Down protocol representation of an issued certificate.
  """

  def startElement(self, stack, name, attrs):
    assert name == "certificate", "Unexpected name %s, stack %s" % (name, stack)
    self.cert_url = attrs["cert_url"]
    self.req_resource_set_as   = resource_set.resource_set_as(attrs["req_resource_set_as"])
    self.req_resource_set_ipv4 = resource_set.resource_set_ipv4(attrs["req_resource_set_ipv4"])
    self.req_resource_set_ipv6 = resource_set.resource_set_ipv6(attrs["req_resource_set_ipv6"])

  def endElement(self, stack, name, text):
    assert name == "certificate"
    self.cert = base64.b64decode(text)
    stack.pop()

  def __str__(self):
    xml = ('    <certificate cert_url="%s"' % (self.cert_url))
    if self.req_resource_set_as:
      xml += ('\n                 req_resource_set_as="%s"' % self.req_resource_set_as)
    if self.req_resource_set_ipv4:
      xml += ('\n                 req_resource_set_ipv4="%s"' % self.req_resource_set_ipv4)
    if self.req_resource_set_ipv6:
      xml += ('\n                 req_resource_set_ipv6="%s"' % self.req_resource_set_ipv6)
    xml += ">" + base64.b64encode(self.cert) + "</certificate>\n"
    return xml

class class_elt(generic_pdu):
  """
  Up-Down protocol representation of a resource class.
  """

  def __init__(self):
    self.certs = []

  def startElement(self, stack, name, attrs):
    if name == "certificate":
      cert = certificate_elt()
      self.certs.append(cert)
      stack.append(cert)
      cert.startElement(stack, name, attrs)
    elif name != "issuer":
      assert name == "class", "Unexpected name %s, stack %s" % (name, stack)
      self.class_name = attrs["class_name"]
      self.cert_url = attrs["cert_url"]
      self.suggested_sia_head = attrs.get("suggested_sia_head")
      self.resource_set_as   = resource_set.resource_set_as(attrs["resource_set_as"])
      self.resource_set_ipv4 = resource_set.resource_set_ipv4(attrs["resource_set_ipv4"])
      self.resource_set_ipv6 = resource_set.resource_set_ipv6(attrs["resource_set_ipv6"])

  def endElement(self, stack, name, text):
    if name == "issuer":
      self.issuer = base64.b64decode(text)
    else:
      assert name == "class", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def __str__(self):
    xml = ('\
  <class class_name="%s"\n\
         cert_url="%s"\n\
         resource_set_as="%s"\n\
         resource_set_ipv4="%s"\n\
         resource_set_ipv6="%s"' \
           % (self.class_name, self.cert_url,
              self.resource_set_as, self.resource_set_ipv4, self.resource_set_ipv6))
    if self.suggested_sia_head:
      xml += ('\n         suggested_sia_head="%s"' % (self.suggested_sia_head))
    xml += ">\n"
    for cert in self.certs:
      xml += str(cert)
    xml += "    <issuer>" + base64.b64encode(self.issuer) + "</issuer>\n  </class>\n"
    return xml

class list_pdu(generic_pdu):
  """
  Up-Down protocol "list" PDU.
  """

  def __str__(self):
    return ""

class list_response_pdu(generic_pdu):
  """
  Up-Down protocol "list_response" PDU.
  """

  def __init__(self):
    self.classes = []

  def startElement(self, stack, name, attrs):
    assert name == "class", "Unexpected name %s, stack %s" % (name, stack)
    klass = class_elt()
    self.classes.append(klass)
    stack.append(klass)
    klass.startElement(stack, name, attrs)
      
  def __str__(self):
    return "".join(map(str, self.classes))

class issue_pdu(generic_pdu):
  """
  Up-Down protocol "issue" PDU.
  """

  def startElement(self, stack, name, attrs):
    assert name == "request", "Unexpected name %s, stack %s" % (name, stack)
    self.class_name = attrs["class_name"]
    self.req_resource_set_as   = resource_set.resource_set_as(attrs.get("req_resource_set_as"))
    self.req_resource_set_ipv4 = resource_set.resource_set_ipv4(attrs.get("req_resource_set_ipv4"))
    self.req_resource_set_ipv6 = resource_set.resource_set_ipv6(attrs.get("req_resource_set_ipv6"))

  def endElement(self, stack, name, text):
    assert name == "request", "Unexpected name %s, stack %s" % (name, stack)
    self.pkcs10 = base64.b64decode(text)
    stack.pop()

  def __str__(self):
    xml = ('  <request class_name="%s"' % self.class_name)
    if self.req_resource_set_as:
      xml += ('\n           req_resource_set_as="%s"' % self.req_resource_set_as)
    if self.req_resource_set_ipv4:
      xml += ('\n           req_resource_set_ipv4="%s"' % self.req_resource_set_ipv4)
    if self.req_resource_set_ipv6:
      xml += ('\n           req_resource_set_ipv6="%s"' % self.req_resource_set_ipv6)
    return xml + ">" + base64.b64encode(self.pkcs10) + "</request>\n"

class issue_response_pdu(list_response_pdu):
  """
  Up-Down protocol "issue_response" PDU.
  """

  def __str__(self):
    assert len(self.classes) == 1
    return list_response_pdu.__str__(self)

class revoke_pdu(generic_pdu):
  """
  Up-Down protocol "revoke" PDU.
  """

  def startElement(self, stack, name, attrs):
    self.class_name = attrs["class_name"]
    self.ski = attrs["ski"]

  def __str__(self):
    return ('  <key class_name="%s" ski="%s" />\n' % (self.class_name, self.ski))

class revoke_response_pdu(revoke_pdu):
  """
  Up-Down protocol "revoke_response" PDU.
  """
  pass

class error_response_pdu(generic_pdu):
  """
  Up-Down protocol "error_response" PDU.
  """

  def __str__(self):
    return '  <status>%d</status>\n' % self.status

  def endElement(self, stack, name, text):
    if name == "status":
      self.status = int(text)
    elif name == "last_message_processed":
      self.last_message_processed = text
    elif name == "description":
      self.description = text
    else:
      assert name == "message", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()
      stack[-1].endElement(stack, name, text)

class message_pdu(generic_pdu):
  """
  Up-Down protocol message wrapper.
  """

  def __str__(self):
    return ('\
<?xml version="1.0" encoding="UTF-8"?>\n\
<message xmlns="http://www.apnic.net/specs/rescerts/up-down/"\n\
         version="1"\n\
         sender="%s"\n\
         recipient="%s"\n\
         type="%s">\n' \
            % (self.sender, self.recipient, self.type)
            ) + str(self.payload) + "</message>\n"

  def startElement(self, stack, name, attrs):
    assert name == "message", "Unexpected name %s, stack %s" % (name, stack)
    self.version = attrs["version"]
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

class sax_handler(sax_utils.handler):
  """
  SAX handler for Up-Down protocol.
  """

  def create_top_level(self, name, attrs):
    assert name == "message" and attrs["version"] == "1"
    return message_pdu()
