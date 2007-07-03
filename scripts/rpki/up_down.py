# $Id$

import base64, xml.sax, resource_set

class msg(object):

  def msgToXML(self):
    return ('\
<?xml version="1.0" encoding="UTF-8"?>\n\
<message xmlns="http://www.apnic.net/specs/rescerts/up-down/"\n\
         version="1"\n\
         sender="%s"\n\
         recipient="%s"\n\
         type="%s">\n' \
            % (self.sender, self.recipient, self.type)
            ) + self.toXML() + "</message>\n"

  def toXML(self):
    return ""

  def startElement(self, name, attrs):
    pass

  def endElement(self, name, text):
    pass

  def __str__(self):
    return self.msgToXML()

class cert(object):

  def __init__(self, attrs):
    for k in ("cert_url", ):
      setattr(self, k, attrs.getValue(k).encode("ascii"))
    for k,f in (("req_resource_set_as", resource_set.resource_set_as),
                ("req_resource_set_ipv4", resource_set.resource_set_ipv4),
                ("req_resource_set_ipv6", resource_set.resource_set_ipv6)):
      try:
        setattr(self, k, f(attrs.getValue(k).encode("ascii")))
      except KeyError:
        setattr(self, k, None)

  def toXML(self):
    xml = ('    <certificate cert_url="%s"' % (self.cert_url))
    if self.req_resource_set_as:
      xml += ('\n                 req_resource_set_as="%s"' % self.req_resource_set_as)
    if self.req_resource_set_ipv4:
      xml += ('\n                 req_resource_set_ipv4="%s"' % self.req_resource_set_ipv4)
    if self.req_resource_set_ipv6:
      xml += ('\n                 req_resource_set_ipv6="%s"' % self.req_resource_set_ipv6)
    xml += ">" + base64.b64encode(self.cert) + "</certificate>\n"
    return xml

class resource_class(object):

  def __init__(self, attrs):
    for k in ("class_name", "cert_url"):
      setattr(self, k, attrs.getValue(k).encode("ascii"))
    for k,f in (("resource_set_as", resource_set.resource_set_as),
                ("resource_set_ipv4", resource_set.resource_set_ipv4),
                ("resource_set_ipv6", resource_set.resource_set_ipv6)):
      setattr(self, k, f(attrs.getValue(k).encode("ascii")))
    try:
      self.suggested_sia_head = attrs.getValue("suggested_sia_head")
    except KeyError:
      self.suggested_sia_head = None
    self.certs = []

  def toXML(self):
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
      xml += cert.toXML()
    xml += "    <issuer>" + base64.b64encode(self.issuer) + "</issuer>\n  </class>\n"
    return xml

class list(msg):
  pass

class list_response(msg):

  def __init__(self):
    self.resource_classes = []

  def startElement(self, name, attrs):
    if name == "class":
      self.resource_classes.append(resource_class(attrs))
    elif name == "certificate":
      self.resource_classes[-1].certs.append(cert(attrs))

  def endElement(self, name, text):
    if name == "certificate":
      self.resource_classes[-1].certs[-1].cert = base64.b64decode(text)
    elif name == "issuer":
      self.resource_classes[-1].issuer = base64.b64decode(text)

  def toXML(self):
    xml = ""
    for c in self.resource_classes:
      xml += c.toXML()
    return xml

class issue(msg):

  def startElement(self, name, attrs):
    assert name == "request"
    self.class_name = attrs.getValue("class_name")
    for k,f in (("req_resource_set_as", resource_set.resource_set_as),
                ("req_resource_set_ipv4", resource_set.resource_set_ipv4),
                ("req_resource_set_ipv6", resource_set.resource_set_ipv6)):
      try:
        setattr(self, k, f(attrs.getValue(k).encode("ascii")))
      except KeyError:
        setattr(self, k, None)

  def endElement(self, name, text):
    assert name == "request"
    self.pkcs10 = base64.b64decode(text)

  def toXML(self):
    xml = ('  <request class_name="%s"' % self.class_name)
    if self.req_resource_set_as:
      xml += ('\n           req_resource_set_as="%s"' % self.req_resource_set_as)
    if self.req_resource_set_ipv4:
      xml += ('\n           req_resource_set_ipv4="%s"' % self.req_resource_set_ipv4)
    if self.req_resource_set_ipv6:
      xml += ('\n           req_resource_set_ipv6="%s"' % self.req_resource_set_ipv6)
    return xml + ">" + base64.b64encode(self.pkcs10) + "</request>\n"

class issue_response(list_response):

  def toXML(self):
    assert len(self.resource_classes) == 1
    return list_response.toXML(self)

class revoke(msg):

  def startElement(self, name, attrs):
    self.class_name = attrs.getValue("class_name")
    self.ski = attrs.getValue("ski")

  def toXML(self):
    return ('  <key class_name="%s" ski="%s" />\n' % (self.class_name, self.ski))

class revoke_response(revoke):
  pass

class error_response(msg):

  def toXML(self):
    return '  <status>%d</status>\n' % self.status

  def endElement(self, name, text):
    if name == "status":
      self.status = int(text)
    elif name == "last_message_processed":
      self.last_message_processed = text
    elif name == "description":
      self.description = text

class sax_handler(xml.sax.handler.ContentHandler):

  def __init__(self):
    self.text = ""
    self.obj = None

  def startElementNS(self, name, qname, attrs):
    return self.startElement(name[1], attrs)

  def endElementNS(self, name, qname):
    return self.endElement(name[1])

  def startElement(self, name, attrs):
    if name == "message":
      assert int(attrs.getValue("version")) == 1
      if self.obj == None:
        self.obj = {
          "list"                  : list(),
          "list_response"         : list_response(),
          "issue"                 : issue(),
          "issue_response"        : issue_response(),
          "revoke"                : revoke(),
          "revoke_response"       : revoke_response(),
          "error_response"        : error_response()
        }[attrs.getValue("type")]
      assert self.obj != None
      for k in ("type", "sender", "recipient"):
        setattr(self.obj, k, attrs.getValue(k).encode("ascii"))
    else:
      assert self.obj != None
      self.obj.startElement(name, attrs)

  def characters(self, content):
    self.text += content

  def endElement(self, name):
    assert self.obj != None
    if name != "message":
      self.obj.endElement(name, self.text)
    self.text = ""
