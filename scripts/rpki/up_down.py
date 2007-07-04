# $Id$

import base64, xml.sax, resource_set

def snarf(obj, attrs, key, func=None):
  try:
    val = attrs.getValue(key).encode("ascii")
    if func:
      val = func(val)
  except KeyError:
    val = None
  setattr(obj, key, val)

class msg(object):

  def __str__(self):
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

class cert(object):

  def __init__(self, attrs):
    snarf(self, attrs, "cert_url")
    snarf(self, attrs, "req_resource_set_as",   resource_set.resource_set_as)
    snarf(self, attrs, "req_resource_set_ipv4", resource_set.resource_set_ipv4)
    snarf(self, attrs, "req_resource_set_ipv6", resource_set.resource_set_ipv6)

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

class resource_class(object):

  def __init__(self, attrs):
    snarf(self, attrs, "class_name")
    snarf(self, attrs, "cert_url")
    snarf(self, attrs, "resource_set_as",   resource_set.resource_set_as)
    snarf(self, attrs, "resource_set_ipv4", resource_set.resource_set_ipv4)
    snarf(self, attrs, "resource_set_ipv6", resource_set.resource_set_ipv6)
    snarf(self, attrs, "suggested_sia_head")
    self.certs = []

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
    return "".join(map(str, self.resource_classes))

class issue(msg):

  def startElement(self, name, attrs):
    assert name == "request"
    snarf(self, attrs, "class_name")
    snarf(self, attrs, "req_resource_set_as",   resource_set.resource_set_as)
    snarf(self, attrs, "req_resource_set_ipv4", resource_set.resource_set_ipv4)
    snarf(self, attrs, "req_resource_set_ipv6", resource_set.resource_set_ipv6)

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
    snarf(self, attrs, "class_name")
    snarf(self, attrs, "ski")

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
        }[attrs.getValue("type").encode("ascii")]
      assert self.obj
      snarf(self.obj, attrs, "sender")
      snarf(self.obj, attrs, "recipient")
      snarf(self.obj, attrs, "type")

    else:
      assert self.obj
      self.obj.startElement(name, attrs)

  def characters(self, content):
    self.text += content

  def endElement(self, name):
    assert self.obj
    if name != "message":
      self.obj.endElement(name, self.text)
    self.text = ""
