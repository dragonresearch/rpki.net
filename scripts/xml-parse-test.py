# $Id$

import base64
import glob
import os
import re
import socket
import xml.sax

def relaxng(xml, rng):
  i, o = os.popen4(("xmllint", "--noout", "--relaxng", rng, "-"))
  i.write(xml)
  i.close()
  v = o.read()
  o.close()
  if v != "- validates\n":
    raise RuntimeError, "RelaxNG validation failure:\n" + v

class rpki_updown_resource_set(object):

  def __init__(self, s):
    self.vec = []
    if s != "":
      vec = s.split(",")
      for elt in vec:
        r = re.match("^(%s)-(%s)$" % (self.re, self.re), elt)
        if r:
          b, e = r.groups()
          self.vec.append((self.pton(b), self.pton(e)))
          continue
        if self.prefixes:
          r = re.match("^(%s)/([0-9]+)$" % (self.re), elt)
        if r:
          i, p = r.groups()
          self.vec.append((self.pton(i), int(p)))
          continue
        self.vec.append((self.pton(elt), ))
      self.vec.sort()

  def __str__(self):
    vec = []
    for elt in self.vec:
      if len(elt) == 1:
        vec.append(self.ntop(elt[0]))
      elif self.prefixes and isinstance(elt[1], int):
        vec.append(self.ntop(elt[0]) + "/" + str(elt[1]))
      else:
        vec.append(self.ntop(elt[0]) + "-" + self.ntop(elt[1]))
    return ",".join(vec)

class rpki_updown_resource_set_as(rpki_updown_resource_set):
  prefixes = False
  re = "[0-9]+"
  def pton(self, x): return long(x)
  def ntop(self, x): return str(x)

class rpki_updown_resource_set_ip(rpki_updown_resource_set):
  prefixes = True
  def pton(self, x): return socket.inet_pton(self.af, x)
  def ntop(self, x): return socket.inet_ntop(self.af, x)

class rpki_updown_resource_set_ipv4(rpki_updown_resource_set_ip):
  re = "[0-9.]+"
  af = socket.AF_INET

class rpki_updown_resource_set_ipv6(rpki_updown_resource_set_ip):
  re = "[0-9:a-fA-F]+"
  af = socket.AF_INET6

class rpki_updown_msg(object):

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

class rpki_updown_cert(object):

  def __init__(self, attrs):
    for k in ("cert_url", ):
      setattr(self, k, attrs.getValue(k).encode("ascii"))
    for k,f in (("req_resource_set_as", rpki_updown_resource_set_as),
                ("req_resource_set_ipv4", rpki_updown_resource_set_ipv4),
                ("req_resource_set_ipv6", rpki_updown_resource_set_ipv6)):
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

class rpki_updown_class(object):

  def __init__(self, attrs):
    for k in ("class_name", "cert_url"):
      setattr(self, k, attrs.getValue(k).encode("ascii"))
    for k,f in (("resource_set_as", rpki_updown_resource_set_as),
                ("resource_set_ipv4", rpki_updown_resource_set_ipv4),
                ("resource_set_ipv6", rpki_updown_resource_set_ipv6)):
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

class rpki_updown_list(rpki_updown_msg):
  pass

class rpki_updown_list_response(rpki_updown_msg):

  def __init__(self):
    self.resource_classes = []

  def startElement(self, name, attrs):
    if name == "class":
      self.resource_classes.append(rpki_updown_class(attrs))
    elif name == "certificate":
      self.resource_classes[-1].certs.append(rpki_updown_cert(attrs))

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

class rpki_updown_issue(rpki_updown_msg):

  def startElement(self, name, attrs):
    assert name == "request"
    self.class_name = attrs.getValue("class_name")
    for k,f in (("req_resource_set_as", rpki_updown_resource_set_as),
                ("req_resource_set_ipv4", rpki_updown_resource_set_ipv4),
                ("req_resource_set_ipv6", rpki_updown_resource_set_ipv6)):
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

class rpki_updown_issue_response(rpki_updown_list_response):

  def toXML(self):
    assert len(self.resource_classes) == 1
    return rpki_updown_list_response.toXML(self)

class rpki_updown_revoke(rpki_updown_msg):

  def startElement(self, name, attrs):
    self.class_name = attrs.getValue("class_name")
    self.ski = attrs.getValue("ski")

  def toXML(self):
    return ('  <key class_name="%s" ski="%s" />\n' % (self.class_name, self.ski))

class rpki_updown_revoke_response(rpki_updown_revoke):
  pass

class rpki_updown_error_response(rpki_updown_msg):

  def toXML(self):
    return '  <status>%d</status>\n' % self.status

  def endElement(self, name, text):
    if name == "status":
      self.status = int(text)
    elif name == "last_message_processed":
      self.last_message_processed = text
    elif name == "description":
      self.description = text

class rpki_updown_sax_handler(xml.sax.handler.ContentHandler):

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
          "list"                  : rpki_updown_list(),
          "list_response"         : rpki_updown_list_response(),
          "issue"                 : rpki_updown_issue(),
          "issue_response"        : rpki_updown_issue_response(),
          "revoke"                : rpki_updown_revoke(),
          "revoke_response"       : rpki_updown_revoke_response(),
          "error_response"        : rpki_updown_error_response()
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

files = glob.glob("up-down-protocol-samples/*.xml")
files.sort()
for f in files:
# try:

    handler = rpki_updown_sax_handler()

#   parser = xml.sax.make_parser()
#   parser.setContentHandler(handler)
#   parser.parse(f)

    fh = open(f, "r")
    x = fh.read()
    fh.close()
    xml.sax.parseString(x, handler)

    obj = handler.obj
    print "<!-- " + str(obj) + " -->\n"
    x = obj.msgToXML()
    print x
    relaxng(x, "up-down-medium-schema.rng")

# except Exception, err:
#   print "? " + str(err) + "\n"
