# $Id$

import base64, glob, os, re, socket, struct, xml.sax

def relaxng(xml, rng):
  i, o = os.popen4(("xmllint", "--noout", "--relaxng", rng, "-"))
  i.write(xml)
  i.close()
  v = o.read()
  o.close()
  if v != "- validates\n":
    raise RuntimeError, "RelaxNG validation failure:\n" + v

class v4addr(long):
  bits = 32

  def __new__(cls, x):
    r = struct.unpack("!I", socket.inet_pton(socket.AF_INET, x))
    return long.__new__(cls, r[0])

  def __str__(self):
    return socket.inet_ntop(socket.AF_INET, struct.pack("!I", long(self)))

class v6addr(long):
  bits = 128

  def __new__(cls, x):
    r = struct.unpack("!QQ", socket.inet_pton(socket.AF_INET6, x))
    return long.__new__(cls, (r[0] << 64) | r[1])

  def __str__(self):
    return socket.inet_ntop(socket.AF_INET6,
                            struct.pack("!QQ", long(self) >> 64,
                                        long(self) & 0xFFFFFFFFFFFFFFFF))

class resource_range(object):

  def __init__(self, min, max):
    assert min <= max, "Mis-ordered range: %s before %s" % (str(min), str(max))
    self.min = min
    self.max = max

  def __cmp__(self, other):
    c = self.min - other.min
    if c == 0:
      c = self.max - other.max
    return c

class resource_range_as(resource_range):

  def __str__(self):
    if self.min == self.max:
      return str(self.min)
    else:
      return str(self.min) + "-" + str(self.max)

class resource_range_ip(resource_range):

  def __str__(self):
    mask = self.min ^ self.max
    prefixlen = self.min.bits
    while mask & 1:
      prefixlen -= 1
      mask >>= 1
    if mask:
      return str(self.min) + "-" + str(self.max)
    else:
      return str(self.min) + "/" + str(prefixlen)

class resource_range_ipv4(resource_range_ip): pass

class resource_range_ipv6(resource_range_ip): pass

class resource_set(object):

  def __init__(self, s):
    if s == "":
      self.vec = []
    else:
      self.vec = map(self.parse, s.split(","))
      self.vec.sort()
      if __debug__:
        for i in range(0, len(self.vec) - 1):
          assert self.vec[i].max < self.vec[i + 1].min, 'Resource overlap "%s"' % (s)

  def __str__(self):
    vec = map(str, self.vec)
    return ",".join(vec)

  def __iter__(self):
    for i in self.vec:
      yield i

  def __len__(self):
    return len(self.vec)

class resource_set_as(resource_set):

  def parse(self, x):
    r = re.match("^([0-9]+)-([0-9]+)$", x)
    if r:
      return resource_range_as(long(r.group(1)), long(r.group(2)))
    else:
      return resource_range_as(long(x), long(x))

class resource_set_ip(resource_set):

  def parse(self, x):
    r = re.match("^([0-9:.a-fA-F]+)-([0-9:.a-fA-F]+)$", x)
    if r:
      return self.range_type(self.addr_type(r.group(1)), self.addr_type(r.group(2)))
    r = re.match("^([0-9:.a-fA-F]+)/([0-9]+)$", x)
    if r:
      min = self.addr_type(r.group(1))
      prefixlen = int(r.group(2))
      mask = (1 << (self.addr_type.bits - prefixlen)) - 1
      assert (min & mask) == 0, "Resource not in canonical form: %s" % (x)
      max = min | mask
      return self.range_type(min, max)
    raise RuntimeError, 'Bad IP resource "%s"' % (x)

class resource_set_ipv4(resource_set_ip):
  addr_type = v4addr
  range_type = resource_range_ipv4

class resource_set_ipv6(resource_set_ip):
  addr_type = v6addr
  range_type = resource_range_ipv6

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

class cert(object):

  def __init__(self, attrs):
    for k in ("cert_url", ):
      setattr(self, k, attrs.getValue(k).encode("ascii"))
    for k,f in (("req_resource_set_as", resource_set_as),
                ("req_resource_set_ipv4", resource_set_ipv4),
                ("req_resource_set_ipv6", resource_set_ipv6)):
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
    for k,f in (("resource_set_as", resource_set_as),
                ("resource_set_ipv4", resource_set_ipv4),
                ("resource_set_ipv6", resource_set_ipv6)):
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
    for k,f in (("req_resource_set_as", resource_set_as),
                ("req_resource_set_ipv4", resource_set_ipv4),
                ("req_resource_set_ipv6", resource_set_ipv6)):
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

files = glob.glob("up-down-protocol-samples/*.xml")
files.sort()
for f in files:
  handler = sax_handler()
  fh = open(f, "r")
  x = fh.read()
  fh.close()
  xml.sax.parseString(x, handler)
  obj = handler.obj
  print "<!-- " + str(obj) + " -->\n"
  x = obj.msgToXML()
  print x
  relaxng(x, "up-down-medium-schema.rng")
