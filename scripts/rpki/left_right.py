# $Id$

import base64, sax_utils, resource_set, lxml.etree, POW, POW.pkix

xmlns = "http://www.hactrn.net/uris/rpki/left-right-spec/"

nsmap = { None : xmlns }

class base_elt(object):
  """
  Base type for left-right message elements.
  """

  attributes = ()
  booleans = ()

  def startElement(self, stack, name, attrs):
    self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    stack.pop()

  def read_attrs(self, attrs):
    for key in self.attributes:
      setattr(self, key, attrs.get(key, None))
    for key in self.booleans:
      setattr(self, key, attrs.get(key, False))

  def make_elt(self, name):
    elt = lxml.etree.Element("{%s}%s" % (xmlns, name), nsmap=nsmap)
    for key in self.attributes:
      val = getattr(self, key, None)
      if val is not None:
        elt.set(key, str(val))
    for key in self.booleans:
      if getattr(self, key, False):
        elt.set(key, "yes")
    return elt

  def make_b64elt(self, elt, name, value=None):
    if value is None:
      value = getattr(self, name, None)
    if value is not None:
      lxml.etree.SubElement(elt, "{%s}%s" % (xmlns, name), nsmap=nsmap).text = base64.b64encode(value)

  def __str__(self):
    lxml.etree.tostring(self.toXML(), pretty_print=True, encoding="us-ascii")

def biz_cert(text):
  cert = POW.pkix.Certificate()
  cert.fromString(base64.b64decode(text))
  return cert

class extension_preference_elt(base_elt):
  """
  Container for extension preferences.
  """

  attributes = ("name",)

  def startElement(self, stack, name, attrs):
    assert name == "extension_preference", "Unexpected name %s, stack %s" % (name, stack)
    self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    self.value = text
    stack.pop()

  def toXML(self):
    elt = self.make_elt("extension_preference")
    elt.text = self.value
    return elt

class self_elt(base_elt):

  attributes = ("action", "type", "self_id")
  booleans = ("rekey", "reissue", "revoke", "run_now", "publish_world_now")

  def __init__(self):
    self.prefs = []

  def startElement(self, stack, name, attrs):
    if name == "extension_preference":
      pref = extension_preference_elt()
      self.prefs.append(pref)
      stack.append(pref)
      pref.startElement(stack, name, attrs)
    else:
      assert name == "self", "Unexpected name %s, stack %s" % (name, stack)
      self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    assert name == "self", "Unexpected name %s, stack %s" % (name, stack)
    stack.pop()

  def toXML(self):
    elt = self.make_elt("self")
    elt.extend([i.toXML() for i in self.prefs])
    return elt

class bsc_elt(base_elt):

  attributes = ("action", "type", "self_id", "bsc_id", "key_type", "hash_alg", "key_length")
  booleans = ("generate_keypair",)

  pkcs10_cert_request = None
  public_key = None

  def __init__(self):
    self.signing_cert = []

  def startElement(self, stack, name, attrs):
    if not name in ("signing_cert", "public_key", "pkcs10_cert_request"):
      assert name == "bsc", "Unexpected name %s, stack %s" % (name, stack)
      self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    if name == "signing_cert":
      self.signing_cert.append(biz_cert(text))
    elif name == "public_key":
      self.public_key = base64.b64decode(text)
    elif name == "pkcs10_cert_request":
      self.pkcs10_cert_request = base64.b64decode(text)
    else:
      assert name == "bsc", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def toXML(self):
    elt = self.make_elt("bsc")
    for cert in self.signing_cert:
      self.make_b64elt(elt, "signing_cert", cert.toString())
    self.make_b64elt(elt, "pkcs10_cert_request")
    self.make_b64elt(elt, "public_key")
    return elt

class parent_elt(base_elt):

  attributes = ("action", "type", "self_id", "parent_id", "bsc_link", "repository_link", "peer_contact", "sia_base")
  booleans = ("rekey", "reissue", "revoke")

  peer_ta = None

  def startElement(self, stack, name, attrs):
    if name != "peer_ta":
      assert name == "parent", "Unexpected name %s, stack %s" % (name, stack)
      self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    if name == "peer_ta":
      self.peer_ta = biz_cert(text)
    else:
      assert name == "parent", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def toXML(self):
    elt = self.make_elt("parent")
    if self.peer_ta:
      self.make_b64elt(elt, "peer_ta", self.peer_ta.toString())
    return elt

class child_elt(base_elt):

  attributes = ("action", "type", "self_id", "child_id", "bsc_link", "child_db_id")
  booleans = ("reissue", )

  peer_ta = None

  def startElement(self, stack, name, attrs):
    if name != "peer_ta":
      assert name == "child", "Unexpected name %s, stack %s" % (name, stack)
      self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    if name == "peer_ta":
      self.peer_ta = biz_cert(text)
    else:
      assert name == "child", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def toXML(self):
    elt = self.make_elt("child")
    if self.peer_ta:
      self.make_b64elt(elt, "peer_ta", self.peer_ta.toString())
    return elt

class repository_elt(base_elt):

  attributes = ("action", "type", "self_id", "repository_id", "bsc_link", "peer_contact")

  peer_ta = None

  def startElement(self, stack, name, attrs):
    if name != "peer_ta":
      assert name == "repository", "Unexpected name %s, stack %s" % (name, stack)
      self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    if name == "peer_ta":
      self.peer_ta = biz_cert(text)
    else:
      assert name == "repository", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def toXML(self):
    elt = self.make_elt("repository")
    if self.peer_ta:
      self.make_b64elt(elt, "peer_ta", self.peer_ta.toString())
    return elt

class route_origin_elt(base_elt):

  attributes = ("action", "type", "self_id", "route_origin_id", "asn", "ipv4", "ipv6")
  booleans = ("suppress_publication",)

  def startElement(self, stack, name, attrs):
    assert name == "route_origin", "Unexpected name %s, stack %s" % (name, stack)
    self.read_attrs(attrs)
    if self.asn is not None:
      self.asn = long(self.asn)
    if self.ipv4 is not None:
      self.ipv4 = resource_set.resource_set_ipv4(self.ipv4)
    if self.ipv6 is not None:
      self.ipv6 = resource_set.resource_set_ipv6(self.ipv4)

  def endElement(self, stack, name, text):
    assert name == "route_origin", "Unexpected name %s, stack %s" % (name, stack)
    stack.pop()

  def toXML(self):
    return self.make_elt("route_origin")

class resource_class_elt(base_elt):

  attributes = ("as", "req_as", "ipv4", "req_ipv4", "ipv6", "req_ipv6")

  def startElement(self, stack, name, attrs):
    assert name == "resource_class", "Unexpected name %s, stack %s" % (name, stack)
    self.read_attrs(attrs)
    if self.as is not None:
      self.as = resource_set.resource_set_as(self.as)
    if self.req_as is not None:
      self.req_as = resource_set.resource_set_as(self.req_as)
    if self.ipv4 is not None:
      self.ipv4 = resource_set.resource_set_ipv4(self.ipv4)
    if self.req_ipv4 is not None:
      self.req_ipv4 = resource_set.resource_set_ipv4(self.req_ipv4)
    if self.ipv6 is not None:
      self.ipv6 = resource_set.resource_set_ipv6(self.ipv6)
    if self.req_ipv6 is not None:
      self.req_ipv6 = resource_set.resource_set_ipv6(self.req_ipv6)

  def endElement(self, stack, name, text):
    assert name == "resource_class", "Unexpected name %s, stack %s" % (name, stack)
    stack.pop()

  def toXML(self):
    return self.make_elt("resource_class")

class list_resources_elt(base_elt):

  attributes = ("type", "self_id", "child_id", "valid_until")

  def __init__(self):
    self.resources = []

  def startElement(self, stack, name, attrs):
    if name == "resource_class":
      rc = resource_class_elt()
      self.resources.append(rc)
      stack.append(rc)
      rc.startElement(stack, name, attrs)
    else:
      assert name == "list_resources", "Unexpected name %s, stack %s" % (name, stack)
      self.read_attrs(attrs)

  def toXML(self):
    elt = self.make_elt("list_resources")
    elt.extend([i.toXML() for i in self.resources])
    return elt

class report_error_elt(base_elt):

  attributes = ("self_id", "error_code")

  def startElement(self, stack, name, attrs):
    assert name == "report_error", "Unexpected name %s, stack %s" % (name, stack)
    self.read_attrs(attrs)

  def toXML(self):
    return self.make_elt("report_error")

class msg(list):
  """
  Left-right PDU.
  """

  version = 1

  def startElement(self, stack, name, attrs):
    if name == "msg":
      assert self.version == int(attrs["version"])
      #assert xmlns == attrs["xmlns"]
    else:
      elt = {
        "self"           : self_elt,
        "child"          : child_elt,
        "parent"         : parent_elt,
        "repository"     : repository_elt,
        "route_origin"   : route_origin_elt,
        "bsc"            : bsc_elt,
        "list_resources" : list_resources_elt,
        "report_error"   : report_error_elt
        }[name]()
      self.append(elt)
      stack.append(elt)
      elt.startElement(stack, name, attrs)

  def endElement(self, stack, name, text):
    assert name == "msg", "Unexpected name %s, stack %s" % (name, stack)
    assert len(stack) == 1
    stack.pop()

  def __str__(self):
    lxml.etree.tostring(self.toXML(), pretty_print=True, encoding="us-ascii")

  def toXML(self):
    elt = lxml.etree.Element("{%s}msg" % (xmlns), nsmap=nsmap, version=str(self.version))
    elt.extend([i.toXML() for i in self])
    return elt

class sax_handler(sax_utils.handler):
  """
  SAX handler for Left-Right protocol.
  """

  def create_top_level(self, name, attrs):
    assert name == "msg" and attrs["version"] == "1"
    return msg()
