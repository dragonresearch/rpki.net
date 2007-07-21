# $Id$

import base64, sax_utils, resource_set

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

  def print_attrs(self):
    xml =""
    for key in self.attributes:
      val = getattr(self, key, None)
      if val is not None:
        xml += ' %s="%s"' % (key, val)
    for key in self.booleans:
      if getattr(self, key, False):
        xml += ' %s="yes"' % key
    return xml

class extension_preference_elt(base_elt):
  """
  Container for extension preferences.
  """

  def startElement(self, stack, name, attrs):
    assert name == "extension_preference", "Unexpected name %s, stack %s" % (name, stack)
    self.name = attrs["name"]

  def endElement(self, stack, name, text):
    self.value = text
    stack.pop()

  def __str__(self):
    return ('    <extension_preference name="%s">%s</extension_preference>\n'
            % (self.name, self.value))

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

  def __str__(self):
    xml = '  <self%s>\n' % self.print_attrs()
    for i in self.prefs:
      xml += str(i)
    return xml + '  </self>\n'

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
      self.signing_cert.append(base64.b64decode(text))
    elif name == "public_key":
      self.public_key = base64.b64decode(text)
    elif name == "pkcs10_cert_request":
      self.pkcs10_cert_request = base64.b64decode(text)
    else:
      assert name == "bsc", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def __str__(self):
    xml = '  <bsc%s>\n' % self.print_attrs()
    for i in self.signing_cert:
      xml += '    <signing_cert>' + base64.b64encode(i) + '</signing_cert>\n'
    if self.pkcs10_cert_request:
      xml += '    <pkcs10_cert_request>' + base64.b64encode(self.pkcs10_cert_request) + '</pkcs10_cert_request>\n'
    if self.public_key:
      xml += '    <public_key>' + base64.b64encode(self.public_key) + '</public_key>\n'
    return xml + '  </bsc>\n'

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
      self.peer_ta = base64.b64decode(text)
    else:
      assert name == "parent", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def __str__(self):
    xml = '  <parent%s>\n' % self.print_attrs()
    if self.peer_ta:
      xml += '    <peer_ta>' + base64.b64encode(self.peer_ta) + '</peer_ta>\n'
    return xml + '  </parent>\n'

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
      self.peer_ta = base64.b64decode(text)
    else:
      assert name == "child", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def __str__(self):
    xml = '  <child%s>\n' % self.print_attrs()
    i = getattr(self, "peer_ta", None)
    if self.peer_ta:
      xml += '    <peer_ta>' + base64.b64encode(self.peer_ta) + '</peer_ta>\n'
    return xml + '  </child>\n'

class repository_elt(base_elt):

  attributes = ("action", "type", "self_id", "repository_id", "bsc_link", "peer_contact")

  peer_ta = None

  def startElement(self, stack, name, attrs):
    if name != "peer_ta":
      assert name == "repository", "Unexpected name %s, stack %s" % (name, stack)
      self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    if name == "peer_ta":
      self.peer_ta = base64.b64decode(text)
    else:
      assert name == "repository", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def __str__(self):
    xml = '  <repository%s>\n' % self.print_attrs()
    if self.peer_ta:
      xml += '    <peer_ta>' + base64.b64encode(self.peer_ta) + '</peer_ta>\n'
    return xml + '  </repository>\n'

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

  def __str__(self):
    return '  <route_origin%s/>\n' % self.print_attrs()

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

  def __str__(self):
    return '    <resource_class%s/>\n' % self.print_attrs()

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

  def __str__(self):
    xml = '  <list_resources%s>\n' % self.print_attrs()
    for i in self.resources:
      xml += str(i)
    return xml + '  </list_resources>\n'

class report_error_elt(base_elt):

  attributes = ("self_id", "error_code")

  def startElement(self, stack, name, attrs):
    assert name == "report_error", "Unexpected name %s, stack %s" % (name, stack)
    self.read_attrs(attrs)

  def __str__(self):
    return '  <report_error%s/>\n' % self.print_attrs()

class msg(list):
  """
  Left-right PDU.
  """

  spec_uri = "http://www.hactrn.net/uris/rpki/left-right-spec/"
  version = 1

  def startElement(self, stack, name, attrs):
    if name == "msg":
      self.version = int(attrs["version"])
      assert self.version == 1
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
    return ('<?xml version="1.0" encoding="US-ASCII" ?>\n'
            '<msg xmlns="%s" version="%d">\n'
            '%s</msg>\n'
            % (self.spec_uri, self.version, "".join(map(str, self))))

class sax_handler(sax_utils.handler):
  """
  SAX handler for Left-Right protocol.
  """

  def create_top_level(self, name, attrs):
    assert name == "msg" and attrs["version"] == "1"
    return msg()
