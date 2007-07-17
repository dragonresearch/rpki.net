# $Id$

import base64, sax_utils, resource_set

# This is still pretty nasty, feels much too complex for a relatively
# simple task.

class base_elt(object):
  """
  Base type for left-right message elements.
  """

  def startElement(self, stack, name, attrs):
    pass

  def endElement(self, stack, name, text):
    stack.pop()

  def attr_maybe(self, key):
    val = getattr(self, key, None)
    if val is None:
      return ''
    else:
      return ' %s="%s"' % (key, val)

class extension_preference_elt(base_elt):
  """
  Container for extension preferences.
  """

  def startElement(self, stack, name, attrs):
    assert name == "extension_preference", "Unexpected name %s, stack %s" % (name, stack)
    self.name = attrs["name"]

  def endElement(self, stack, name, text):
    self.value = text.strip()
    stack.pop()

  def __str__(self):
    return ('    <extension_preference name="%s">%s</extension_preference>\n'
            % (self.name, self.value))

class self_elt(base_elt):

  booleans = ("rekey", "reissue", "revoke", "run_now", "publish_world_now")

  rekey = False
  reissue = False
  revoke = False
  run_now = False
  publish_world_now = False

  def __init__(self):
    self.prefs = []

  def startElement(self, stack, name, attrs):
    if name == "extension_preference":
      pref = extension_preference_elt()
      self.prefs.append(pref)
      stack.append(pref)
      pref.startElement(stack, name, attrs)
    elif name in self.booleans:
      setattr(self, name, True)
    else:
      assert name == "self", "Unexpected name %s, stack %s" % (name, stack)
      self.action = attrs["action"]
      self.self_id = attrs.get("self_id")

  def endElement(self, stack, name, text):
    if name not in self.booleans:
      assert name == "self", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def __str__(self):
    xml = '  <self action="%s"%s>\n' % (self.action, self.attr_maybe("self_id"))
    for i in self.prefs:
      xml += str(i)
    for i in self.booleans:
      if getattr(self, i):
        xml += '    <%s/>\n' % i
    return xml + '  </self>\n'

class bsc_elt(base_elt):

  generate_keypair = False

  def __init__(self):
    self.signing_cert = []

  def startElement(self, stack, name, attrs):
    if name == "generate_keypair":
      self.generate_keypair = True
      self.key_type = attrs["key_type"]
      self.hash_alg = attrs["hash_alg"]
      self.key_length = attrs["key_length"]
    elif not name in ("signing_cert", "public_key", "pkcs10_cert_request"):
      assert name == "bsc", "Unexpected name %s, stack %s" % (name, stack)
      self.action = attrs["action"]
      self.self_id = attrs["self_id"]
      self.bsc_id = attrs.get("bsc_id")

  def endElement(self, stack, name, text):
    if name == "signing_cert":
      self.signing_cert.append(base64.b64decode(text))
    elif name == "public_key":
      self.public_key = base64.b64decode(text)
    elif name == "pkcs10_cert_request":
      self.pkcs10_cert_request = base64.b64decode(text)
    elif name != "generate_keypair":
      assert name == "bsc", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def __str__(self):
    xml = ('  <bsc action="%s" self_id="%s"%s>\n'
           % (self.action, self.self_id, self.attr_maybe("bsc_id")))
    for i in self.signing_cert:
      xml += '    <signing_cert>' + base64.b64encode(i) + '</signing_cert>\n'
    i = getattr(self, "pkcs10_cert_request", None)
    if i is not None:
      xml += '    <pkcs10_cert_request>' + base64.b64encode(i) + '</pkcs10_cert_request>\n'
    i = getattr(self, "public_key", None)
    if i is not None:
      xml += '    <public_key>' + base64.b64encode(i) + '</public_key>\n'
    return xml + '  </bsc>\n'

class parent_elt(base_elt):

  ids = ("bsc_link", "repository_link")
  uris = ("peer_contact", "sia_base")
  booleans = ("rekey", "reissue", "revoke")

  rekey = False
  reissue = False
  revoke = False

  def startElement(self, stack, name, attrs):
    if name in self.uris:
      setattr(self, name, attrs["uri"])
    elif name in self.ids:
      setattr(self, name, attrs["id"])
    elif name in self.booleans:
      setattr(self, name, True)
    elif name != "peer_ta":
      assert name == "parent", "Unexpected name %s, stack %s" % (name, stack)
      self.action = attrs["action"]
      self.self_id = attrs["self_id"]
      self.parent_id = attrs.get("parent_id")

  def endElement(self, stack, name, text):
    if name == "peer_ta":
      self.peer_ta = base64.b64decode(text)
    elif name not in self.booleans + self.ids + self.uris:
      assert name == "parent", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def __str__(self):
    xml = ('  <parent action="%s" self_id="%s"%s>\n'
           % (self.action, self.self_id, self.attr_maybe("parent_id")))
    i = getattr(self, "peer_ta", None)
    if i is not None:
      xml += '    <peer_ta>' + base64.b64encode(i) + '</peer_ta>\n'
    i = getattr(self, "peer_contact", None)
    if i is not None:
      xml += '    <peer_contact uri="%s"/>\n' % i
    i = getattr(self, "sia_base", None)
    if i is not None:
      xml += '    <sia_base uri="%s"/>\n' % i
    i = getattr(self, "bsc_link", None)
    if i is not None:
      xml += '    <bsc_link id="%s"/>\n' % i
    i = getattr(self, "repository_link", None)
    if i is not None:
      xml += '    <repository_link id="%s"/>\n' % i
    for i in self.booleans:
      if getattr(self, i):
        xml += '    <%s/>\n' % i
    return xml + '  </parent>\n'

class child_elt(base_elt):

  ids = ("bsc_link", "child_db_id")
  booleans = ("reissue", )

  reissue = False

  def startElement(self, stack, name, attrs):
    if name in self.ids:
      setattr(self, name, attrs["id"])
    elif name in self.booleans:
      setattr(self, name, True)
    elif name != "peer_ta":
      assert name == "child", "Unexpected name %s, stack %s" % (name, stack)
      self.action = attrs["action"]
      self.self_id = attrs["self_id"]
      self.child_id = attrs.get("child_id")

  def endElement(self, stack, name, text):
    if name == "peer_ta":
      self.peer_ta = base64.b64decode(text)
    elif name not in self.booleans + self.ids:
      assert name == "child", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def __str__(self):
    xml = ('  <child action="%s" self_id="%s"%s>\n'
           % (self.action, self.self_id, self.attr_maybe("child_id")))
    i = getattr(self, "peer_ta", None)
    if i is not None:
      xml += '    <peer_ta>' + base64.b64encode(i) + '</peer_ta>\n'
    i = getattr(self, "bsc_link", None)
    if i is not None:
      xml += '    <bsc_link id="%s"/>\n' % i
    i = getattr(self, "child_db_id", None)
    if i is not None:
      xml += '    <child_db_id id="%s"/>\n' % i
    for i in self.booleans:
      if getattr(self, i):
        xml += '    <%s/>\n' % i
    return xml + '  </child>\n'

class repository_elt(base_elt):

  def startElement(self, stack, name, attrs):
    if name == "bsc_link":
      self.bsc_link = attrs["id"]
    elif name == "peer_contact":
      self.peer_contact = attrs["uri"]
    elif name != "peer_ta":
      assert name == "repository", "Unexpected name %s, stack %s" % (name, stack)
      self.action = attrs["action"]
      self.self_id = attrs["self_id"]
      self.repository_id = attrs.get("repository_id")

  def endElement(self, stack, name, text):
    if name == "peer_ta":
      self.peer_ta = base64.b64decode(text)
    elif name not in ("bsc_link", "peer_contact"):
      assert name == "repository", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def __str__(self):
    xml = ('  <repository action="%s" self_id="%s"%s>\n'
           % (self.action, self.self_id, self.attr_maybe("repository_id")))
    i = getattr(self, "peer_ta", None)
    if i is not None:
      xml += '    <peer_ta>' + base64.b64encode(i) + '</peer_ta>\n'
    i = getattr(self, "peer_contact", None)
    if i is not None:
      xml += '    <peer_contact uri="%s"/>\n' % i
    i = getattr(self, "bsc_link", None)
    if i is not None:
      xml += '    <bsc_link id="%s"/>\n' % i
    return xml + '  </repository>\n'

class route_origin_elt(base_elt):

  suppress_publication = False

  ipv4 = None
  ipv6 = None

  def startElement(self, stack, name, attrs):
    if name == "suppress_publication":
      self.suppress_publication = True
    elif name == "resources":
      self.asn = long(attrs["asn"])
      if "ipv4" in attrs:
        self.ipv4 = resource_set.resource_set_ipv4(attrs["ipv4"])
      if "ipv6" in attrs:
        self.ipv6 = resource_set.resource_set_ipv6(attrs["ipv6"])
    else:
      assert name == "route_origin", "Unexpected name %s, stack %s" % (name, stack)
      self.action = attrs["action"]
      self.self_id = attrs["self_id"]
      self.route_origin_id = attrs.get("route_origin_id")

  def endElement(self, stack, name, text):
    if name not in ("suppress_publication", "resources"):
      assert name == "route_origin", "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def __str__(self):
    xml = ('  <route_origin action="%s" self_id="%s"%s>\n'
           % (self.action, self.self_id, self.attr_maybe("route_origin_id")))
    asn = getattr(self, "asn", None)
    if asn is not None:
      xml += '    <resources asn="%d"' % asn
      if self.ipv4 is not None:
        xml += ' ipv4="%s"' % str(self.ipv4)
      if self.ipv6 is not None:
        xml += ' ipv6="%s"' % str(self.ipv6)
      xml += '/>\n'
    return xml + '  </route_origin>\n'

class resource_class_elt(base_elt):

  def startElement(self, stack, name, attrs):
    assert name == "resource_class", "Unexpected name %s, stack %s" % (name, stack)
    if "as" in attrs:
      self.as = resource_set.resource_set_as(attrs["as"])
    if "req_as" in attrs:
      self.req_as = resource_set.resource_set_as(attrs["req_as"])
    if "ipv4" in attrs:
      self.ipv4 = resource_set.resource_set_ipv4(attrs["ipv4"])
    if "req_ipv4" in attrs:
      self.req_ipv4 = resource_set.resource_set_ipv4(attrs["req_ipv4"])
    if "ipv6" in attrs:
      self.ipv6 = resource_set.resource_set_ipv6(attrs["ipv6"])
    if "req_ipv6" in attrs:
      self.req_ipv6 = resource_set.resource_set_ipv6(attrs["req_ipv6"])
  
  def __str__(self):
    xml = '    <resource_class'
    for k in ("as", "req_as", "ipv4", "req_ipv4", "ipv6", "req_ipv6"):
      v = getattr(self, k, None)
      if v is not None:
        xml += ' %s="%s"' % (k, v)
    return xml + '/>\n'

class list_resources_elt(base_elt):

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
      self.self_id = attrs["self_id"]
      self.child_id = attrs.get("child_id")
      self.valid_until = attrs.get("valid_until")

  def __str__(self):
    xml = ('  <list_resources self_id="%s"%s%s>\n'
           % (self.self_id, self.attr_maybe("child_id"), self.attr_maybe("valid_until")))
    for i in self.resources:
      xml += str(i)
    return xml + '  </list_resources>\n'

class report_error_elt(base_elt):

  def startElement(self, stack, name, attrs):
    assert name == "report_error", "Unexpected name %s, stack %s" % (name, stack)
    self.self_id = attrs["self_id"]
    self.error_code = attrs["error_code"]

  def __str__(self):
    return '  <report_error self_id="%s" error_code="%s"/>\n' % (self.self_id, self.error_code)

class msg(list):
  """
  Left-right PDU.
  """

  spec_uri = "http://www.hactrn.net/uris/rpki/left-right-spec/"
  version = 1

  def startElement(self, stack, name, attrs):
    if name == "msg":
      self.version = int(attrs["version"])
      self.type = attrs["type"]
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
            '<msg xmlns="%s"\n'
            '     version="%d"\n'
            '     type="%s">\n'
            '%s</msg>\n'
            % (self.spec_uri, self.version, self.type,
               "".join(map(str, self))))

class sax_handler(sax_utils.handler):
  """
  SAX handler for Left-Right protocol.
  """

  def create_top_level(self, name, attrs):
    assert name == "msg" and attrs["version"] == "1"
    return msg()
