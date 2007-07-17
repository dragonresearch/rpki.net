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

class extension_preference_elt(base_elt):
  """
  Container for extension preferences.
  """

  def startElement(self, stack, name, attrs):
    assert name == "extension_preference"
    self.name = attrs["name"]

  def endElement(self, stack, name, text):
    self.value = text
    stack.pop()

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
      stack.append(prefs)
      pref.startElement(stack, name, attrs)
    elif name in self.booleans:
      setattr(self, name, True)
    else:
      assert name == "self"
      self.action = attrs["action"]
      self.self_id = attrs.get("self_id")

  def endElement(self, stack, name, text):
    if name not in self.booleans:
      assert name == "self"
      stack.pop()

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
      assert name == "bsc"
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
    else:
      assert name == "bsc"
      stack.pop()

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
      assert name == "parent"
      self.action = attrs["action"]
      self.self_id = attrs["self_id"]
      self.parent_id = attrs.get("parent_id")

  def endElement(self, stack, name, text):
    if name == "peer_ta":
      self.peer_ta = base64.b64decode(text)
    elif name not in self.booleans + self.ids + self.uris:
      assert name == "parent"
      stack.pop()

class child_elt(base_elt):

  ids = ("bsc_link", "child_db_id")
  booleans = ("reissue")

  rekey = False
  reissue = False
  revoke = False

  def startElement(self, stack, name, attrs):
    if name in self.ids:
      setattr(self, name, attrs["id"])
    elif name in self.booleans:
      setattr(self, name, True)
    elif name != "peer_ta":
      assert name == "child"
      self.action = attrs["action"]
      self.self_id = attrs["self_id"]
      self.child_id = attrs.get("child_id")

  def endElement(self, stack, name, text):
    if name == "peer_ta":
      self.peer_ta = base64.b64decode(text)
    elif name not in self.booleans + self.ids:
      assert name == "child"
      stack.pop()

class repository_elt(base_elt):

  def startElement(self, stack, name, attrs):
    if name == "bsc_link":
      self.bsc_link = attrs["id"]
    elif name == "peer_contact":
      self.peer_contact = attrs["uri"]
    elif name != "peer_ta":
      assert name == "repository"
      self.action = attrs["action"]
      self.self_id = attrs["self_id"]
      self.repository_id = attrs.get("repository_id")

  def endElement(self, stack, name, text):
    if name == "peer_ta":
      self.peer_ta = base64.b64decode(text)
    elif name not in ("bsc_link", "peer_contact"):
      assert name == "repository"
      stack.pop()

class route_origin_elt(base_elt):

  suppress_publication = False
  ipv4 = None
  ipv6 = None

  def startElement(self, stack, name, attrs):
    if name == "suppress_publication":
      self.suppress_publication = True
    elif name == "resources":
      self.asn = attrs["asn"]
      if "ipv4" in attrs:
        self.ipv4 = resource_set.resource_set_ipv4(attrs["ipv4"])
      if "ipv6" in attrs:
        self.ipv6 = resource_set.resource_set_ipv6(attrs["ipv6"])
    else:
      assert name == "route_origin"
      self.action = attrs["action"]
      self.self_id = attrs["self_id"]
      self.route_origin_id = attrs.get("route_origin_id")

  def endElement(self, stack, name, text):
    if name not in ("suppress_publication", "resources"):
      assert name == "route_origin"
      stack.pop()

class resource_class_elt(base_elt):

  def startElement(self, stack, name, attrs):
    assert name == "resource_class"
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
      assert name == "list_resources"
      self.self_id = attrs["self_id"]
      self.child_id = attrs.get("child_id")

class report_error_elt(base_elt):

  def startElement(self, stack, name, attrs):
    assert name == "report_error"
    self.self_id = attrs["self_id"]
    self.error_code = attrs["error_code"]

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
    assert name == "msg"
    assert len(stack) == 1
    stack.pop()

  def __str__(self):
    return ('<?xml version="1.0" encoding="US-ASCII" ?>\n'
            '<msg xmlns="%s" version="%d" type="%s">\n'
            '%s</msg>\n'
            % (self.spec_uri, self.version, self.type,
               "".join(map(str, self))))

class sax_handler(sax_utils.handler):
  """
  SAX handler for Left-Right protocol.
  """

  def create_top_level(self, name, attrs):
    assert name == "msg" and attrs["version"] == "1"
    return msg_elt()
