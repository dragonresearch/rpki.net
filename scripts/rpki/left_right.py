# $Id$

import base64, sax_utils, resource_set

# This is still pretty nasty, feels much too complex for a relatively
# simple task.

class base_elt(object):
  """
  Base type for left-right message elements.
  """

  # This isn't quite right, as_number is only multivalue in some elements.
  # Live with it for the moment, fix after code stablizes.

  multivalue = ("peer_contact", "signing_cert", "extension_preference", "resource_class",
                "as_number",   "as_range",   "subset_as_number",   "subset_as_range",
                "ipv4_prefix", "ipv4_range", "subset_ipv4_prefix", "subset_ipv4_range",
                "ipv6_prefix", "ipv6_range", "subset_ipv6_prefix", "subset_ipv6_range")

  b64content = ("peer_ta", "pkcs10_cert_request", "public_key", "signing_cert")

  pdu_objects = ("self", "child", "parent", "bsc", "repository", "route_origin",
                 "list_resources", "report_error")

  def store(self, key, val):
    if key not in self.multivalue:
      assert not hasattr(self, key)
      setattr(self, key, val)
    elif hasattr(self, key):
      getattr(self, key).append(val)
    else:
      setattr(self, key, [val])

  def startElement(self, stack, name, attrs):
    if name not in type_map:
      getattr(self, "handle_" + name)(stack, name, attrs)
    elif type(self) is type_map(name):
      sax_utils.snarf_attribute(self, attrs, self.attributes)
    else:
      elt = type_map[name]()
      stack.append(elt)
      self.store(name, elt)
      elt.startElement(stack, name, attrs)

  def endElement(self, stack, name, text):
    if name in self.b64content:
      self.store(name, base64.b64decode(text))
    if name in type_map:
      stack.pop()

  def boolean_handler(stack, name, attrs):
    setattr(self, name, True)

  handle_publish_world_now = boolean_handler
  handle_reissue = boolean_handler
  handle_rekey = boolean_handler
  handle_revoke = boolean_handler
  handle_run_now = boolean_handler
  handle_suppress_publication = boolean_handler

  def handle_generate_keypair(stack, name, attrs):
    self.boolean_handler(stack, name, attrs)
    sax_utils.snarf_attribute(self, attrs, ("key_type", "hash_alg", "key_length"))

  def id_handler(stack, name, attrs):
    sax_utils.snarf_attribute(self, attrs, "id")

  handle_bsc_link = id_handler
  handle_child_db_id = id_handler
  handle_repository_link = id_handler
  handle_sia_base = id_handler

  def handle_peer_contact(stack, name, attrs):
    self.peer_contact = attrs.getValue("uri").encode("ascii")

  # Mumble, really should be using resource_set types here, more
  # idiocy due to premature optimization

  # Special case for dumb reasons, fix later
  def handle_as_number(stack, name, attrs):
    asn = long(attrs.getValue("asn"))
    if isinstance(self, route_origin_elt):
      assert not hasattr(self, name)
      self.as_number = asn
    else:
      self.store(name, resource_range_as(asn, asn))

  def handle_subset_as_number(stack, name, attrs):
    asn = long(attrs.getValue("asn"))
    self.store(name, resource_range_as(asn, asn))

  def handle_as_range(stack, name, attrs):
    self.store(name, resource_range_as(long(attrs.getValue("min")),
                                       long(attrs.getValue("max"))))

  handle_subset_as_range = handle_as_range

  def handle_ipv4_range(stack, name, attrs):
    self.store(name, resource_range_ipv4(ipaddrs.v4addr(attrs.getValue("min")),
                                         ipaddrs.v4addr(attrs.getValue("max"))))

  handle_subset_ipv4_range = handle_ipv4_range

  def handle_ipv6_range(stack, name, attrs):
    self.store(name, resource_range_ipv6(ipaddrs.v6addr(attrs.getValue("min")),
                                         ipaddrs.v6addr(attrs.getValue("max"))))

  handle_subset_ipv6_range = handle_ipv6_range

  # Haven't written (subset_)?ipv[46]_prefix() handlers yet.  Some of the code for
  # that might belong in resource_set.py instead of here.


class self_elt(base_elt):
  attributes = ("action", "self_id")

class bsc_elt(base_elt):
  attributes = ("action", "self_id", "bsc_id")

class parent_elt(base_elt):
  attributes = ("action", "self_id", "parent_id")

class child_elt(base_elt):
  attributes = ("action", "self_id", "child_id")

class repository_elt(base_elt):
  attributes = ("action", "self_id", "repository_id")

class route_origin_elt(base_elt):
  attributes = ("action", "self_id", "route_origin_id")

class list_resources_elt(base_elt):
  attributes = ("self_id", "child_id")

class report_error_elt(base_elt):
  attributes = ("self_id", "error_code")

class msg(list):
  """
  Left-right PDU.
  """

  spec_uri = "http://www.hactrn.net/uris/rpki/left-right-spec/"
  version = 1

  def startElement(self, stack, name, attrs):
    if name == "msg":
      sax_utils.snarf_attribute(self, attrs, "version", int)
      sax_utils.snarf_attribute(self, attrs, "type")
      assert self.version == 1
    else:
      assert name in type_map
      elt = type_map[name](self)
      self.append(elt)
      stack.append(elt)
      elt.startElement(stack, name, attrs)

  def endElement(self, stack, name, text):
    assert name == "msg"
    assert len(stack) == 1

  def __str__(self):
    return ('<?xml version="1.0" encoding="US-ASCII" ?>\n'
            '<msg xmlns="%s" version="%d" type="%s">\n' \
            % (self.spec_uri, self.version, self.type)
            ) + "".join(map(str,self)) + "</msg>\n"

class sax_handler(sax_utils.handler):
  """
  SAX handler for Left-Right protocol.
  """

  def startElement(self, name, attrs):
    if name == "msg":
      self.stack = [msg()]
    self.stack[-1].startElement(self.stack, name, attrs)

  def endElement(self, name):
    self.stack[-1].endElement(self.stack, name, self.get_text())
    if name == "msg":
      assert len(self.stack) == 1
      self.set_obj(self.stack[0])

type_map = {
  "msg"                  : msg_elt,
  "self"                 : self_elt,
  "child"                : child_elt,
  "parent"               : parent_elt,
  "repository"           : repository_elt,
  "route_origin"         : route_origin_elt,
  "bsc"                  : bsc_elt,
  "list_resources"       : list_resources_elt,
  "report_error"         : report_error_elt,
  "extension_preference" : extension_preference_elt,
  "resource_class"       : resource_class_elt
}
