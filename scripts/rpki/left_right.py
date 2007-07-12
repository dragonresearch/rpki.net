# $Id$

import base64, sax_utils, resource_set

class base_elt(object):
  """
  Base type for left-right message elements.
  """

  content_attr = False
  base64_content = False
  multivalue = ()

  def __init__(self, up=None):
    self.up = up
    for key in self.multivalue:
      setattr(self, key, [])
    
  def store(self, key, val):
    if key in self.multivalue:
      getattr(self, key).append(val)
    else:
      setattr(self, key, val)

  def startElement(self, name, attrs):
    if name == self.name:
      sax_utils.snarf_attribute(self, attrs, self.attributes)

  def endElement(self, name, text):
    if name == self.name and self.content_attr:
      if self.base64_content:
        self.store(self.content_attr, base64.b64decode(text))
      else:
        self.store(self.content_attr, text)

class as_number_elt(base_elt): pass
class bsc_link_elt(base_elt): pass
class child_db_id_elt(base_elt): pass
class extension_preference_elt(base_elt): pass
class generate_keypair_elt(base_elt): pass
class ipv4_prefix_elt(base_elt): pass
class ipv4_range_elt(base_elt): pass
class ipv6_prefix_elt(base_elt): pass
class ipv6_range_elt(base_elt): pass
class pkcs10_cert_request_elt(base_elt): pass
class public_key_elt(base_elt): pass
class publish_world_now_elt(base_elt): pass
class reissue_elt(base_elt): pass
class rekey_elt(base_elt): pass
class repository_link_elt(base_elt): pass
class revoke_elt(base_elt): pass
class run_now_elt(base_elt): pass
class sia_base_elt(base_elt): pass
class signing_cert_elt(base_elt): pass
class suppress_publication_elt(base_elt): pass
class ta_elt(base_elt): pass
class uri_elt(base_elt): pass

class self_elt(base_elt):
  name = "self"
  attributes = ("action", "self_id")
  elements = { "extension_preference" : extension_preference_elt,
               "rekey"                : rekey_elt,
               "revoke"               : revoke_elt,
               "run_now"              : run_now_elt,
               "publish_world_now"    : publish_world_now_elt }
  multivalue = ("extension_preference",)

class bsc_elt(base_elt):
  name = "biz_signing_context"
  attributes = ("action", "self_id", "biz_signing_context_id")
  elements = { "signing_cert"         : signing_cert_elt,
               "generate_keypair"     : generate_keypair_elt,
               "pkcs10_cert_request"  : pkcs10_cert_request_elt,
               "public_key"           : public_key_elt }
  multivalue = ("signing_cert",)
               
class parent_elt(base_elt):
  name = "parent"
  attributes = ("action", "self_id", "parent_id")
  elements = { "ta"                   : ta_elt,
               "uri"                  : uri_elt,
               "sia_base"             : sia_base_elt,
               "biz_signing_context"  : bsc_link_elt,
               "repository"           : repository_link_elt,
               "rekey"                : rekey_elt,
               "reissue"              : reissue_elt,
               "revoke"               : revoke_elt }

class child_elt(base_elt):
  name = "child"
  attributes = ("action", "self_id", "child_id")
  elements = { "ta"                   : ta_elt,
               "biz_signing_context"  : bsc_link_elt,
               "child_db_id"          : child_db_id_elt,
               "reissue"              : reissue_elt }

class repository_elt(base_elt):
  name = "repository"
  attributes = ("action", "self_id", "repository_id")
  elements = { "ta"                   : ta_elt,
               "uri"                  : uri_elt,
               "biz_signing_context"  : bsc_link_elt }

class route_origin_elt(base_elt):
  name = "route_origin"
  attributes = ("action", "self_id", "route_origin_id")
  elements = { "suppress_publication" : suppress_publication_elt,
               "as_number"            : as_number_elt,
               "ipv4_prefix"          : ipv4_prefix_elt,
               "ipv4_range"           : ipv4_range_elt,
               "ipv6_prefix"          : ipv6_prefix_elt,
               "ipv6_range"           : ipv6_range_elt }
  multivalue = ("ipv4_prefix", "ipv4_range", "ipv6_prefix", "ipv6_range")


class list_resources_elt(base_elt):
  def startElement(self, name, attrs):
    sax_utils.snarf_attribute(self, attrs, ("self_id", "child_id"))

class report_error_elt(base_elt):
  def startElement(self, name, attrs):
    sax_utils.snarf_attribute(self, attrs, ("self_id", "error_code"))

class msg(list):
  """
  Left-right PDU.
  """

  spec_uri = "http://www.hactrn.net/uris/rpki/left-right-spec/"
  version = 1

  dispatch = {
    "self"                : self_elt,
    "child"               : child_elt,
    "parent"              : parent_elt,
    "repository"          : repository_elt,
    "route_origin"        : route_origin_elt,
    "biz_signing_context" : bsc_elt,
    "list_resources"      : list_resources_elt,
    "report_error"        : report_error_elt }

  def startElement(self, name, attrs):
    if name == "msg":
      sax_utils.snarf_attribute(self, attrs, "version", int)
      sax_utils.snarf_attribute(self, attrs, "type")
      assert self.version == 1
    else:
      if name in self.dispatch:
        self.append(self.dispatch[name](self))
      self[-1].startElement(name, attrs)

  def endElement(self, name, text):
    self[-1].endElement(name, text)

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
      self.set_obj(msg())
    self.obj.startElement(name, attrs)

  def endElement(self, name):
    self.obj.endElement(name, self.get_text())
