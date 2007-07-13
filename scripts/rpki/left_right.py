# $Id$

import base64, sax_utils, resource_set

Broken = True

assert ! Broken

# This still isn't right, although it's not as broken as it was.  I
# don't see any sane way to avoid keeping a stack of objects under
# construction, probably in our sax_handler object.  Passing SAX
# events along to the current object is ok, but passing every SAX
# event down through the chain of objects under construction is just
# nuts.  So probably want push and pop methods in the sax_handler so
# that the current object can create a child and push it onto the
# stack, and so that a current object can pop itself off the stack.

class base_elt(object):
  """
  Base type for left-right message elements.
  """

  def __init__(self, up=None):
    self.up = up
    for key in self.multivalue:
      setattr(self, key, [])
    
  multivalue = ("peer_contact", "signing_cert", "extension_preference", "resource_class",
                "as_number",   "as_range",   "subset_as_number",   "subset_as_range",
                "ipv4_prefix", "ipv4_range", "subset_ipv4_prefix", "subset_ipv4_range",
                "ipv6_prefix", "ipv6_range", "subset_ipv6_prefix", "subset_ipv6_range")

  def store(self, key, val):
    if key in self.multivalue:
      getattr(self, key).append(val)
    else:
      setattr(self, key, val)

  b64content = ("peer_ta", "pkcs10_cert_request", "public_key", "signing_cert")

  def endElement(self, name, text):
    if name in self.b64content:
      self.store(name, base64.b64decode(text))

  pdu_objects = ("self", "child", "parent", "bsc", "repository", "route_origin",
                 "list_resources", "report_error")

  def startElement(self, name, attrs):
    if name in pdu_objects:
      sax_utils.snarf_attribute(self, attrs, self.attributes)
    else:
      getattr(self, "handle_" + name)(name, attrs)

  # handle_xxx methods not yet written

class self_elt(base_elt):
  attributes = ("action", "self_id")

class bsc_elt(base_elt):
  attributes = ("action", "self_id", "biz_signing_context_id")

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

  dispatch = {
    "self"           : self_elt,
    "child"          : child_elt,
    "parent"         : parent_elt,
    "repository"     : repository_elt,
    "route_origin"   : route_origin_elt,
    "bsc"            : bsc_elt,
    "list_resources" : list_resources_elt,
    "report_error"   : report_error_elt }

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


# bsc_link                              ; attribute-only element
# child_db_id                           ; attribute-only element
# repository_link                       ; attribute-only element
# sia_base                              ; attribute-only element
# 
# as_number                             ; attribute-only element, single/multi depending on context (sigh)
# as_range                              ; attribute-only element, multi
# ipv4_prefix                           ; attribute-only element, multi
# ipv4_range                            ; attribute-only element, multi
# ipv6_prefix                           ; attribute-only element, multi
# ipv6_range                            ; attribute-only element, multi
# peer_contact                          ; attribute-only element, multi
# subset_as_number                      ; attribute-only element, multi
# subset_as_range                       ; attribute-only element, multi
# subset_ipv4_prefix                    ; attribute-only element, multi
# subset_ipv4_range                     ; attribute-only element, multi
# subset_ipv6_prefix		        ; attribute-only element, multi
# subset_ipv6_range		        ; attribute-only element, multi
# 
# peer_ta				; base64 element
# pkcs10_cert_request			; base64 element
# public_key				; base64 element
# signing_cert				; base64 element, multi
# 
# extension_preference			; container element, multi
# resource_class			; container element, multi
# 
# generate_keypair                      ; attribute-only control element
# publish_world_now			; empty control element
# reissue				; empty control element
# rekey					; empty control element
# revoke				; empty control element
# run_now				; empty control element
# suppress_publication			; empty control element
# 
# msg					; pdu
# bsc					; pdu element
# child					; pdu element
# list_resources			; pdu element
# parent				; pdu element
# report_error				; pdu element
# repository				; pdu element
# route_origin				; pdu element
# self					; pdu element
