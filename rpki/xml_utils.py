# $Id$
#
# Copyright (C) 2009-2012  Internet Systems Consortium ("ISC")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.
#
# Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
XML utilities.
"""

import logging
import lxml.etree
import rpki.exceptions

logger = logging.getLogger(__name__)


class base_elt(object):
  """
  Virtual base class for XML message elements.  The left-right and
  publication_control protocols use this.
  """

  ## @var attributes
  # XML attributes for this element.
  attributes = ()

  ## @var elements
  # XML elements contained by this element.
  elements = ()

  ## @var booleans
  # Boolean attributes (value "yes" or "no") for this element.
  booleans = ()

  ## @var text_attribute
  # Name of class attribute that tells us where to put text values, if any.
  text_attribute = None

  @classmethod
  def fromXML(cls, elt):
    """
    First cut at non-SAX message unpacker.  This will probably change.
    """

    self = cls()

    for key in self.attributes:
      val = elt.get(key, None)
      if val is not None:
        val = val.encode("ascii")
        if isinstance(self.attributes, dict) and self.attributes[key] is not None:
          val = self.attributes[key](val)
        elif val.isdigit() and not key.endswith("_handle"):
          val = long(val)
      setattr(self, key, val)
    for key in self.booleans:
      setattr(self, key, elt.get(key, False))

    # This test could go in an extended method in text_elt.  Then
    # again, perhaps spreading the logic in as many places as we
    # possibly can is not really helping matters....

    if self.text_attribute is not None:
      setattr(self, self.text_attribute, elt.text)

    # In the long run, we probably want the key for that to include
    # the namespace, but that would break the current .toXML() code,
    # so kludge it for now.

    for b64 in elt:
      assert b64.tag.startswith(self.xmlns)
      ename = b64.tag[len(self.xmlns):]
      etype = self.elements[ename]
      setattr(self, ename, etype(Base64 = b64.text))

    return self

  def toXML(self):
    """
    Default toXML() element generator.
    """

    return self.make_elt()

  def read_attrs(self, attrs):
    """
    Template-driven attribute reader.
    """

  def make_elt(self):
    """
    XML element constructor.
    """

    elt = lxml.etree.Element(self.xmlns + self.element_name, nsmap = self.nsmap)
    for key in self.attributes:
      val = getattr(self, key, None)
      if val is not None:
        elt.set(key, str(val))
    for key in self.booleans:
      if getattr(self, key, False):
        elt.set(key, "yes")
    return elt

  def make_b64elt(self, elt, name, value):
    """
    Constructor for Base64-encoded subelement.
    """

    if value is not None and not value.empty():
      lxml.etree.SubElement(elt, self.xmlns + name, nsmap = self.nsmap).text = value.get_Base64()

  def __str__(self):
    """
    Convert a base_elt object to string format.
    """

    return lxml.etree.tostring(self.toXML(), pretty_print = True, encoding = "us-ascii")

  @classmethod
  def make_pdu(cls, **kargs):
    """
    Generic PDU constructor.
    """

    self = cls()
    for k, v in kargs.items():
      if isinstance(v, bool):
        v = 1 if v else 0
      setattr(self, k, v)
    return self

class text_elt(base_elt):
  """
  Virtual base class for XML message elements that contain text.
  """

  def toXML(self):
    """
    Insert text into generated XML.
    """

    elt = self.make_elt()
    elt.text = getattr(self, self.text_attribute) or None
    return elt

class data_elt(base_elt):
  """
  Virtual base class for PDUs that map to SQL objects.  These objects
  all implement the create/set/get/list/destroy action attribute.
  """

  def toXML(self):
    """
    Default element generator for SQL-based objects.  This assumes
    that sub-elements are Base64-encoded DER objects.
    """

    elt = self.make_elt()
    for i in self.elements:
      self.make_b64elt(elt, i, getattr(self, i, None))
    return elt

  def make_reply(self, r_pdu = None):
    """
    Construct a reply PDU.
    """

    if r_pdu is None:
      r_pdu = self.__class__()
      self.make_reply_clone_hook(r_pdu)
      handle_name = self.element_name + "_handle"
      setattr(r_pdu, handle_name, getattr(self, handle_name, None))
    else:
      self.make_reply_clone_hook(r_pdu)
      for b in r_pdu.booleans:
        setattr(r_pdu, b, False)
    r_pdu.action = self.action
    r_pdu.tag = self.tag
    return r_pdu

  def make_reply_clone_hook(self, r_pdu):
    """
    Overridable hook.
    """

    pass

  def serve_fetch_one(self):
    """
    Find the object on which a get, set, or destroy method should
    operate.
    """

    r = self.serve_fetch_one_maybe()
    if r is None:
      raise rpki.exceptions.NotFound
    return r

  def serve_pre_save_hook(self, q_pdu, r_pdu, cb, eb):
    """
    Overridable hook.
    """

    cb()

  def serve_post_save_hook(self, q_pdu, r_pdu, cb, eb):
    """
    Overridable hook.
    """

    cb()

  def serve_create(self, r_msg, cb, eb):
    """
    Handle a create action.
    """

    r_pdu = self.make_reply()

    def one():
      self.sql_store()
      setattr(r_pdu, self.sql_template.index, getattr(self, self.sql_template.index))
      self.serve_post_save_hook(self, r_pdu, two, eb)

    def two():
      r_msg.append(r_pdu)
      cb()

    oops = self.serve_fetch_one_maybe()
    if oops is not None:
      raise rpki.exceptions.DuplicateObject("Object already exists: %r[%r] %r[%r]" % (self, getattr(self, self.element_name + "_handle"),
                                                                                      oops, getattr(oops, oops.element_name + "_handle")))

    self.serve_pre_save_hook(self, r_pdu, one, eb)

  def serve_set(self, r_msg, cb, eb):
    """
    Handle a set action.
    """

    db_pdu = self.serve_fetch_one()
    r_pdu = self.make_reply()
    for a in db_pdu.sql_template.columns[1:]:
      v = getattr(self, a, None)
      if v is not None:
        setattr(db_pdu, a, v)
    db_pdu.sql_mark_dirty()

    def one():
      db_pdu.sql_store()
      db_pdu.serve_post_save_hook(self, r_pdu, two, eb)

    def two():
      r_msg.append(r_pdu)
      cb()

    db_pdu.serve_pre_save_hook(self, r_pdu, one, eb)

  def serve_get(self, r_msg, cb, eb):
    """
    Handle a get action.
    """

    r_pdu = self.serve_fetch_one()
    self.make_reply(r_pdu)
    r_msg.append(r_pdu)
    cb()

  def serve_list(self, r_msg, cb, eb):
    """
    Handle a list action for non-self objects.
    """

    for r_pdu in self.serve_fetch_all():
      self.make_reply(r_pdu)
      r_msg.append(r_pdu)
    cb()

  def serve_destroy_hook(self, cb, eb):
    """
    Overridable hook.
    """

    cb()

  def serve_destroy(self, r_msg, cb, eb):
    """
    Handle a destroy action.
    """

    def done():
      db_pdu.sql_delete()
      r_msg.append(self.make_reply())
      cb()
    db_pdu = self.serve_fetch_one()
    db_pdu.serve_destroy_hook(done, eb)

  def serve_dispatch(self, r_msg, cb, eb):
    """
    Action dispatch handler.
    """

    method = getattr(self, "serve_" + self.action, None)
    if method is None:
      raise rpki.exceptions.BadQuery("Unexpected query: action %s" % self.action)
    method(r_msg, cb, eb)

  def unimplemented_control(self, *controls):
    """
    Uniform handling for unimplemented control operations.
    """

    unimplemented = [x for x in controls if getattr(self, x, False)]
    if unimplemented:
      raise rpki.exceptions.NotImplementedYet("Unimplemented control %s" % ", ".join(unimplemented))

class msg(list):
  """
  Generic top-level PDU.
  """

  def __str__(self):
    """
    Convert msg object to string.
    """

    return lxml.etree.tostring(self.toXML(), pretty_print = True, encoding = "us-ascii")

  def toXML(self):
    """
    Generate top-level PDU.
    """

    elt = lxml.etree.Element(self.xmlns + "msg", nsmap = self.nsmap, version = str(self.version), type = self.type)
    elt.extend(i.toXML() for i in self)
    return elt

  @classmethod
  def query(cls, *args):
    """
    Create a query PDU.
    """

    self = cls(args)
    self.type = "query"
    return self

  @classmethod
  def reply(cls, *args):
    """
    Create a reply PDU.
    """

    self = cls(args)
    self.type = "reply"
    return self

  def is_query(self):
    """
    Is this msg a query?
    """

    return self.type == "query"

  def is_reply(self):
    """
    Is this msg a reply?
    """

    return self.type == "reply"

  @classmethod
  def fromXML(cls, elt):
    """
    First cut at non-SAX message unpacker.  This will probably change.
    """

    assert cls.version == int(elt.get("version"))
    self = cls()
    self.type = elt.get("type")

    # This could be simplified by including the namespace name in the .pdus[] key.

    for sub in elt:
      assert sub.tag.startswith(self.xmlns)
      self.append(self.pdus[sub.tag[len(self.xmlns):]].fromXML(sub))

    return self
