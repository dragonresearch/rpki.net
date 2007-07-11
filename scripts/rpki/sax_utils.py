# $Id$

import xml.sax

def snarf(obj, attrs, key, func=None):
  """
  Utility function to consolidate the steps needed to extract a field
  from the SAX XML parse and insert it as an object attribute of the
  same name.
  """

  try:
    val = attrs.getValue(key).encode("ascii")
    if func:
      val = func(val)
  except KeyError:
    val = None
  setattr(obj, key, val)

class handler(xml.sax.handler.ContentHandler):
  """
  SAX handler for RPKI protocols.  Handles a few tasks
  common to all of these protocols, needs to be subtyped
  to handle protocol-specific details.
  """

  def __init__(self):
    self.text = ""
    self.obj = None

  def startElementNS(self, name, qname, attrs):
    return self.startElement(name[1], attrs)

  def endElementNS(self, name, qname):
    return self.endElement(name[1])

  def characters(self, content):
    self.text += content

  def get_text(self):
    val = self.text
    self.text = ""
    return val

  def set_obj(self, obj):
    assert self.obj is None
    self.obj = obj
