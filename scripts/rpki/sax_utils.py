# $Id$

import xml.sax

class handler(xml.sax.handler.ContentHandler):
  """
  SAX handler for RPKI protocols.
  """

  def __init__(self):
    self.text = ""
    self.stack = []

  def startElementNS(self, name, qname, attrs):
    return self.startElement(name[1], attrs)

  def endElementNS(self, name, qname):
    return self.endElement(name[1])

  def characters(self, content):
    self.text += content

  def startElement(self, name, attrs):
    a = dict()
    for k,v in attrs.items():
      a[k.encode("ascii")] = v.encode("ascii")
    if len(self.stack) == 0:
      assert not hasattr(self, "result")
      self.result = self.create_top_level(name, a)
      self.stack.append(self.result)
    self.stack[-1].startElement(self.stack, name, a)

  def endElement(self, name):
    text = self.text.encode("ascii").strip()
    self.text = ""
    self.stack[-1].endElement(self.stack, name, text)
