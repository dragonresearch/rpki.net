# $Id$
#
# Copyright (C) 2014  Dragon Research Labs ("DRL")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL DRL BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
Wrapper around lxml to extract various useful data and methods
from an XML-format RelaxNG schema.
"""

import lxml.etree

class RelaxNGParser(object):
  """
  Parse schema, extract XML namespace and protocol version (if any).
  Method calls are just passed along to the parsed RelaxNG schema.
  """

  def __init__(self, text):
    xml = lxml.etree.fromstring(text)
    self.schema = lxml.etree.RelaxNG(xml)
    ns = xml.get("ns")
    self.xmlns = "{" + ns + "}"
    self.nsmap = { None : ns }
    x = xml.xpath("ns0:define[@name = 'version']/ns0:value",
                  namespaces = dict(ns0 = "http://relaxng.org/ns/structure/1.0"))
    if len(x) == 1:
      self.version = x[0].text

  def __getattr__(self, name):
    return getattr(self.schema, name)
