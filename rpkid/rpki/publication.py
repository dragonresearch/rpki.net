# $Id$

# Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
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

"""RPKI "publication" protocol.

At the moment this module imports and tweaks classes from
rpki.left_right.  The code in question should be refactored at some
point to make the imports cleaner, but it's faster to write it this
way and see which things I end up using before spending time on
refactoring stuff I don't really need....
"""

import base64, lxml.etree, time, traceback, os
import rpki.resource_set, rpki.x509, rpki.sql, rpki.exceptions, rpki.sax_utils
import rpki.https, rpki.up_down, rpki.relaxng, rpki.sundial, rpki.log, rpki.roa
import rpki.left_right

publication_xmlns = "http://www.hactrn.net/uris/rpki/publication-spec/"
publication_nsmap = { None : publication_xmlns }

class data_elt(rpki.left_right.base_elt):
  """Virtual class for top-level publication protocol data elements.

  This is a placeholder.  It will probably end up being a mixin that
  uses rpki.sql.sql_persistant, just like its counterpart in
  rpki.left_right, but wait and see.
  """

  xmlns = publication_xmlns
  nsmap = publication_nsmap

class client_elt(data_elt):
  """<client/> element."""

  element_name = "client"
  attributes = ("action", "tag", "client_id", "base_uri")
  elements = ("bpki_cert", "bpki_glue")

  bpki_cert = None
  bpki_glue = None

  def startElement(self, stack, name, attrs):
    """Handle <client/> element."""
    if name not in ("bpki_cert", "bpki_glue"):
      assert name == self.element_name, "Unexpected name %s, stack %s" % (name, stack)
      self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    """Handle <client/> element."""
    if name == "bpki_cert":
      self.bpki_cert = rpki.x509.X509(Base64 = text)
      self.clear_https_ta_cache = True
    elif name == "bpki_glue":
      self.bpki_glue = rpki.x509.X509(Base64 = text)
      self.clear_https_ta_cache = True
    else:
      assert name == self.element_name, "Unexpected name %s, stack %s" % (name, stack)
      stack.pop()

  def toXML(self):
    """Generate <client/> element."""
    elt = self.make_elt()
    if self.bpki_cert and not self.bpki_cert.empty():
      self.make_b64elt(elt, "bpki_cert", self.bpki_cert.get_DER())
    if self.bpki_glue and not self.bpki_glue.empty():
      self.make_b64elt(elt, "bpki_glue", self.bpki_glue.get_DER())
    return elt

class report_error_elt(rpki.left_right.report_error_elt):
  """<report_error/> element.

  For now this is identical to its left_right equivilent.
  """

  pass

class msg(rpki.left_right.msg):
  """Publication PDU."""

  xmlns = publication_xmlns
  nsmap = publication_nsmap

  ## @var version
  # Protocol version
  version = 1

  ## @var pdus
  # Dispatch table of PDUs for this protocol.
  pdus = dict((x.element_name, x)
              for x in (client_elt, report_error_elt))

class sax_handler(rpki.sax_utils.handler):
  """SAX handler for publication protocol."""

  pdu = msg
  name = "msg"
  version = "1"

class cms_msg(rpki.x509.XML_CMS_object):
  """Class to hold a CMS-signed publication PDU."""

  encoding = "us-ascii"
  schema = rpki.relaxng.publication
  saxify = sax_handler.saxify
