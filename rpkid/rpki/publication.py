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

"""RPKI "publication" protocol."""

import base64, lxml.etree, time, traceback, os
import rpki.resource_set, rpki.x509, rpki.sql, rpki.exceptions, rpki.xml_utils
import rpki.https, rpki.up_down, rpki.relaxng, rpki.sundial, rpki.log, rpki.roa

publication_xmlns = "http://www.hactrn.net/uris/rpki/publication-spec/"
publication_nsmap = { None : publication_xmlns }

class data_elt(rpki.xml_utils.base_elt):
  """Virtual class for publication protocol PDUs."""

  xmlns = publication_xmlns
  nsmap = publication_nsmap

class client_elt(rpki.xml_utils.data_elt, rpki.sql.sql_persistant):
  """<client/> element."""

  xmlns = publication_xmlns
  nsmap = publication_nsmap

  element_name = "client"
  attributes = ("action", "tag", "client_id", "base_uri")
  elements = ("bpki_cert", "bpki_glue")

  sql_template = rpki.sql.template("client", "client_id", "base_uri", ("bpki_cert", rpki.x509.X509), ("bpki_glue", rpki.x509.X509))

  base_uri  = None
  bpki_cert = None
  bpki_glue = None

  clear_https_ta_cache = False

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

  def serve_post_save_hook(self, q_pdu, r_pdu):
    """Extra server actions for client_elt."""
    if self.clear_https_ta_cache:
      self.gctx.clear_https_ta_cache()
      self.clear_https_ta_cache = False

  def serve_fetch_one(self):
    """Find the client object on which a get, set, or destroy method
    should operate.
    """
    r = self.sql_fetch(self.gctx, self.client_id)
    if r is None:
      raise rpki.exceptions.NotFound
    return r

  def serve_fetch_all(self):
    """Find client objects on which a list method should operate."""
    return self.sql_fetch_all(self.gctx)

  def serve_dispatch(self, r_msg, client):
    """Action dispatch handler."""
    if client is not None:
      raise rpki.exceptions.BadQuery, "Client query received on control channel"
    rpki.xml_utils.data_elt.serve_dispatch(self, r_msg)

  def check_allowed_uri(self, uri):
    if not uri.startswith(self.base_uri):
      raise rpki.exceptions.ForbiddenURI

class publication_object_elt(data_elt):
  """Virtual class for publishable objects.  These have very similar
  syntax, differences lie in underlying datatype and methods.
  """

  attributes = ("action", "tag", "client_id", "uri")
  payload = None

  def startElement(self, stack, name, attrs):
    """Handle a publishable element."""
    assert name == self.element_name, "Unexpected name %s, stack %s" % (name, stack)
    self.read_attrs(attrs)

  def endElement(self, stack, name, text):
    """Handle a publishable element element."""
    assert name == self.element_name, "Unexpected name %s, stack %s" % (name, stack)
    if text:
      self.payload = self.payload_type(Base64 = text)
    stack.pop()

  def toXML(self):
    """Generate XML element for publishable object."""
    elt = self.make_elt()
    if self.payload:
      elt.text = base64.b64encode(self.payload.get_DER())
    return elt

  def serve_dispatch(self, r_msg, client):
    """Action dispatch handler."""
    if client is None:
      raise rpki.exceptions.BadQuery, "Control query received on client channel"
    dispatch = { "publish"  : self.serve_publish,
                 "withdraw" : self.serve_withdraw }
    if self.action not in dispatch:
      raise rpki.exceptions.BadQuery, "Unexpected query: action %s" % self.action
    client.check_allowed_uri(self.uri)
    dispatch[self.action]()
    r_pdu = self.__class__()
    r_pdu.action = self.action
    r_pdu.tag = self.tag
    r_pdu.uri = self.uri
    r_msg.append(r_pdu)

  def serve_publish(self):
    """Publish an object."""
    rpki.log.info("Publishing %s as %s" % (repr(self.payload), repr(self.uri)))
    filename = self.uri_to_filename()
    dirname = os.path.dirname(filename)
    if not os.path.isdir(dirname):
      os.makedirs(dirname)
    f = open(filename, "wb")
    f.write(self.payload.get_DER())
    f.close()

  def serve_withdraw(self):
    """Withdraw an object."""
    rpki.log.info("Withdrawing %s from at %s" % (repr(self.payload), repr(self.uri)))
    os.remove(self.uri_to_filename())

  def uri_to_filename(self):
    """Convert a URI to a local filename."""
    if not self.uri.startswith("rsync://"):
      raise rpki.exceptions.BadURISyntax
    filename = self.gctx.publication_base + self.uri[len("rsync://"):]
    if filename.find("//") >= 0 or filename.find("/../") >= 0 or filename.endswith("/.."):
      raise rpki.exceptions.BadURISyntax
    return filename

class certificate_elt(publication_object_elt):
  """<certificate/> element."""

  element_name = "certificate"
  payload_type = rpki.x509.X509

class crl_elt(publication_object_elt):
  """<crl/> element."""

  element_name = "crl"
  payload_type = rpki.x509.CRL
  
class manifest_elt(publication_object_elt):
  """<manifest/> element."""

  element_name = "manifest"
  payload_type = rpki.x509.SignedManifest

class roa_elt(publication_object_elt):
  """<roa/> element."""

  element_name = "roa"
  payload_type = rpki.x509.ROA

## @var obj2elt
# Map of data types to publication element wrapper types

obj2elt = dict((e.payload_type, e) for e in (certificate_elt, crl_elt, manifest_elt, roa_elt))

class report_error_elt(rpki.xml_utils.base_elt):
  """<report_error/> element."""

  xmlns = publication_xmlns
  nsmap = publication_nsmap

  element_name = "report_error"
  attributes = ("tag", "error_code")

  def startElement(self, stack, name, attrs):
    """Handle <report_error/> element."""
    assert name == self.element_name, "Unexpected name %s, stack %s" % (name, stack)
    self.read_attrs(attrs)

  def toXML(self):
    """Generate <report_error/> element."""
    return self.make_elt()

  @classmethod
  def from_exception(cls, exc):
    """Generate a <report_error/> element from an exception."""
    self = cls()
    self.error_code = exc.__class__.__name__
    return self

class msg(rpki.xml_utils.msg):
  """Publication PDU."""

  xmlns = publication_xmlns
  nsmap = publication_nsmap

  ## @var version
  # Protocol version
  version = 1

  ## @var pdus
  # Dispatch table of PDUs for this protocol.
  pdus = dict((x.element_name, x)
              for x in (client_elt, certificate_elt, crl_elt, manifest_elt, roa_elt, report_error_elt))

  def serve_top_level(self, gctx, client):
    """Serve one msg PDU."""
    if self.type != "query":
      raise rpki.exceptions.BadQuery, "Message type is not query"
    r_msg = self.__class__()
    r_msg.type = "reply"
    for q_pdu in self:
      q_pdu.gctx = gctx
      q_pdu.serve_dispatch(r_msg, client)
    return r_msg

class sax_handler(rpki.xml_utils.sax_handler):
  """SAX handler for publication protocol."""

  pdu = msg
  name = "msg"
  version = "1"

class cms_msg(rpki.x509.XML_CMS_object):
  """Class to hold a CMS-signed publication PDU."""

  encoding = "us-ascii"
  schema = rpki.relaxng.publication
  saxify = sax_handler.saxify
