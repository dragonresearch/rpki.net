"""RPKI "publication" protocol.

$Id$

Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import base64, lxml.etree, time, traceback, os
import rpki.resource_set, rpki.x509, rpki.sql, rpki.exceptions, rpki.xml_utils
import rpki.https, rpki.up_down, rpki.relaxng, rpki.sundial, rpki.log, rpki.roa

class publication_namespace(object):
  """XML namespace parameters for publication protocol."""

  xmlns = "http://www.hactrn.net/uris/rpki/publication-spec/"
  nsmap = { None : xmlns }

class control_elt(rpki.xml_utils.data_elt, rpki.sql.sql_persistant, publication_namespace):
  """Virtual class for control channel objects."""

  def serve_dispatch(self, r_msg, client, cb):
    """Action dispatch handler.  This needs special handling because
    we need to make sure that this PDU arrived via the control channel.
    """
    if client is not None:
      raise rpki.exceptions.BadQuery, "Control query received on client channel"
    rpki.xml_utils.data_elt.serve_dispatch(self, r_msg, cb)

class config_elt(control_elt):
  """<config/> element.  This is a little weird because there should
  never be more than one row in the SQL config table, but we have to
  put the BPKI CRL somewhere and SQL is the least bad place available.

  So we reuse a lot of the SQL machinery, but we nail config_id at 1,
  we don't expose it in the XML protocol, and we only support the get
  and set actions.
  """

  attributes = ("action", "tag")
  element_name = "config"
  elements = ("bpki_crl",)

  sql_template = rpki.sql.template("config", "config_id", ("bpki_crl", rpki.x509.CRL))

  wired_in_config_id = 1

  def startElement(self, stack, name, attrs):
    """StartElement() handler for config object.  This requires
    special handling because of the weird way we treat config_id.
    """
    control_elt.startElement(self, stack, name, attrs)
    self.config_id = self.wired_in_config_id

  @classmethod
  def fetch(cls, gctx):
    """Fetch the config object from SQL.  This requires special
    handling because of the weird way we treat config_id.
    """
    return cls.sql_fetch(gctx, cls.wired_in_config_id)

  def serve_set(self, r_msg, cb):
    """Handle a set action.  This requires special handling because
    config doesn't support the create method.
    """
    if self.sql_fetch(self.gctx, self.config_id) is None:
      control_elt.serve_create(self, r_msg, cb)
    else:
      control_elt.serve_set(self, r_msg, cb)

  def serve_fetch_one(self):
    """Find the config object on which a get or set method should
    operate.
    """
    r = self.sql_fetch(self.gctx, self.config_id)
    if r is None:
      raise rpki.exceptions.NotFound
    return r

class client_elt(control_elt):
  """<client/> element."""

  element_name = "client"
  attributes = ("action", "tag", "client_id", "base_uri")
  elements = ("bpki_cert", "bpki_glue")

  sql_template = rpki.sql.template("client", "client_id", "base_uri", ("bpki_cert", rpki.x509.X509), ("bpki_glue", rpki.x509.X509))

  base_uri  = None
  bpki_cert = None
  bpki_glue = None

  clear_https_ta_cache = False

  def endElement(self, stack, name, text):
    """Handle subelements of <client/> element.  These require special
    handling because modifying them invalidates the HTTPS trust anchor
    cache.
    """
    control_elt.endElement(self, stack, name, text)
    if name in self.elements:
      self.clear_https_ta_cache = True

  def serve_post_save_hook(self, q_pdu, r_pdu, cb):
    """Extra server actions for client_elt."""
    if self.clear_https_ta_cache:
      self.gctx.clear_https_ta_cache()
      self.clear_https_ta_cache = False
    cb()

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

  def check_allowed_uri(self, uri):
    if not uri.startswith(self.base_uri):
      raise rpki.exceptions.ForbiddenURI

class publication_object_elt(rpki.xml_utils.base_elt, publication_namespace):
  """Virtual class for publishable objects.  These have very similar
  syntax, differences lie in underlying datatype and methods.  XML
  methods are a little different from the pattern used for objects
  that support the create/set/get/list/destroy actions, but
  publishable objects don't go in SQL either so these classes would be
  different in any case.
  """

  attributes = ("action", "tag", "client_id", "uri")
  payload = None

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

  def serve_dispatch(self, r_msg, client, cb):
    """Action dispatch handler."""
    if client is None:
      raise rpki.exceptions.BadQuery, "Client query received on control channel"
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
    cb()

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
    rpki.log.info("Withdrawing %s" % repr(self.uri))
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

class report_error_elt(rpki.xml_utils.base_elt, publication_namespace):
  """<report_error/> element."""

  element_name = "report_error"
  attributes = ("tag", "error_code")

  @classmethod
  def from_exception(cls, exc):
    """Generate a <report_error/> element from an exception."""
    self = cls()
    self.error_code = exc.__class__.__name__
    return self

class msg(rpki.xml_utils.msg, publication_namespace):
  """Publication PDU."""

  ## @var version
  # Protocol version
  version = 1

  ## @var pdus
  # Dispatch table of PDUs for this protocol.
  pdus = dict((x.element_name, x)
              for x in (config_elt, client_elt, certificate_elt, crl_elt, manifest_elt, roa_elt, report_error_elt))

  def serve_top_level(self, gctx, client, cb):
    """Serve one msg PDU."""
    if self.type != "query":
      raise rpki.exceptions.BadQuery, "Message type is not query"
    r_msg = self.__class__()
    r_msg.type = "reply"

    def loop(iterator, q_pdu):
      q_pdu.gctx = gctx
      q_pdu.serve_dispatch(r_msg, client, iterator)

    def done():
      cb(r_msg)

    rpki.async.iterator(self, loop, done)

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
