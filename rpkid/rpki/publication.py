"""
RPKI "publication" protocol.

$Id$

Copyright (C) 2009--2011  Internet Systems Consortium ("ISC")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.

Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")

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

import os, errno
import rpki.resource_set, rpki.x509, rpki.sql, rpki.exceptions, rpki.xml_utils
import rpki.http, rpki.up_down, rpki.relaxng, rpki.sundial, rpki.log, rpki.roa

class publication_namespace(object):
  """
  XML namespace parameters for publication protocol.
  """

  xmlns = "http://www.hactrn.net/uris/rpki/publication-spec/"
  nsmap = { None : xmlns }

class control_elt(rpki.xml_utils.data_elt, rpki.sql.sql_persistent, publication_namespace):
  """
  Virtual class for control channel objects.
  """

  def serve_dispatch(self, r_msg, cb, eb):
    """
    Action dispatch handler.  This needs special handling because we
    need to make sure that this PDU arrived via the control channel.
    """
    if self.client is not None:
      raise rpki.exceptions.BadQuery, "Control query received on client channel"
    rpki.xml_utils.data_elt.serve_dispatch(self, r_msg, cb, eb)

class config_elt(control_elt):
  """
  <config/> element.  This is a little weird because there should
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
    """
    StartElement() handler for config object.  This requires special
    handling because of the weird way we treat config_id.
    """
    control_elt.startElement(self, stack, name, attrs)
    self.config_id = self.wired_in_config_id

  @classmethod
  def fetch(cls, gctx):
    """
    Fetch the config object from SQL.  This requires special handling
    because of the weird way we treat config_id.
    """
    return cls.sql_fetch(gctx, cls.wired_in_config_id)

  def serve_set(self, r_msg, cb, eb):
    """
    Handle a set action.  This requires special handling because
    config doesn't support the create method.
    """
    if self.sql_fetch(self.gctx, self.config_id) is None:
      control_elt.serve_create(self, r_msg, cb, eb)
    else:
      control_elt.serve_set(self, r_msg, cb, eb)

  def serve_fetch_one_maybe(self):
    """
    Find the config object on which a get or set method should
    operate.
    """
    return self.sql_fetch(self.gctx, self.config_id)

class client_elt(control_elt):
  """
  <client/> element.
  """

  element_name = "client"
  attributes = ("action", "tag", "client_handle", "base_uri")
  elements = ("bpki_cert", "bpki_glue")

  sql_template = rpki.sql.template("client", "client_id", "client_handle", "base_uri",
                                   ("bpki_cert", rpki.x509.X509),
                                   ("bpki_glue", rpki.x509.X509),
                                   ("last_cms_timestamp", rpki.sundial.datetime))

  base_uri  = None
  bpki_cert = None
  bpki_glue = None

  def serve_fetch_one_maybe(self):
    """
    Find the client object on which a get, set, or destroy method
    should operate, or which would conflict with a create method.
    """
    return self.sql_fetch_where1(self.gctx, "client_handle = %s", self.client_handle)

  def serve_fetch_all(self):
    """
    Find client objects on which a list method should operate.
    """
    return self.sql_fetch_all(self.gctx)

  def check_allowed_uri(self, uri):
    if not uri.startswith(self.base_uri):
      raise rpki.exceptions.ForbiddenURI

class publication_object_elt(rpki.xml_utils.base_elt, publication_namespace):
  """
  Virtual class for publishable objects.  These have very similar
  syntax, differences lie in underlying datatype and methods.  XML
  methods are a little different from the pattern used for objects
  that support the create/set/get/list/destroy actions, but
  publishable objects don't go in SQL either so these classes would be
  different in any case.
  """

  attributes = ("action", "tag", "client_handle", "uri")
  payload_type = None
  payload = None

  def endElement(self, stack, name, text):
    """
    Handle a publishable element element.
    """
    assert name == self.element_name, "Unexpected name %s, stack %s" % (name, stack)
    if text:
      self.payload = self.payload_type(Base64 = text)
    stack.pop()

  def toXML(self):
    """
    Generate XML element for publishable object.
    """
    elt = self.make_elt()
    if self.payload:
      elt.text = self.payload.get_Base64()
    return elt

  def serve_dispatch(self, r_msg, cb, eb):
    """
    Action dispatch handler.
    """
    try:
      if self.client is None:
        raise rpki.exceptions.BadQuery, "Client query received on control channel"
      dispatch = { "publish"  : self.serve_publish,
                   "withdraw" : self.serve_withdraw }
      if self.action not in dispatch:
        raise rpki.exceptions.BadQuery, "Unexpected query: action %s" % self.action
      self.client.check_allowed_uri(self.uri)
      dispatch[self.action]()
      r_pdu = self.__class__()
      r_pdu.action = self.action
      r_pdu.tag = self.tag
      r_pdu.uri = self.uri
      r_msg.append(r_pdu)
      cb()
    except rpki.exceptions.NoObjectAtURI, e:
      # This can happen when we're cleaning up from a prior mess, so
      # we generate a <report_error/> PDU then carry on.
      r_msg.append(report_error_elt.from_exception(e, self.tag))
      cb()

  def serve_publish(self):
    """
    Publish an object.
    """
    rpki.log.info("Publishing %r as %r" % (self.payload, self.uri))
    filename = self.uri_to_filename()
    filename_tmp = filename + ".tmp"
    dirname = os.path.dirname(filename)
    if not os.path.isdir(dirname):
      os.makedirs(dirname)
    f = open(filename_tmp, "wb")
    f.write(self.payload.get_DER())
    f.close()
    os.rename(filename_tmp, filename)

  def serve_withdraw(self):
    """
    Withdraw an object.
    """
    rpki.log.info("Withdrawing %r" % (self.uri,))
    filename = self.uri_to_filename()
    try:
      os.remove(filename)
    except OSError, e:
      if e.errno == errno.ENOENT:
        raise rpki.exceptions.NoObjectAtURI, "No object published at %r" % self.uri
      else:
        raise

  def uri_to_filename(self):
    """
    Convert a URI to a local filename.
    """
    if not self.uri.startswith("rsync://"):
      raise rpki.exceptions.BadURISyntax, self.uri
    path = self.uri.split("/")[3:]
    if not self.gctx.publication_multimodule:
      del path[0]
    path.insert(0, self.gctx.publication_base.rstrip("/"))
    filename = "/".join(path)
    if "/../" in filename or filename.endswith("/.."):
      raise rpki.exceptions.BadURISyntax, filename
    return filename

  @classmethod
  def make_publish(cls, uri, obj, tag = None):
    """
    Construct a publication PDU.
    """
    assert cls.payload_type is not None and type(obj) is cls.payload_type
    return cls.make_pdu(action = "publish", uri = uri, payload = obj, tag = tag)      

  @classmethod
  def make_withdraw(cls, uri, obj, tag = None):
    """
    Construct a withdrawal PDU.
    """
    assert cls.payload_type is not None and type(obj) is cls.payload_type
    return cls.make_pdu(action = "withdraw", uri = uri, tag = tag)

  def raise_if_error(self):
    """
    No-op, since this is not a <report_error/> PDU.
    """
    pass

class certificate_elt(publication_object_elt):
  """
  <certificate/> element.
  """

  element_name = "certificate"
  payload_type = rpki.x509.X509

class crl_elt(publication_object_elt):
  """
  <crl/> element.
  """

  element_name = "crl"
  payload_type = rpki.x509.CRL
  
class manifest_elt(publication_object_elt):
  """
  <manifest/> element.
  """

  element_name = "manifest"
  payload_type = rpki.x509.SignedManifest

class roa_elt(publication_object_elt):
  """
  <roa/> element.
  """

  element_name = "roa"
  payload_type = rpki.x509.ROA

publication_object_elt.obj2elt = dict((e.payload_type, e) for e in (certificate_elt, crl_elt, manifest_elt, roa_elt))

class report_error_elt(rpki.xml_utils.text_elt, publication_namespace):
  """
  <report_error/> element.
  """

  element_name = "report_error"
  attributes = ("tag", "error_code")
  text_attribute = "error_text"

  error_text = None

  @classmethod
  def from_exception(cls, e, tag = None):
    """
    Generate a <report_error/> element from an exception.
    """
    self = cls()
    self.tag = tag
    self.error_code = e.__class__.__name__
    self.error_text = str(e)
    return self

  def __str__(self):
    s = ""
    if getattr(self, "tag", None) is not None:
      s += "[%s] " % self.tag
    s += self.error_code
    if getattr(self, "error_text", None) is not None:
      s += ": " + self.error_text
    return s

  def raise_if_error(self):
    """
    Raise exception associated with this <report_error/> PDU.
    """
    t = rpki.exceptions.__dict__.get(self.error_code)
    if isinstance(t, type) and issubclass(t, rpki.exceptions.RPKI_Exception):
      raise t, getattr(self, "text", None)
    else:
      raise rpki.exceptions.BadPublicationReply, "Unexpected response from pubd: %s" % self

class msg(rpki.xml_utils.msg, publication_namespace):
  """
  Publication PDU.
  """

  ## @var version
  # Protocol version
  version = 1

  ## @var pdus
  # Dispatch table of PDUs for this protocol.
  pdus = dict((x.element_name, x)
              for x in (config_elt, client_elt, certificate_elt, crl_elt, manifest_elt, roa_elt, report_error_elt))

  def serve_top_level(self, gctx, client, cb):
    """
    Serve one msg PDU.
    """
    if not self.is_query():
      raise rpki.exceptions.BadQuery, "Message type is not query"
    r_msg = self.__class__.reply()

    def loop(iterator, q_pdu):

      def fail(e):
        if not isinstance(e, rpki.exceptions.NotFound):
          rpki.log.traceback()
        r_msg.append(report_error_elt.from_exception(e, q_pdu.tag))
        cb(r_msg)

      try:
        q_pdu.gctx = gctx
        q_pdu.client = client
        q_pdu.serve_dispatch(r_msg, iterator, fail)
      except (rpki.async.ExitNow, SystemExit):
        raise
      except Exception, e:
        fail(e)

    def done():
      cb(r_msg)

    rpki.async.iterator(self, loop, done)

class sax_handler(rpki.xml_utils.sax_handler):
  """
  SAX handler for publication protocol.
  """

  pdu = msg
  name = "msg"
  version = "1"

class cms_msg(rpki.x509.XML_CMS_object):
  """
  Class to hold a CMS-signed publication PDU.
  """

  encoding = "us-ascii"
  schema = rpki.relaxng.publication
  saxify = sax_handler.saxify
