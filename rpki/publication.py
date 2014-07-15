# $Id$
#
# Copyright (C) 2013--2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2009--2012  Internet Systems Consortium ("ISC")
# Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL, ISC, AND ARIN DISCLAIM ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL DRL,
# ISC, OR ARIN BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
# OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
RPKI publication protocol.
"""

import os
import errno
import logging
import rpki.resource_set
import rpki.x509
import rpki.sql
import rpki.exceptions
import rpki.xml_utils
import rpki.http
import rpki.up_down
import rpki.relaxng
import rpki.sundial
import rpki.log

logger = logging.getLogger(__name__)


class publication_namespace(object):
  xmlns = "http://www.hactrn.net/uris/rpki/publication-spec/"
  nsmap = { None : xmlns }


class base_publication_elt(rpki.xml_utils.base_elt, publication_namespace):
  """
  Base element for publication protocol.  Publish and withdraw PDUs subclass this.
  """

  attributes = ("tag", "uri", "hash")

  tag = None
  uri = None
  hash = None
  payload = None

  def __repr__(self):
    return rpki.log.log_repr(self, self.tag, self.uri, self.hash, self.payload)

  def serve_dispatch(self, r_msg, snapshot, cb, eb):
    """
    Action dispatch handler.
    """

    try:
      self.client.check_allowed_uri(self.uri)
      self.serve_action(snapshot)
      r_pdu = self.__class__()
      r_pdu.tag = self.tag
      r_pdu.uri = self.uri
      r_msg.append(r_pdu)
      cb()
    except rpki.exceptions.NoObjectAtURI, e:
      # This can happen when we're cleaning up from a prior mess, so
      # we generate a <report_error/> PDU then carry on.
      r_msg.append(report_error_elt.from_exception(e, self.tag))
      cb()

  def uri_to_filename(self):
    """
    Convert a URI to a local filename.
    """

    if not self.uri.startswith("rsync://"):
      raise rpki.exceptions.BadURISyntax(self.uri)
    path = self.uri.split("/")[3:]
    if not self.gctx.publication_multimodule:
      del path[0]
    path.insert(0, self.gctx.publication_base.rstrip("/"))
    filename = "/".join(path)
    if "/../" in filename or filename.endswith("/.."):
      raise rpki.exceptions.BadURISyntax(filename)
    return filename

  def raise_if_error(self):
    """
    No-op, since this is not a <report_error/> PDU.
    """

    pass


class publish_elt(base_publication_elt):
  """
  <publish/> element.
  """

  element_name = "publish"

  def endElement(self, stack, name, text):
    """
    Handle reading of the object to be published
    """

    assert name == self.element_name, "Unexpected name %s, stack %s" % (name, stack)
    if text:
      self.payload = rpki.x509.uri_dispatch(self.uri)(Base64 = text)
    stack.pop()

  def toXML(self):
    """
    Generate XML element for publishable object.
    """

    elt = self.make_elt()
    if self.payload != None:
      elt.text = self.payload.get_Base64()
    return elt

  def serve_action(self, snapshot):
    """
    Publish an object.
    """

    logger.info("Publishing %s", self.payload.tracking_data(self.uri))
    snapshot.publish(self.client, self.payload, self.uri, self.hash)
    filename = self.uri_to_filename()
    filename_tmp = filename + ".tmp"
    dirname = os.path.dirname(filename)
    if not os.path.isdir(dirname):
      os.makedirs(dirname)
    with open(filename_tmp, "wb") as f:
      f.write(self.payload.get_DER())
    os.rename(filename_tmp, filename)


class withdraw_elt(base_publication_elt):
  """
  <withdraw/> element.
  """

  element_name = "withdraw"

  def serve_action(self, snapshot):
    """
    Withdraw an object, then recursively delete empty directories.
    """

    logger.info("Withdrawing %s", self.uri)
    snapshot.withdraw(self.client, self.uri, self.hash)
    filename = self.uri_to_filename()
    try:
      os.remove(filename)
    except OSError, e:
      if e.errno == errno.ENOENT:
        raise rpki.exceptions.NoObjectAtURI("No object published at %s" % self.uri)
      else:
        raise
    min_path_len = len(self.gctx.publication_base.rstrip("/"))
    dirname = os.path.dirname(filename)
    while len(dirname) > min_path_len:
      try:
        os.rmdir(dirname)
      except OSError:
        break
      else:
        dirname = os.path.dirname(dirname)


class list_elt(base_publication_elt):
  """
  <list/> element.
  """

  def serve_dispatch(self, r_msg, snapshot, cb, eb):
    """
    Action dispatch handler.
    """

    for obj in self.client.published_objects:
      r_pdu = self.__class__()
      r_pdu.tag = self.tag
      r_pdu.uri = obj.uri
      r_pdu.hash = obj.hash
      r_msg.append(r_pdu)


class report_error_elt(rpki.xml_utils.text_elt, publication_namespace):
  """
  <report_error/> element.
  """

  element_name = "report_error"
  attributes = ("tag", "error_code")
  text_attribute = "error_text"

  error_code = None
  error_text = None

  def __repr__(self):
    return rpki.log.log_repr(self, self.error_code, self.error_text)

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
      raise t(getattr(self, "text", None))
    else:
      raise rpki.exceptions.BadPublicationReply("Unexpected response from pubd: %s" % self)


class msg(rpki.xml_utils.msg, publication_namespace):
  """
  Publication PDU.
  """

  ## @var version
  # Protocol version
  version = 3

  ## @var pdus
  # Dispatch table of PDUs for this protocol.
  pdus = dict((x.element_name, x) for x in (publish_elt, withdraw_elt, report_error_elt))

  def serve_top_level(self, gctx, client, cb):
    """
    Serve one msg PDU.
    """

    if not self.is_query():
      raise rpki.exceptions.BadQuery("Message type is not query")
    r_msg = self.__class__.reply()
    snapshot = gctx.session.new_snapshot() if len(self) > 0 else None

    def loop(iterator, q_pdu):

      def fail(e):
        if not isinstance(e, rpki.exceptions.NotFound):
          logger.exception("Exception processing PDU %r", q_pdu)
        r_msg.append(report_error_elt.from_exception(e, q_pdu.tag))
        snapshot.sql_delete()
        cb(r_msg)

      try:
        q_pdu.gctx = gctx
        q_pdu.client = client
        q_pdu.serve_dispatch(r_msg, snapshot, iterator, fail)
      except (rpki.async.ExitNow, SystemExit):
        raise
      except Exception, e:
        fail(e)

    def done():
      gctx.session.add_snapshot(snapshot)
      cb(r_msg)

    rpki.async.iterator(self, loop, done)


class sax_handler(rpki.xml_utils.sax_handler):
  """
  SAX handler for publication protocol.
  """

  pdu = msg
  name = "msg"
  version = "3"


class cms_msg(rpki.x509.XML_CMS_object):
  """
  Class to hold a CMS-signed publication PDU.
  """

  encoding = "us-ascii"
  schema = rpki.relaxng.publication
  saxify = sax_handler.saxify
