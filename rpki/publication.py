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
  xmlns = rpki.relaxng.publication.xmlns
  nsmap = rpki.relaxng.publication.nsmap


class base_publication_elt(rpki.xml_utils.base_elt, publication_namespace):
  """
  Base element for publication protocol.  Publish and withdraw PDUs subclass this.
  """

  attributes = ("tag", "uri", "hash")

  tag = None
  uri = None
  der = None
  hash = None
  
  _payload = None

  def __repr__(self):
    return rpki.log.log_repr(self, self.tag, self.uri, self.hash, self.payload)

  @property
  def payload(self):
    if self._payload is None and self.der is not None:
      self._payload = rpki.x509.uri_dispatch(self.uri)(DER = self.der)
    return self._payload

  def raise_if_error(self):
    """
    No-op unless this is a <report_error/> PDU.
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
      self.der = text.decode("base64")
    stack.pop()

  def toXML(self):
    """
    Generate XML element for publishable object.
    """

    elt = self.make_elt()
    if self.der is not None:
      elt.text = self.der.encode("base64")
    return elt

  def serve_action(self, delta):
    """
    Publish an object.
    """

    logger.info("Publishing %s", self.payload.tracking_data(self.uri))
    delta.publish(self.client, self.der, self.uri, self.hash)

    # The rest of this shouldn't happen until after the SQL commit
    filename = self.gctx.uri_to_filename(self.uri)
    filename_tmp = filename + ".tmp"
    dirname = os.path.dirname(filename)
    if not os.path.isdir(dirname):
      os.makedirs(dirname)
    with open(filename_tmp, "wb") as f:
      f.write(self.der)
    os.rename(filename_tmp, filename)


class withdraw_elt(base_publication_elt):
  """
  <withdraw/> element.
  """

  element_name = "withdraw"

  def serve_action(self, delta):
    """
    Withdraw an object, then recursively delete empty directories.
    """

    logger.info("Withdrawing %s", self.uri)
    delta.withdraw(self.client, self.uri, self.hash)

    # The rest of this shouldn't happen until after the SQL commit
    filename = self.gctx.uri_to_filename(self.uri)
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

  element_name = "list"


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

    try:
      e = getattr(rpki.exceptions, self.error_code)
      if issubclass(e, rpki.exceptions.RPKI_Exception):
        raise e(getattr(self, "text", None))
    except (TypeError, AttributeError):
      pass
    raise rpki.exceptions.BadPublicationReply("Unexpected response from pubd: %s" % self)


class msg(rpki.xml_utils.msg, publication_namespace):
  """
  Publication PDU.
  """

  ## @var version
  # Protocol version
  version = int(rpki.relaxng.publication.version)

  ## @var pdus
  # Dispatch table of PDUs for this protocol.
  pdus = dict((x.element_name, x) for x in (publish_elt, withdraw_elt, list_elt, report_error_elt))


class sax_handler(rpki.xml_utils.sax_handler):
  """
  SAX handler for publication protocol.
  """

  pdu = msg
  name = "msg"
  version = rpki.relaxng.publication.version


class cms_msg(rpki.x509.XML_CMS_object):
  """
  Class to hold a CMS-signed publication PDU.
  """

  encoding = "us-ascii"
  schema = rpki.relaxng.publication
  saxify = sax_handler.saxify

class cms_msg_no_sax(cms_msg):
  """
  Transition kludge: varient of cms_msg (q.v.) with SAX parsing disabled.
  If and when we ditch SAX entirely, this will become cms_msg.
  """

  saxify = None
