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

"""
Global context for rpkid.  Probably should be renamed rpkid.py, but
the identifier gctx is scattered all through the code at the moment.
"""

import traceback, os, time, getopt, sys, MySQLdb, lxml.etree
import rpki.resource_set, rpki.up_down, rpki.left_right, rpki.x509, rpki.sql
import rpki.https, rpki.config, rpki.cms, rpki.exceptions, rpki.relaxng, rpki.log

class global_context(object):
  """A container for various global parameters."""

  def __init__(self, cfg):

    self.db = MySQLdb.connect(user   = cfg.get("sql-username"),
                              db     = cfg.get("sql-database"),
                              passwd = cfg.get("sql-password"))
    self.cur = self.db.cursor()

    self.cms_ta_irdb   = rpki.x509.X509(Auto_file = cfg.get("cms-ta-irdb"))
    self.cms_ta_irbe   = rpki.x509.X509(Auto_file = cfg.get("cms-ta-irbe"))
    self.cms_key       = rpki.x509.RSA(Auto_file = cfg.get("cms-key"))
    self.cms_certs     = rpki.x509.X509_chain(Auto_files = cfg.multiget("cms-cert"))

    self.https_key     = rpki.x509.RSA(Auto_file = cfg.get("https-key"))
    self.https_certs   = rpki.x509.X509_chain(Auto_files = cfg.multiget("https-cert"))
    self.https_ta_irdb = rpki.x509.X509_chain(Auto_files = cfg.multiget("https-ta-irdb"))
    self.https_ta_irbe = rpki.x509.X509_chain(Auto_files = cfg.multiget("https-ta-irbe"))

    self.irdb_url    = cfg.get("irdb-url")

    self.https_server_host = cfg.get("server-host", "")
    self.https_server_port = int(cfg.get("server-port", "4433"))

    self.publication_kludge_base = cfg.get("publication-kludge-base", "publication/")

    self.sql_cache = {}
    self.sql_dirty = set()

  def irdb_query(self, self_id, child_id = None):
    """Perform an IRDB callback query.  In the long run this should not
    be a blocking routine, it should instead issue a query and set up a
    handler to receive the response.  For the moment, though, we are
    doing simple lock step and damn the torpedos.  Not yet doing
    anything useful with subject name.  Most likely this function should
    really be wrapped up in a class that carries both the query result
    and also the intermediate state needed for the event-driven code
    that this function will need to become.
    """

    rpki.log.trace()

    q_msg = rpki.left_right.msg()
    q_msg.append(rpki.left_right.list_resources_elt())
    q_msg[0].type = "query"
    q_msg[0].self_id = self_id
    q_msg[0].child_id = child_id
    q_elt = q_msg.toXML()
    rpki.relaxng.left_right.assertValid(q_elt)
    q_cms = rpki.cms.xml_sign(q_elt, self.cms_key, self.cms_certs)
    r_cms = rpki.https.client(
      privateKey    = self.https_key,
      certChain     = self.https_certs,
      x509TrustList = self.https_ta_irdb,
      url           = self.irdb_url,
      msg           = q_cms)
    r_elt = rpki.cms.xml_verify(r_cms, self.cms_ta_irdb)
    rpki.relaxng.left_right.assertValid(r_elt)
    r_msg = rpki.left_right.sax_handler.saxify(r_elt)
    if len(r_msg) == 0 or not isinstance(r_msg[0], rpki.left_right.list_resources_elt) or r_msg[0].type != "reply":
      raise rpki.exceptions.BadIRDBReply, "Unexpected response to IRDB query: %s" % lxml.etree.tostring(r_msg.toXML(), pretty_print = True, encoding = "us-ascii")
    return rpki.resource_set.resource_bag(
      as          = r_msg[0].as,
      v4          = r_msg[0].ipv4,
      v6          = r_msg[0].ipv6,
      valid_until = r_msg[0].valid_until)

  def sql_cache_clear(self):
    """Clear the object cache."""
    self.sql_cache.clear()

  def sql_assert_pristine(self):
    """Assert that there are no dirty objects in the cache."""
    assert not self.sql_dirty, "Dirty objects in SQL cache: %s" % self.sql_dirty

  def sql_sweep(self):
    """Write any dirty objects out to SQL."""
    for s in self.sql_dirty.copy():
      rpki.log.debug("Sweeping %s" % repr(s))
      if s.sql_deleted:
        s.sql_delete()
      else:
        s.sql_store()
    self.sql_assert_pristine()

  def left_right_handler(self, query, path):
    """Process one left-right PDU."""
    rpki.log.trace()
    try:
      q_elt = rpki.cms.xml_verify(query, self.cms_ta_irbe)
      rpki.relaxng.left_right.assertValid(q_elt)
      q_msg = rpki.left_right.sax_handler.saxify(q_elt)
      r_msg = q_msg.serve_top_level(self)
      r_elt = r_msg.toXML()
      rpki.relaxng.left_right.assertValid(r_elt)
      reply = rpki.cms.xml_sign(r_elt, self.cms_key, self.cms_certs)
      self.sql_sweep()
      return 200, reply
    except lxml.etree.DocumentInvalid:
      rpki.log.warn("Received reply document does not pass schema check: " + lxml.etree.tostring(r_elt, pretty_print = True))
      rpki.log.warn(traceback.format_exc())
      return 500, "Schema violation"
    except Exception, data:
      rpki.log.error(traceback.format_exc())
      return 500, "Unhandled exception %s" % data

  def up_down_handler(self, query, path):
    """Process one up-down PDU."""
    rpki.log.trace()
    try:
      child_id = path.partition("/up-down/")[2]
      if not child_id.isdigit():
        raise rpki.exceptions.BadContactURL, "Bad path: %s" % path
      child = rpki.left_right.child_elt.sql_fetch(self, long(child_id))
      if child is None:
        raise rpki.exceptions.ChildNotFound, "Could not find child %s" % child_id
      reply = child.serve_up_down(query)
      self.sql_sweep()
      return 200, reply
    except Exception, data:
      rpki.log.error(traceback.format_exc())
      return 400, "Could not process PDU: %s" % data

  def cronjob_handler(self, query, path):
    """Periodic tasks.  As simple as possible for now, may need to break
    this up into separate handlers later.
    """

    rpki.log.trace()
    for s in rpki.left_right.self_elt.sql_fetch_all(self):
      s.client_poll()
      s.update_children()
      s.regenerate_crls_and_manifests()
    self.sql_sweep()
    return 200, "OK"
