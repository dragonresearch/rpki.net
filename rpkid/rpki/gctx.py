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
import rpki.https, rpki.config, rpki.exceptions, rpki.relaxng, rpki.log

# This should be wrapped somewhere in rpki.x509 eventually
import POW

class global_context(object):
  """A container for various global parameters."""

  def __init__(self, cfg):

    self.db = rpki.sql.connect(cfg)
    self.cur = self.db.cursor()

    self.bpki_ta    = rpki.x509.X509(Auto_file = cfg.get("bpki-ta"))
    self.irdb_cert  = rpki.x509.X509(Auto_file = cfg.get("irdb-cert"))
    self.irbe_cert  = rpki.x509.X509(Auto_file = cfg.get("irbe-cert"))
    self.rpkid_cert = rpki.x509.X509(Auto_file = cfg.get("rpkid-cert"))
    self.rpkid_key  = rpki.x509.RSA( Auto_file = cfg.get("rpkid-key"))

    self.irdb_url   = cfg.get("irdb-url")

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
    q_msg.type = "query"
    q_msg.append(rpki.left_right.list_resources_elt())
    q_msg[0].self_id = self_id
    q_msg[0].child_id = child_id
    q_cms = rpki.left_right.cms_msg.wrap(q_msg, self.rpkid_key, self.rpkid_cert)
    der = rpki.https.client(
      server_ta    = (self.bpki_ta, self.irdb_cert),
      client_key   = self.rpkid_key,
      client_cert  = self.rpkid_cert,
      url          = self.irdb_url,
      msg          = q_cms)
    r_msg = rpki.left_right.cms_msg.unwrap(der, (self.bpki_ta, self.irdb_cert))
    if len(r_msg) == 0 or not isinstance(r_msg[0], rpki.left_right.list_resources_elt) or r_msg.type != "reply":
      raise rpki.exceptions.BadIRDBReply, "Unexpected response to IRDB query: %s" % lxml.etree.tostring(r_msg.toXML(), pretty_print = True, encoding = "us-ascii")
    return rpki.resource_set.resource_bag(
      asn         = r_msg[0].asn,
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
      q_msg = rpki.left_right.cms_msg.unwrap(query, (self.bpki_ta, self.irbe_cert))
      if q_msg.type != "query":
        raise rpki.exceptions.BadQuery, "Message type is not query"
      r_msg = q_msg.serve_top_level(self)
      reply = rpki.left_right.cms_msg.wrap(r_msg, self.rpkid_key, self.rpkid_cert)
      self.sql_sweep()
      return 200, reply
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
    try:
      for s in rpki.left_right.self_elt.sql_fetch_all(self):
        s.client_poll()
        s.update_children()
        s.update_roas()
        s.regenerate_crls_and_manifests()
      self.sql_sweep()
      return 200, "OK"
    except Exception, data:
      rpki.log.error(traceback.format_exc())
      return 500, "Unhandled exception %s" % data

  ## @var https_ta_cache
  # HTTPS trust anchor cache, to avoid regenerating it for every TLS connection.
  https_ta_cache = None

  def clear_https_ta_cache(self):
    """Clear cached HTTPS trust anchor X509Store."""

    if self.https_ta_cache is not None:
      rpki.log.debug("Clearing HTTPS trusted cert cache")
      self.https_ta_cache = None

  def build_x509store(self):
    """Build a dynamic x509store object.

    This probably should be refactored to do the real work in the
    rpki.https module so that this module can treat the x509store as a
    black box.  This method's jobs would then be just to identify
    certs that need to be added and to cache an opaque object.
    """

    if self.https_ta_cache is None:
      store = POW.X509Store()
      selves = rpki.left_right.self_elt.sql_fetch_all(self)
      children = rpki.left_right.child_elt.sql_fetch_all(self)
      certs = [c.bpki_cert for c in children if c.bpki_cert is not None] + \
              [c.bpki_glue for c in children if c.bpki_glue is not None] + \
              [s.bpki_cert for s in selves if s.bpki_cert is not None] + \
              [s.bpki_glue for s in selves if s.bpki_glue is not None] + \
              [self.irbe_cert, self.irdb_cert, self.bpki_ta]
      for x in certs:
        if rpki.https.debug_tls_certs:
          rpki.log.debug("HTTPS dynamic trusted cert issuer %s [%s] subject %s [%s]" % (x.getIssuer(), x.hAKI(), x.getSubject(), x.hSKI()))
        store.addTrust(x.get_POW())
      self.https_ta_cache = store

    return self.https_ta_cache
