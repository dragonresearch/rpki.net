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
RPKI publication engine.
"""

import os
import re
import uuid
import time
import logging
import argparse
import rpki.resource_set
import rpki.up_down
import rpki.x509
import rpki.sql
import rpki.http
import rpki.config
import rpki.exceptions
import rpki.relaxng
import rpki.log
import rpki.publication
import rpki.publication_control
import rpki.daemonize

logger = logging.getLogger(__name__)

class main(object):
  """
  Main program for pubd.
  """

  def __init__(self):

    os.environ["TZ"] = "UTC"
    time.tzset()

    self.irbe_cms_timestamp = None

    parser = argparse.ArgumentParser(description = __doc__)
    parser.add_argument("-c", "--config",
                        help = "override default location of configuration file")
    parser.add_argument("-f", "--foreground", action = "store_true",
                        help = "do not daemonize")
    parser.add_argument("--pidfile",
                        help = "override default location of pid file")
    parser.add_argument("--profile",
                        help = "enable profiling, saving data to PROFILE")
    rpki.log.argparse_setup(parser)
    args = parser.parse_args()

    self.profile = args.profile

    rpki.log.init("pubd", args)

    self.cfg = rpki.config.parser(args.config, "pubd")
    self.cfg.set_global_flags()

    if not args.foreground:
      rpki.daemonize.daemon(pidfile = args.pidfile)

    if self.profile:
      import cProfile
      prof = cProfile.Profile()
      try:
        prof.runcall(self.main)
      finally:
        prof.dump_stats(self.profile)
        logger.info("Dumped profile data to %s", self.profile)
    else:
      self.main()

  def main(self):

    if self.profile:
      logger.info("Running in profile mode with output to %s", self.profile)

    self.sql = rpki.sql.session(self.cfg)

    self.bpki_ta   = rpki.x509.X509(Auto_update = self.cfg.get("bpki-ta"))
    self.irbe_cert = rpki.x509.X509(Auto_update = self.cfg.get("irbe-cert"))
    self.pubd_cert = rpki.x509.X509(Auto_update = self.cfg.get("pubd-cert"))
    self.pubd_key  = rpki.x509.RSA( Auto_update = self.cfg.get("pubd-key"))
    self.pubd_crl  = rpki.x509.CRL( Auto_update = self.cfg.get("pubd-crl"))

    self.http_server_host = self.cfg.get("server-host", "")
    self.http_server_port = self.cfg.getint("server-port")

    self.publication_base = self.cfg.get("publication-base", "publication/")

    self.publication_multimodule = self.cfg.getboolean("publication-multimodule", False)

    rpki.http.server(
      host     = self.http_server_host,
      port     = self.http_server_port,
      handlers = (("/control", self.control_handler),
                  ("/client/", self.client_handler)))


  def control_handler(self, query, path, cb):
    """
    Process one PDU from the IRBE.
    """

    def done(r_msg):
      self.sql.sweep()
      cb(code = 200,
         body = rpki.publication_control.cms_msg().wrap(r_msg, self.pubd_key, self.pubd_cert))

    try:
      q_cms = rpki.publication_control.cms_msg(DER = query)
      q_msg = q_cms.unwrap((self.bpki_ta, self.irbe_cert))
      self.irbe_cms_timestamp = q_cms.check_replay(self.irbe_cms_timestamp, "control")
      q_msg.serve_top_level(self, done)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception, e:
      logger.exception("Unhandled exception processing control query, path %r", path)
      cb(code = 500, reason = "Unhandled exception %s: %s" % (e.__class__.__name__, e))


  client_url_regexp = re.compile("/client/([-A-Z0-9_/]+)$", re.I)

  def client_handler(self, query, path, cb):
    """
    Process one PDU from a client.
    """

    def done(r_msg):
      self.sql.sweep()
      cb(code = 200,
         body = rpki.publication.cms_msg().wrap(r_msg, self.pubd_key, self.pubd_cert, self.pubd_crl))

    try:
      match = self.client_url_regexp.search(path)
      if match is None:
        raise rpki.exceptions.BadContactURL("Bad path: %s" % path)
      client_handle = match.group(1)
      client = rpki.publication_control.client_elt.sql_fetch_where1(self, "client_handle = %s", (client_handle,))
      if client is None:
        raise rpki.exceptions.ClientNotFound("Could not find client %s" % client_handle)
      q_cms = rpki.publication.cms_msg(DER = query)
      q_msg = q_cms.unwrap((self.bpki_ta, client.bpki_cert, client.bpki_glue))
      q_cms.check_replay_sql(client, client.client_handle)
      q_msg.serve_top_level(self, client, done)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception, e:
      logger.exception("Unhandled exception processing client query, path %r", path)
      cb(code = 500,
         reason = "Could not process PDU: %s" % e)


class session_obj(rpki.sql.sql_persistent):
  """
  An RRDP session.
  """

  # We probably need additional columns or an additional table to
  # handle cleanup of old serial numbers.  Not sure quite what these
  # would look like, other than that the SQL datatypes are probably
  # BIGINT and DATETIME.  Maybe a table to track time at which we
  # retired a particular serial number, or, to save us the arithmetic,
  # the corresponding cleanup time?

  sql_template = rpki.sql.template(
    "session",
    "session_id",
    "uuid",
    "serial")

  def __repr__(self):
    return rpki.log.log_repr(self, self.uuid, self.serial)

  @classmethod
  def fetch(cls, gctx):
    """
    Fetch the one and only session, creating it if necessary.
    """

    self = cls.sql_fetch(gctx, 1)
    if self is None:
      self = cls()
      self.gctx = gctx
      self.session_id = 1
      self.uuid = uuid.uuid4()
      self.serial = 1
      self.sql_store()
    return self

  @property
  @rpki.sql.cache_reference
  def objects(self):
    return object_obj.sql_fetch_where(self.gctx, "session_id = %s", (self.session_id))

  def next_serial_number(self):
    """
    Bump serial number
    """

    self.serial += 1
    self.sql_mark_dirty()
    return self.serial

  # More methods when I know what they look like


class object_obj(rpki.sql.sql_persistent):
  """
  A published object.
  """

  sql_template = rpki.sql.template(
    "object",
    "object_id",
    "uri",
    "hash",
    "payload",
    "published",
    "withdrawn")

  uri       = None
  published = None
  withdrawn = None

  def __repr__(self):
    return rpki.log.log_repr(self, self.uri, self.published, self.withdrawn)

  @property
  @rpki.sql.cache_reference
  def session(self):
    return session_obj.sql_fetch(self.gctx, self.session_id)

  @property
  @rpki.sql.cache_reference
  def client(self):
    return rpki.publication_control.client_elt.sql_fetch(self.gctx, self.client_id)
