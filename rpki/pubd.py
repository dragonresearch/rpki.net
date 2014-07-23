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
import socket
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

from lxml.etree import Element, SubElement, tostring as ElementToString

logger = logging.getLogger(__name__)


rrdp_xmlns   = rpki.relaxng.rrdp.xmlns
rrdp_nsmap   = rpki.relaxng.rrdp.nsmap
rrdp_version = "1"


def DERSubElement(elt, name, der, attrib = None, **kwargs):
  """
  Convenience wrapper around SubElement for use with Base64 text.
  """

  se = SubElement(elt, name, attrib, **kwargs)
  se.text = rpki.x509.base64_with_linebreaks(der)
  se.tail = "\n"
  return se


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

    self.rrdp_uri_base = self.cfg.get("rrdp-uri-base", "http://%s/" % socket.getfqdn())
    self.rrdp_expiration_interval = rpki.sundial.timedelta.parse(self.cfg.get("rrdp-expiration-interval", "6h"))
    self.rrdp_publication_base = self.cfg.get("rrdp-publication-base", "rrdp-publication/")

    self.session = session_obj.fetch(self)

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
      if not q_msg.is_query():
        raise rpki.exceptions.BadQuery("Message type is not query")
      r_msg = q_msg.__class__.reply()
      delta = self.session.new_delta()
      failed = False
      for q_pdu in q_msg:
        try:
          if isinstance(q_pdu, rpki.publication.list_elt):
            for obj in client.published_objects:
              r_pdu = q_pdu.__class__()
              r_pdu.tag = q_pdu.tag
              r_pdu.uri = obj.uri
              r_pdu.hash = obj.hash
              r_msg.append(r_pdu)
          else:
            q_pdu.gctx = self
            q_pdu.client = client
            q_pdu.client.check_allowed_uri(q_pdu.uri)
            q_pdu.serve_action(delta)
            r_pdu = q_pdu.__class__()
            r_pdu.tag = q_pdu.tag
            r_pdu.uri = q_pdu.uri
            r_msg.append(r_pdu)
        except (rpki.async.ExitNow, SystemExit):
          raise
        except Exception, e:
          if not isinstance(e, rpki.exceptions.NotFound):
            logger.exception("Exception processing PDU %r", q_pdu)
          r_msg.append(rpki.publication.report_error_elt.from_exception(e, q_pdu.tag))
          failed = True
      #
      # This isn't really right as long as we're using SQL autocommit
      #
      if failed:
        # This should SQL rollback
        #
        # Under current scheme I don't think delta is in SQL yet so this may be wrong
        delta.sql_delete()
      else:
        delta.activate()
        self.sql.sweep()
        self.session.generate_snapshot()

        # Should SQL commit here

        # These could be merged, and perhaps should be.
        self.session.write_snapshot()
        self.session.write_deltas()
        self.session.write_notification()

        # Somewhere around here is also where we should finally write
        # stuff out to rsync store, now that SQL is the publication
        # database of record.  This may require doing the filesystem
        # updates from the delta, but that should be straightforward.

      cb(code = 200,
         body = rpki.publication.cms_msg().wrap(r_msg, self.pubd_key, self.pubd_cert, self.pubd_crl))
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception, e:
      logger.exception("Unhandled exception processing client query, path %r", path)
      cb(code = 500,
         reason = "Could not process PDU: %s" % e)

  def uri_to_filename(self, uri):
    """
    Convert a URI to a local filename.
    """

    if not uri.startswith("rsync://"):
      raise rpki.exceptions.BadURISyntax(uri)
    path = uri.split("/")[4:]
    path.insert(0, self.publication_base.rstrip("/"))
    filename = "/".join(path)
    if "/../" in filename or filename.endswith("/.."):
      raise rpki.exceptions.BadURISyntax(filename)
    return filename


class session_obj(rpki.sql.sql_persistent):
  """
  An RRDP session.
  """

  sql_template = rpki.sql.template(
    "session",
    "session_id",
    "uuid",
    "serial",
    "snapshot",
    "hash")

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
      self.uuid = str(uuid.uuid4())
      self.serial = 0
      self.snapshot = None
      self.hash = None
      self.gctx = gctx
      self.sql_store()
    return self

  @property
  def objects(self):
    return object_obj.sql_fetch_where(self.gctx, "session_id = %s", (self.session_id,))

  @property
  def deltas(self):
    return delta_obj.sql_fetch_where(self.gctx, "session_id = %s", (self.session_id,))

  def new_delta(self):
    return delta_obj.create(self)

  def expire_deltas(self):
    for delta in delta_obj.sql_fetch_where(self.gctx,
                                           "session_id = %s AND expires IS NOT NULL AND expires < %s",
                                           (self.session_id, rpki.sundial.now())):
      delta.sql_delete()

  def write_rrdp_file(self, fn, text, overwrite = False):
    """
    Save RRDP XML to disk.
    """

    if overwrite or not os.path.exists(os.path.join(self.gctx.rrdp_publication_base, fn)):
      tn = os.path.join(self.gctx.rrdp_publication_base, fn + ".%s.tmp" % os.getpid())
      if not os.path.isdir(os.path.dirname(tn)):
        os.makedirs(os.path.dirname(tn))
      with open(tn, "w") as f:
        f.write(text)
      os.rename(tn, os.path.join(self.gctx.rrdp_publication_base, fn))

  def generate_snapshot(self):
    """
    Generate an XML snapshot of this session.
    """

    xml = Element(rrdp_xmlns + "snapshot", nsmap = rrdp_nsmap,
                  version = rrdp_version,
                  session_id = self.uuid,
                  serial = str(self.serial))
    xml.text = "\n"
    for obj in self.objects:
      DERSubElement(xml, rrdp_xmlns + "publish",
                    der = obj.der,
                    uri = obj.uri)
    rpki.relaxng.rrdp.assertValid(xml)
    self.snapshot = ElementToString(xml, pretty_print = True)
    self.hash = rpki.x509.sha256(self.snapshot).encode("hex")
    self.sql_store()

  def write_snapshot(self):
    """
    Write current session snapshot to disk.
    """

    self.write_rrdp_file("%s/snapshot/%s.xml" % (self.uuid, self.serial), self.snapshot)

  def write_deltas(self):
    """
    Write any missing deltas to disk.
    """

    for delta in self.deltas:
      self.write_rrdp_file(delta.fn, delta.xml)

  def write_notification(self):
    """
    Write current notification file to disk.
    """

    xml = Element(rrdp_xmlns + "notification", nsmap = rrdp_nsmap,
                  version = rrdp_version,
                  session_id = self.uuid,
                  serial = str(self.serial))
    SubElement(xml, rrdp_xmlns + "snapshot",
               uri = "%s/%s/snapshot/%d.xml" % (self.gctx.rrdp_uri_base, self.uuid, self.serial),
               hash = self.hash)
    for delta in self.deltas:
      se = SubElement(xml, rrdp_xmlns + "delta",
                      to = str(delta.serial),
                      uri = "%s/%s" % (self.gctx.rrdp_uri_base, delta.fn),
                      hash =  delta.hash)
      se.set("from", str(delta.serial - 1))
    rpki.relaxng.rrdp.assertValid(xml)
    self.write_rrdp_file("%s/notification.xml" % self.uuid,
                         ElementToString(xml, pretty_print = True),
                         overwrite = True)


class delta_obj(rpki.sql.sql_persistent):
  """
  An RRDP delta.
  """

  sql_template = rpki.sql.template(
    "delta",
    "delta_id",
    "session_id",
    "serial",
    "xml",
    "hash",
    ("expires", rpki.sundial.datetime))

  @property
  @rpki.sql.cache_reference
  def session(self):
    return session_obj.sql_fetch(self.gctx, self.session_id)

  @property
  def fn(self):
    return "%s/deltas/%s-%s.xml" % (self.session.uuid, self.serial - 1, self.serial)

  @classmethod
  def create(cls, session):
    self = cls()
    session.serial += 1
    session.sql_mark_dirty()
    self.gctx = session.gctx
    self.session_id = session.session_id
    self.serial = session.serial
    self.xml = None
    self.hash = None
    self.expires = rpki.sundial.now() + self.gctx.rrdp_expiration_interval
    self.deltas = Element(rrdp_xmlns + "deltas", nsmap = rrdp_nsmap,
                          to = str(self.serial),
                          version =  rrdp_version,
                          session_id = session.uuid)
    self.deltas.set("from", str(self.serial - 1))
    SubElement(self.deltas, rrdp_xmlns + "delta", serial = str(self.serial)).text = "\n"
    return self

  def activate(self):
    rpki.relaxng.rrdp.assertValid(self.deltas)
    self.xml = ElementToString(self.deltas, pretty_print = True)
    self.hash = rpki.x509.sha256(self.xml).encode("hex")
    del self.deltas
    self.sql_mark_dirty()

  def publish(self, client, der, uri, hash):
    obj = object_obj.current_object_at_uri(client, self, uri)
    if obj is not None and obj.hash == hash:
      obj.delete(self)
    elif obj is not None:
      raise rpki.exceptions.ExistingObjectAtURI("Object already published at %s" % uri)
    logger.debug("Publishing %s", uri)
    object_obj.create(client, self, der, uri)
    se = DERSubElement(self.deltas[0], rrdp_xmlns + "publish", der = der, uri = uri)
    if hash is not None:
      se.set("hash", hash)
    rpki.relaxng.rrdp.assertValid(self.deltas)

  def withdraw(self, client, uri, hash):
    obj = object_obj.current_object_at_uri(client, self, uri)
    if obj is None:
      raise rpki.exceptions.NoObjectAtURI("No object published at %s" % uri)
    if obj.hash != hash:
      raise rpki.exceptions.DifferentObjectAtURI("Found different object at %s (old %s, new %s)" % (uri, obj.hash, hash))
    logger.debug("Withdrawing %s", uri)
    obj.delete(self)
    SubElement(self.deltas[0], rrdp_xmlns + "withdraw", uri = uri, hash = hash).tail = "\n"
    rpki.relaxng.rrdp.assertValid(self.deltas)


class object_obj(rpki.sql.sql_persistent):
  """
  A published object.
  """

  sql_template = rpki.sql.template(
    "object",
    "object_id",
    "uri",
    "der",
    "hash",
    "client_id",
    "session_id")

  def __repr__(self):
    return rpki.log.log_repr(self, self.uri)

  @property
  @rpki.sql.cache_reference
  def session(self):
    return session_obj.sql_fetch(self.gctx, self.session_id)

  @property
  @rpki.sql.cache_reference
  def client(self):
    return rpki.publication_control.client_elt.sql_fetch(self.gctx, self.client_id)

  @classmethod
  def create(cls, client, delta, der, uri):
    self = cls()
    self.gctx = delta.gctx
    self.uri = uri
    self.der = der
    self.hash = rpki.x509.sha256(der).encode("hex")
    logger.debug("Computed hash %s for %s", self.hash, self.uri)
    self.session_id = delta.session_id
    self.client_id = client.client_id
    self.sql_mark_dirty()
    return self

  def delete(self, delta):
    self.sql_mark_deleted()

  @classmethod
  def current_object_at_uri(cls, client, delta, uri):
    return cls.sql_fetch_where1(client.gctx,
                                "session_id = %s AND client_id = %s AND uri = %s",
                                (delta.session_id, client.client_id, uri))
