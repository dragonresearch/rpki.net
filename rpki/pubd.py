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
import rpki.x509
import rpki.config
import rpki.exceptions
import rpki.log
import rpki.publication
import rpki.publication_control
import rpki.daemonize
import rpki.http_simple

from lxml.etree import Element, SubElement

logger = logging.getLogger(__name__)


class main(object):
  """
  Main program for pubd.
  """

  def __init__(self):

    os.environ.update(TZ = "UTC",
                      DJANGO_SETTINGS_MODULE = "rpki.django_settings.pubd")
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

    self.cfg = rpki.config.parser(set_filename = args.config, section = "pubd")
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

    import django
    django.setup()

    global rpki                         # pylint: disable=W0602
    import rpki.pubdb                   # pylint: disable=W0621

    self.bpki_ta   = rpki.x509.X509(Auto_update = self.cfg.get("bpki-ta"))
    self.irbe_cert = rpki.x509.X509(Auto_update = self.cfg.get("irbe-cert"))
    self.pubd_cert = rpki.x509.X509(Auto_update = self.cfg.get("pubd-cert"))
    self.pubd_key  = rpki.x509.RSA( Auto_update = self.cfg.get("pubd-key"))
    self.pubd_crl  = rpki.x509.CRL( Auto_update = self.cfg.get("pubd-crl"))

    self.http_server_host = self.cfg.get("server-host", "")
    self.http_server_port = self.cfg.getint("server-port")

    self.publication_base = self.cfg.get("publication-base", "publication/")

    self.rrdp_uri_base = self.cfg.get("rrdp-uri-base",
                                      "http://%s/rrdp/" % socket.getfqdn())
    self.rrdp_expiration_interval = rpki.sundial.timedelta.parse(self.cfg.get("rrdp-expiration-interval", "6h"))
    self.rrdp_publication_base = self.cfg.get("rrdp-publication-base",
                                              "rrdp-publication/")

    try:
      self.session = rpki.pubdb.models.Session.objects.get()
    except rpki.pubdb.models.Session.DoesNotExist:
      self.session = rpki.pubdb.models.Session.objects.create(uuid = str(uuid.uuid4()), serial = 0)

    rpki.http_simple.server(
      host     = self.http_server_host,
      port     = self.http_server_port,
      handlers = (("/control", self.control_handler),
                  ("/client/", self.client_handler)))


  def control_handler(self, request, q_der):
    """
    Process one PDU from the IRBE.
    """

    from django.db import transaction, connection

    try:
      connection.cursor()           # Reconnect to mysqld if necessary
      q_cms = rpki.publication_control.cms_msg(DER = q_der)
      q_msg = q_cms.unwrap((self.bpki_ta, self.irbe_cert))
      self.irbe_cms_timestamp = q_cms.check_replay(self.irbe_cms_timestamp, "control")
      if q_msg.get("type") != "query":
        raise rpki.exceptions.BadQuery("Message type is %s, expected query" % q_msg.get("type"))
      r_msg = Element(rpki.publication_control.tag_msg, nsmap = rpki.publication_control.nsmap,
                      type = "reply", version = rpki.publication_control.version)

      try:
        q_pdu = None
        with transaction.atomic():

          for q_pdu in q_msg:
            if q_pdu.tag != rpki.publication_control.tag_client:
              raise rpki.exceptions.BadQuery("PDU is %s, expected client" % q_pdu.tag)
            client_handle = q_pdu.get("client_handle")
            action = q_pdu.get("action")
            if client_handle is None:
              logger.info("Control %s request", action)
            else:
              logger.info("Control %s request for %s", action, client_handle)

            if action in ("get", "list"):
              if action == "get":
                clients = rpki.pubdb.models.Client.objects.get(client_handle = client_handle),
              else:
                clients = rpki.pubdb.models.Client.objects.all()
              for client in clients:
                r_pdu = SubElement(r_msg, q_pdu.tag, action = action,
                                   client_handle = client.client_handle, base_uri = client.base_uri)
                if q_pdu.get("tag"):
                  r_pdu.set("tag", q_pdu.get("tag"))
                SubElement(r_pdu, rpki.publication_control.tag_bpki_cert).text = client.bpki_cert.get_Base64()
                if client.bpki_glue is not None:
                  SubElement(r_pdu, rpki.publication_control.tag_bpki_glue).text = client.bpki_glue.get_Base64()

            if action in ("create", "set"):
              if action == "create":
                client = rpki.pubdb.models.Client(client_handle = client_handle)
              else:
                client = rpki.pubdb.models.Client.objects.get(client_handle = client_handle)
              if q_pdu.get("base_uri"):
                client.base_uri = q_pdu.get("base_uri")
              bpki_cert = q_pdu.find(rpki.publication_control.tag_bpki_cert)
              if bpki_cert is not None:
                client.bpki_cert = rpki.x509.X509(Base64 = bpki_cert.text)
              bpki_glue = q_pdu.find(rpki.publication_control.tag_bpki_glue)
              if bpki_glue is not None:
                client.bpki_glue = rpki.x509.X509(Base64 = bpki_glue.text)
              if q_pdu.get("clear_replay_protection") == "yes":
                client.last_cms_timestamp = None
              client.save()
              logger.debug("Stored client_handle %s, base_uri %s, bpki_cert %r, bpki_glue %r, last_cms_timestamp %s",
                           client.client_handle, client.base_uri, client.bpki_cert, client.bpki_glue,
                           client.last_cms_timestamp)
              r_pdu = SubElement(r_msg, q_pdu.tag, action = action, client_handle = client_handle)
              if q_pdu.get("tag"):
                r_pdu.set("tag", q_pdu.get("tag"))

            if action == "destroy":
              rpki.pubdb.models.Client.objects.filter(client_handle = client_handle).delete()
              r_pdu = SubElement(r_msg, q_pdu.tag, action = action, client_handle = client_handle)
              if q_pdu.get("tag"):
                r_pdu.set("tag", q_pdu.get("tag"))

      except Exception, e:
        logger.exception("Exception processing PDU %r", q_pdu)
        r_pdu = SubElement(r_msg, rpki.publication_control.tag_report_error, error_code = e.__class__.__name__)
        r_pdu.text = str(e)
        if q_pdu.get("tag") is not None:
          r_pdu.set("tag", q_pdu.get("tag"))

      request.send_cms_response(rpki.publication_control.cms_msg().wrap(r_msg, self.pubd_key, self.pubd_cert))

    except Exception, e:
      logger.exception("Unhandled exception processing control query, path %r", request.path)
      request.send_error(500, "Unhandled exception %s: %s" % (e.__class__.__name__, e))


  client_url_regexp = re.compile("/client/([-A-Z0-9_/]+)$", re.I)

  def client_handler(self, request, q_der):
    """
    Process one PDU from a client.
    """

    from django.db import transaction, connection

    try:
      connection.cursor()           # Reconnect to mysqld if necessary
      match = self.client_url_regexp.search(request.path)
      if match is None:
        raise rpki.exceptions.BadContactURL("Bad path: %s" % request.path)
      client = rpki.pubdb.models.Client.objects.get(client_handle = match.group(1))
      q_cms = rpki.publication.cms_msg(DER = q_der)
      q_msg = q_cms.unwrap((self.bpki_ta, client.bpki_cert, client.bpki_glue))
      client.last_cms_timestamp = q_cms.check_replay(client.last_cms_timestamp, client.client_handle)
      client.save()
      if q_msg.get("type") != "query":
        raise rpki.exceptions.BadQuery("Message type is %s, expected query" % q_msg.get("type"))
      r_msg = Element(rpki.publication.tag_msg, nsmap = rpki.publication.nsmap,
                      type = "reply", version = rpki.publication.version)
      delta = None
      try:
        with transaction.atomic():
          for q_pdu in q_msg:
            if q_pdu.get("uri"):
              logger.info("Client %s request for %s", q_pdu.tag, q_pdu.get("uri"))
            else:
              logger.info("Client %s request", q_pdu.tag)

            if q_pdu.tag == rpki.publication.tag_list:
              for obj in client.publishedobject_set.all():
                r_pdu = SubElement(r_msg, q_pdu.tag, uri = obj.uri, hash = obj.hash)
                if q_pdu.get("tag") is not None:
                  r_pdu.set("tag", q_pdu.get("tag"))

            else:
              assert q_pdu.tag in (rpki.publication.tag_publish, rpki.publication.tag_withdraw)
              if delta is None:
                delta = self.session.new_delta(rpki.sundial.now() + self.rrdp_expiration_interval)
              client.check_allowed_uri(q_pdu.get("uri"))
              if q_pdu.tag == rpki.publication.tag_publish:
                der = q_pdu.text.decode("base64")
                logger.info("Publishing %s", rpki.x509.uri_dispatch(q_pdu.get("uri"))(DER = der).tracking_data(q_pdu.get("uri")))
                delta.publish(client, der, q_pdu.get("uri"), q_pdu.get("hash"))
              else:
                logger.info("Withdrawing %s", q_pdu.get("uri"))
                delta.withdraw(client, q_pdu.get("uri"), q_pdu.get("hash"))
              r_pdu = SubElement(r_msg, q_pdu.tag, uri = q_pdu.get("uri"))
              if q_pdu.get("tag") is not None:
                r_pdu.set("tag", q_pdu.get("tag"))

          if delta is not None:
            delta.activate()
            self.session.generate_snapshot()
            self.session.expire_deltas()

      except Exception, e:
        logger.exception("Exception processing PDU %r", q_pdu)
        r_pdu = SubElement(r_msg, rpki.publication.tag_report_error, error_code = e.__class__.__name__)
        r_pdu.text = str(e)
        if q_pdu.get("tag") is not None:
          r_pdu.set("tag", q_pdu.get("tag"))

      else:
        if delta is not None:
          self.session.synchronize_rrdp_files(self.rrdp_publication_base, self.rrdp_uri_base)
          delta.update_rsync_files(self.publication_base)

      request.send_cms_response(rpki.publication.cms_msg().wrap(r_msg, self.pubd_key, self.pubd_cert, self.pubd_crl))

    except Exception, e:
      logger.exception("Unhandled exception processing client query, path %r", request.path)
      request.send_error(500, "Could not process PDU: %s" % e)
