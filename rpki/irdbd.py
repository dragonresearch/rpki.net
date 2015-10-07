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
IR database daemon.
"""

import os
import time
import logging
import argparse
import urlparse
import rpki.http_simple
import rpki.config
import rpki.resource_set
import rpki.relaxng
import rpki.exceptions
import rpki.left_right
import rpki.log
import rpki.x509
import rpki.daemonize

from lxml.etree import Element, SubElement

logger = logging.getLogger(__name__)

class main(object):

  def handle_list_resources(self, q_pdu, r_msg):
    self_handle  = q_pdu.get("self_handle")
    child_handle = q_pdu.get("child_handle")
    child  = rpki.irdb.Child.objects.get(
      issuer__handle__exact = self_handle,
      handle = child_handle)
    resources = child.resource_bag
    r_pdu = SubElement(r_msg, rpki.left_right.tag_list_resources, self_handle = self_handle, child_handle = child_handle,
                       valid_until = child.valid_until.strftime("%Y-%m-%dT%H:%M:%SZ"))
    for k, v in (("asn",  resources.asn),
                 ("ipv4", resources.v4),
                 ("ipv6", resources.v6),
                 ("tag",  q_pdu.get("tag"))):
      if v:
        r_pdu.set(k, str(v))

  def handle_list_roa_requests(self, q_pdu, r_msg):
    self_handle = q_pdu.get("self_handle")
    for request in rpki.irdb.ROARequest.objects.raw("""
        SELECT irdb_roarequest.*
        FROM   irdb_roarequest, irdb_resourceholderca
        WHERE  irdb_roarequest.issuer_id = irdb_resourceholderca.id
        AND    irdb_resourceholderca.handle = %s
        """, [self_handle]):
      prefix_bag = request.roa_prefix_bag
      r_pdu = SubElement(r_msg, rpki.left_right.tag_list_roa_requests, self_handle = self_handle, asn = str(request.asn))
      for k, v in (("ipv4", prefix_bag.v4),
                   ("ipv6", prefix_bag.v6),
                   ("tag",  q_pdu.get("tag"))):
        if v:
          r_pdu.set(k, str(v))

  def handle_list_ghostbuster_requests(self, q_pdu, r_msg):
    self_handle   = q_pdu.get("self_handle")
    parent_handle = q_pdu.get("parent_handle")
    ghostbusters = rpki.irdb.GhostbusterRequest.objects.filter(
      issuer__handle__exact = self_handle,
      parent__handle__exact = parent_handle)
    if ghostbusters.count() == 0:
      ghostbusters = rpki.irdb.GhostbusterRequest.objects.filter(
        issuer__handle__exact = self_handle,
        parent = None)
    for ghostbuster in ghostbusters:
      r_pdu = SubElement(r_msg, q_pdu.tag, self_handle = self_handle, parent_handle = parent_handle)
      if q_pdu.get("tag"):
        r_pdu.set("tag", q_pdu.get("tag"))
      r_pdu.text = ghostbuster.vcard

  def handle_list_ee_certificate_requests(self, q_pdu, r_msg):
    self_handle = q_pdu.get("self_handle")
    for ee_req in rpki.irdb.EECertificateRequest.objects.filter(issuer__handle__exact = self_handle):
      resources = ee_req.resource_bag
      r_pdu = SubElement(r_msg, q_pdu.tag, self_handle = self_handle, gski = ee_req.gski,
                         valid_until = ee_req.valid_until.strftime("%Y-%m-%dT%H:%M:%SZ"),
                         cn = ee_req.cn, sn = ee_req.sn)
      for k, v in (("asn",  resources.asn),
                   ("ipv4", resources.v4),
                   ("ipv6", resources.v6),
                   ("eku",  ee_req.eku),
                   ("tag",  q_pdu.get("tag"))):
        if v:
          r_pdu.set(k, str(v))
      SubElement(r_pdu, rpki.left_right.tag_pkcs10).text = ee_req.pkcs10.get_Base64()

  def handler(self, request, q_der):
    try:
      from django.db import connection
      connection.cursor()           # Reconnect to mysqld if necessary
      self.start_new_transaction()
      serverCA = rpki.irdb.ServerCA.objects.get()
      rpkid = serverCA.ee_certificates.get(purpose = "rpkid")
      irdbd = serverCA.ee_certificates.get(purpose = "irdbd")
      q_cms = rpki.left_right.cms_msg_no_sax(DER = q_der)
      q_msg = q_cms.unwrap((serverCA.certificate, rpkid.certificate))
      self.cms_timestamp = q_cms.check_replay(self.cms_timestamp, request.path)
      if q_msg.get("type") != "query":
        raise rpki.exceptions.BadQuery("Message type is %s, expected query" % q_msg.get("type"))
      r_msg = Element(rpki.left_right.tag_msg, nsmap = rpki.left_right.nsmap,
                      type = "reply", version = rpki.left_right.version)
      try:
        for q_pdu in q_msg:
          getattr(self, "handle_" + q_pdu.tag[len(rpki.left_right.xmlns):])(q_pdu, r_msg)

      except Exception, e:
        logger.exception("Exception processing PDU %r", q_pdu)
        r_pdu = SubElement(r_msg, rpki.left_right.tag_report_error, error_code = e.__class__.__name__)
        r_pdu.text = str(e)
        if q_pdu.get("tag") is not None:
          r_pdu.set("tag", q_pdu.get("tag"))

      request.send_cms_response(rpki.left_right.cms_msg_no_sax().wrap(r_msg, irdbd.private_key, irdbd.certificate))

    except Exception, e:
      logger.exception("Unhandled exception while processing HTTP request")
      request.send_error(500, "Unhandled exception %s: %s" % (e.__class__.__name__, e))

  def __init__(self, **kwargs):

    global rpki                         # pylint: disable=W0602

    os.environ.update(TZ = "UTC",
                      DJANGO_SETTINGS_MODULE = "rpki.django_settings.irdb")
    time.tzset()

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

    rpki.log.init("irdbd", args)

    self.cfg = rpki.config.parser(set_filename = args.config, section = "irdbd")
    self.cfg.set_global_flags()

    if not args.foreground:
      rpki.daemonize.daemon(pidfile = args.pidfile)

    if args.profile:
      import cProfile
      prof = cProfile.Profile()
      try:
        prof.runcall(self.main)
      finally:
        prof.dump_stats(args.profile)
        logger.info("Dumped profile data to %s", args.profile)
    else:
      self.main()

  def main(self):

    startup_msg = self.cfg.get("startup-message", "")
    if startup_msg:
      logger.info(startup_msg)

    # Now that we know which configuration file to use, it's OK to
    # load modules that require Django's settings module.

    global rpki                         # pylint: disable=W0602
    import rpki.irdb                    # pylint: disable=W0621

    # Entirely too much fun with read-only access to transactional databases.
    #
    # http://stackoverflow.com/questions/3346124/how-do-i-force-django-to-ignore-any-caches-and-reload-data
    # http://devblog.resolversystems.com/?p=439
    # http://groups.google.com/group/django-users/browse_thread/thread/e25cec400598c06d
    # http://stackoverflow.com/questions/1028671/python-mysqldb-update-query-fails
    # http://dev.mysql.com/doc/refman/5.0/en/set-transaction.html
    #
    # It turns out that MySQL is doing us a favor with this weird
    # transactional behavior on read, because without it there's a
    # race condition if multiple updates are committed to the IRDB
    # while we're in the middle of processing a query.  Note that
    # proper transaction management by the committers doesn't protect
    # us, this is a transactional problem on read.  So we need to use
    # explicit transaction management.  Since irdbd is a read-only
    # consumer of IRDB data, this means we need to commit an empty
    # transaction at the beginning of processing each query, to reset
    # the transaction isolation snapshot.

    import django.db.transaction
    self.start_new_transaction = django.db.transaction.commit_manually(django.db.transaction.commit)

    self.http_server_host = self.cfg.get("server-host", "")
    self.http_server_port = self.cfg.getint("server-port")

    self.cms_timestamp = None

    rpki.http_simple.server(
      host     = self.http_server_host,
      port     = self.http_server_port,
      handlers = self.handler)
