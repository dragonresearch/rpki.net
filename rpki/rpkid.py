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
RPKI CA engine.
"""

import os
import re
import time
import random
import logging
import argparse

import rpki.resource_set
import rpki.up_down
import rpki.left_right
import rpki.x509
import rpki.http
import rpki.config
import rpki.exceptions
import rpki.relaxng
import rpki.log
import rpki.async
import rpki.daemonize
import rpki.rpkid_tasks

from lxml.etree import Element, SubElement, tostring as ElementToString

logger = logging.getLogger(__name__)


class main(object):
  """
  Main program for rpkid.
  """

  def __init__(self):

    os.environ.update(TZ = "UTC",
                      DJANGO_SETTINGS_MODULE = "rpki.django_settings.rpkid")
    time.tzset()

    self.irdbd_cms_timestamp = None
    self.irbe_cms_timestamp = None
    self.task_current = None
    self.task_queue = []

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

    rpki.log.init("rpkid", args)

    self.cfg = rpki.config.parser(set_filename = args.config, section = "rpkid")
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

    startup_msg = self.cfg.get("startup-message", "")
    if startup_msg:
      logger.info(startup_msg)

    if self.profile:
      logger.info("Running in profile mode with output to %s", self.profile)

    logger.debug("Initializing Django")

    import django
    django.setup()

    logger.debug("Initializing rpkidb...")

    global rpki                         # pylint: disable=W0602
    import rpki.rpkidb                  # pylint: disable=W0621

    logger.debug("Initializing rpkidb...done")

    self.bpki_ta    = rpki.x509.X509(Auto_update = self.cfg.get("bpki-ta"))
    self.irdb_cert  = rpki.x509.X509(Auto_update = self.cfg.get("irdb-cert"))
    self.irbe_cert  = rpki.x509.X509(Auto_update = self.cfg.get("irbe-cert"))
    self.rpkid_cert = rpki.x509.X509(Auto_update = self.cfg.get("rpkid-cert"))
    self.rpkid_key  = rpki.x509.RSA( Auto_update = self.cfg.get("rpkid-key"))

    self.irdb_url   = self.cfg.get("irdb-url")

    self.http_server_host = self.cfg.get("server-host", "")
    self.http_server_port = self.cfg.getint("server-port")

    self.publication_kludge_base = self.cfg.get("publication-kludge-base", "publication/")

    self.use_internal_cron = self.cfg.getboolean("use-internal-cron", True)

    self.initial_delay = random.randint(self.cfg.getint("initial-delay-min", 10),
                                        self.cfg.getint("initial-delay-max", 120))

    # Should be much longer in production
    self.cron_period = rpki.sundial.timedelta(seconds = self.cfg.getint("cron-period", 120))
    self.cron_keepalive = rpki.sundial.timedelta(seconds = self.cfg.getint("cron-keepalive", 0))
    if not self.cron_keepalive:
      self.cron_keepalive = self.cron_period * 4
    self.cron_timeout = None

    self.start_cron()

    rpki.http.server(
      host     = self.http_server_host,
      port     = self.http_server_port,
      handlers = (("/left-right", self.left_right_handler),
                  ("/up-down/",   self.up_down_handler, rpki.up_down.allowed_content_types),
                  ("/cronjob",    self.cronjob_handler)))

  def start_cron(self):
    """
    Start clock for rpkid's internal cron process.
    """

    if self.use_internal_cron:
      self.cron_timer = rpki.async.timer(handler = self.cron)
      when = rpki.sundial.now() + rpki.sundial.timedelta(seconds = self.initial_delay)
      logger.debug("Scheduling initial cron pass at %s", when)
      self.cron_timer.set(when)
    else:
      logger.debug("Not using internal clock, start_cron() call ignored")

  @staticmethod
  def _compose_left_right_query():
    """
    Compose top level element of a left-right query to irdbd.
    """

    return Element(rpki.left_right.tag_msg, nsmap = rpki.left_right.nsmap,
                   type = "query", version = rpki.left_right.version)

  def irdb_query(self, q_msg, callback, errback):
    """
    Perform an IRDB callback query.
    """

    try:
      q_tags = set(q_pdu.tag for q_pdu in q_msg)

      q_der = rpki.left_right.cms_msg().wrap(q_msg, self.rpkid_key, self.rpkid_cert)

      def unwrap(r_der):
        try:
          r_cms = rpki.left_right.cms_msg(DER = r_der)
          r_msg = r_cms.unwrap((self.bpki_ta, self.irdb_cert))
          self.irdbd_cms_timestamp = r_cms.check_replay(self.irdbd_cms_timestamp, self.irdb_url)
          #rpki.left_right.check_response(r_msg)
          if r_msg.get("type") != "reply" or not all(r_pdu.tag in q_tags for r_pdu in r_msg):
            raise rpki.exceptions.BadIRDBReply(
              "Unexpected response to IRDB query: %s" % r_cms.pretty_print_content())
          callback(r_msg)
        except Exception, e:
          errback(e)

      rpki.http.client(
        url          = self.irdb_url,
        msg          = q_der,
        callback     = unwrap,
        errback      = errback)

    except Exception, e:
      errback(e)


  def irdb_query_child_resources(self, self_handle, child_handle, callback, errback):
    """
    Ask IRDB about a child's resources.
    """

    q_msg = self._compose_left_right_query()
    SubElement(q_msg, rpki.left_right.tag_list_resources,
               self_handle = self_handle, child_handle = child_handle)

    def done(r_msg):
      if len(r_msg) != 1:
        raise rpki.exceptions.BadIRDBReply(
          "Expected exactly one PDU from IRDB: %s" % r_msg.pretty_print_content())
      callback(rpki.resource_set.resource_bag(
        asn         = rpki.resource_set.resource_set_as(r_msg[0].get("asn")),
        v4          = rpki.resource_set.resource_set_ipv4(r_msg[0].get("ipv4")),
        v6          = rpki.resource_set.resource_set_ipv6(r_msg[0].get("ipv6")),
        valid_until = rpki.sundial.datetime.fromXMLtime(r_msg[0].get("valid_until"))))

    self.irdb_query(q_msg, done, errback)

  def irdb_query_roa_requests(self, self_handle, callback, errback):
    """
    Ask IRDB about self's ROA requests.
    """

    q_msg = self._compose_left_right_query()
    SubElement(q_msg, rpki.left_right.tag_list_roa_requests, self_handle = self_handle)
    self.irdb_query(q_msg, callback, errback)

  def irdb_query_ghostbuster_requests(self, self_handle, parent_handles, callback, errback):
    """
    Ask IRDB about self's ghostbuster record requests.
    """

    q_msg = self._compose_left_right_query()
    for parent_handle in parent_handles:
      SubElement(q_msg, rpki.left_right.tag_list_ghostbuster_requests,
                 self_handle = self_handle, parent_handle = parent_handle)
    self.irdb_query(q_msg, callback, errback)

  def irdb_query_ee_certificate_requests(self, self_handle, callback, errback):
    """
    Ask IRDB about self's EE certificate requests.
    """

    q_msg = self._compose_left_right_query()
    SubElement(q_msg, rpki.left_right.tag_list_ee_certificate_requests, self_handle = self_handle)
    self.irdb_query(q_msg, callback, errback)

  @property
  def left_right_models(self):
    """
    Map element tag to rpkidb model.
    """

    try:
      return self._left_right_models
    except AttributeError:
      import rpki.rpkidb.models         # pylint: disable=W0621
      self._left_right_models = {
        rpki.left_right.tag_self        : rpki.rpkidb.models.Self,
        rpki.left_right.tag_bsc         : rpki.rpkidb.models.BSC,
        rpki.left_right.tag_parent      : rpki.rpkidb.models.Parent,
        rpki.left_right.tag_child       : rpki.rpkidb.models.Child,
        rpki.left_right.tag_repository  : rpki.rpkidb.models.Repository }
      return self._left_right_models

  @property
  def left_right_trivial_handlers(self):
    """
    Map element tag to bound handler methods for trivial PDU types.
    """

    try:
      return self._left_right_trivial_handlers
    except AttributeError:
      self._left_right_trivial_handlers = {
        rpki.left_right.tag_list_published_objects      : self.handle_list_published_objects,
        rpki.left_right.tag_list_received_resources     : self.handle_list_received_resources }
      return self._left_right_trivial_handlers

  def handle_list_published_objects(self, q_pdu, r_msg):
    """
    <list_published_objects/> server.
    """

    self_handle = q_pdu.get("self_handle")
    msg_tag     = q_pdu.get("tag")

    kw = dict(self_handle = self_handle)
    if msg_tag is not None:
      kw.update(tag = msg_tag)

    for ca_detail in rpki.rpkidb.models.CADetail.objects.filter(ca__parent__self__self_handle = self_handle, state = "active"):
      SubElement(r_msg, rpki.left_right.tag_list_published_objects,
                 uri = ca_detail.crl_uri, **kw).text = ca_detail.latest_crl.get_Base64()
      SubElement(r_msg, rpki.left_right.tag_list_published_objects,
                 uri = ca_detail.manifest_uri, **kw).text = ca_detail.latest_manifest.get_Base64()
      for c in ca_detail.child_certs.all():
        SubElement(r_msg, rpki.left_right.tag_list_published_objects,
                   uri = c.uri, child_handle = c.child.child_handle, **kw).text = c.cert.get_Base64()
      for r in ca_detail.roas.filter(roa__isnull = False):
        SubElement(r_msg, rpki.left_right.tag_list_published_objects,
                   uri = r.uri, **kw).text = r.roa.get_Base64()
      for g in ca_detail.ghostbusters.all():
        SubElement(r_msg, rpki.left_right.tag_list_published_objects,
                   uri = g.uri, **kw).text = g.ghostbuster.get_Base64()
      for c in ca_detail.ee_certificates.all():
        SubElement(r_msg, rpki.left_right.tag_list_published_objects,
                   uri = c.uri, **kw).text = c.cert.get_Base64()

  def handle_list_received_resources(self, q_pdu, r_msg):
    """
    <list_received_resources/> server.
    """

    logger.debug(".handle_list_received_resources() %s", ElementToString(q_pdu))
    self_handle = q_pdu.get("self_handle")
    msg_tag     = q_pdu.get("tag")
    for ca_detail in rpki.rpkidb.models.CADetail.objects.filter(ca__parent__self__self_handle = self_handle,
                                                                state = "active", latest_ca_cert__isnull = False):
      cert      = ca_detail.latest_ca_cert
      resources = cert.get_3779resources()
      r_pdu = SubElement(r_msg, rpki.left_right.tag_list_received_resources,
                         self_handle        = self_handle,
                         parent_handle      = ca_detail.ca.parent.parent_handle,
                         uri                = ca_detail.ca_cert_uri,
                         notBefore          = str(cert.getNotBefore()),
                         notAfter           = str(cert.getNotAfter()),
                         sia_uri            = cert.get_sia_directory_uri(),
                         aia_uri            = cert.get_aia_uri(),
                         asn                = str(resources.asn),
                         ipv4               = str(resources.v4),
                         ipv6               = str(resources.v6))
      if msg_tag is not None:
        r_pdu.set("tag", msg_tag)


  def left_right_handler(self, query, path, cb):
    """
    Process one left-right PDU.
    """

    # This handles five persistent classes (self, bsc, parent, child,
    # repository) and two simple queries (list_published_objects and
    # list_received_resources).  The former probably need to dispatch
    # via methods to the corresponding model classes; the latter
    # probably just become calls to ordinary methods of this
    # (rpki.rpkid.main) class.
    #
    # Need to clone logic from rpki.pubd.main.control_handler().

    logger.debug("Entering left_right_handler()")

    try:
      q_cms = rpki.left_right.cms_msg(DER = query)
      q_msg = q_cms.unwrap((self.bpki_ta, self.irbe_cert))
      r_msg = Element(rpki.left_right.tag_msg, nsmap = rpki.left_right.nsmap,
                      type = "reply", version = rpki.left_right.version)
      self.irbe_cms_timestamp = q_cms.check_replay(self.irbe_cms_timestamp, path)

      assert q_msg.tag.startswith(rpki.left_right.xmlns)
      assert all(q_pdu.tag.startswith(rpki.left_right.xmlns) for q_pdu in q_msg)

      if q_msg.get("version") != rpki.left_right.version:
        raise rpki.exceptions.BadQuery("Unrecognized protocol version")

      if q_msg.get("type") != "query":
        raise rpki.exceptions.BadQuery("Message type is not query")

      def done():
        cb(200, body = rpki.left_right.cms_msg().wrap(r_msg, self.rpkid_key, self.rpkid_cert))

      def loop(iterator, q_pdu):

        logger.debug("left_right_handler():loop(%r)", q_pdu)

        def fail(e):
          if not isinstance(e, rpki.exceptions.NotFound):
            logger.exception("Unhandled exception serving left-right PDU %r", q_pdu)
          error_self_handle = q_pdu.get("self_handle")
          error_tag         = q_pdu.get("tag")
          r_pdu = SubElement(r_msg, rpki.left_right.tag_report_error, error_code = e.__class__.__name__)
          r_pdu.text = str(e)
          if error_tag is not None:
            r_pdu.set("tag", error_tag)
          if error_self_handle is not None:
            r_pdu.set("self_handle", error_self_handle)
          cb(200, body = rpki.left_right.cms_msg().wrap(r_msg, self.rpkid_key, self.rpkid_cert))

        try:
          if q_pdu.tag in self.left_right_trivial_handlers:
            logger.debug("left_right_handler(): trivial handler")
            self.left_right_trivial_handlers[q_pdu.tag](q_pdu, r_msg)
            iterator()

          else:
            action = q_pdu.get("action")
            model  = self.left_right_models[q_pdu.tag]

            logger.debug("left_right_handler(): action %s model %r", action, model)

            if action in ("get", "list"):
              logger.debug("left_right_handler(): get/list")
              for obj in model.objects.xml_list(q_pdu):
                logger.debug("left_right_handler(): get/list: encoding %r", obj)
                obj.xml_template.encode(obj, q_pdu, r_msg)
              iterator()

            elif action == "destroy":
              def destroy_cb():
                obj.delete()
                obj.xml_template.acknowledge(obj, q_pdu, r_msg)
                iterator()
              logger.debug("left_right_handler(): destroy")
              obj = model.objects.xml_get_for_delete(q_pdu)
              obj.xml_pre_delete_hook(self, destroy_cb, fail)

            elif action in ("create", "set"):
              def create_set_cb():
                obj.xml_template.acknowledge(obj, q_pdu, r_msg)
                iterator()
              logger.debug("left_right_handler(): create/set")
              obj = model.objects.xml_get_or_create(q_pdu)
              obj.xml_template.decode(obj, q_pdu)
              obj.xml_pre_save_hook(q_pdu)
              obj.save()
              obj.xml_post_save_hook(self, q_pdu, create_set_cb, fail)

            else:
              raise rpki.exceptions.BadQuery

        except (rpki.async.ExitNow, SystemExit):
          raise
        except Exception, e:
          fail(e)

      rpki.async.iterator(q_msg, loop, done)

    except (rpki.async.ExitNow, SystemExit):
      raise

    except Exception, e:
      logger.exception("Unhandled exception serving left-right request")
      cb(500, reason = "Unhandled exception %s: %s" % (e.__class__.__name__, e))

  up_down_url_regexp = re.compile("/up-down/([-A-Z0-9_]+)/([-A-Z0-9_]+)$", re.I)

  def up_down_handler(self, q_der, path, cb):
    """
    Process one up-down PDU.
    """

    def done(r_der):
      cb(200, body = r_der)

    try:
      match = self.up_down_url_regexp.search(path)
      if match is None:
        raise rpki.exceptions.BadContactURL("Bad URL path received in up_down_handler(): %s" % path)
      self_handle, child_handle = match.groups()
      try:
        child = rpki.rpkidb.models.Child.objects.get(self__self_handle = self_handle, child_handle = child_handle)
      except rpki.rpkidb.models.Child.DoesNotExist:
        raise rpki.exceptions.ChildNotFound("Could not find child %s of self %s in up_down_handler()" % (
          child_handle, self_handle))
      child.serve_up_down(self, q_der, done)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except (rpki.exceptions.ChildNotFound, rpki.exceptions.BadContactURL), e:
      logger.warning(str(e))
      cb(400, reason = str(e))
    except Exception, e:
      logger.exception("Unhandled exception processing up-down request")
      cb(400, reason = "Could not process PDU: %s" % e)

  def checkpoint(self, force = False):
    """
    Record that we were still alive when we got here, by resetting
    keepalive timer.
    """

    if force or self.cron_timeout is not None:
      self.cron_timeout = rpki.sundial.now() + self.cron_keepalive

  def task_add(self, task):
    """
    Add a task to the scheduler task queue, unless it's already queued.
    """

    if task not in self.task_queue:
      logger.debug("Adding %r to task queue", task)
      self.task_queue.append(task)
      return True
    else:
      logger.debug("Task %r was already in the task queue", task)
      return False

  def task_next(self):
    """
    Pull next task from the task queue and put it the deferred event
    queue (we don't want to run it directly, as that could eventually
    blow out our call stack).
    """

    try:
      self.task_current = self.task_queue.pop(0)
    except IndexError:
      self.task_current = None
    else:
      rpki.async.event_defer(self.task_current)

  def task_run(self):
    """
    Run first task on the task queue, unless one is running already.
    """

    if self.task_current is None:
      self.task_next()

  def cron(self, cb = None):
    """
    Periodic tasks.
    """

    now = rpki.sundial.now()

    logger.debug("Starting cron run")

    def done():
      self.cron_timeout = None
      logger.info("Finished cron run started at %s", now)
      if cb is not None:
        cb()

    completion = rpki.rpkid_tasks.CompletionHandler(done)
    try:
      selves = rpki.rpkidb.models.Self.objects.all()
    except Exception:
      logger.exception("Error pulling selves from SQL, maybe SQL server is down?")
    else:
      for s in selves:
        s.schedule_cron_tasks(self, completion)
    nothing_queued = completion.count == 0

    assert self.use_internal_cron or self.cron_timeout is None

    if self.cron_timeout is not None and self.cron_timeout < now:
      logger.warning("cron keepalive threshold %s has expired, breaking lock", self.cron_timeout)
      self.cron_timeout = None

    if self.use_internal_cron:
      when = now + self.cron_period
      logger.debug("Scheduling next cron run at %s", when)
      self.cron_timer.set(when)

    if self.cron_timeout is None:
      self.checkpoint(self.use_internal_cron)
      self.task_run()

    elif self.use_internal_cron:
      logger.warning("cron already running, keepalive will expire at %s", self.cron_timeout)

    if nothing_queued:
      done()

  def cronjob_handler(self, query, path, cb):
    """
    External trigger for periodic tasks.  This is somewhat obsolete
    now that we have internal timers, but the test framework still
    uses it.
    """

    def done():
      cb(200, body = "OK")

    if self.use_internal_cron:
      cb(500, reason = "Running cron internally")
    else:
      logger.debug("Starting externally triggered cron")
      self.cron(done)


class publication_queue(object):
  """
  Utility to simplify publication from within rpkid.

  General idea here is to accumulate a collection of objects to be
  published, in one or more repositories, each potentially with its
  own completion callback.  Eventually we want to publish everything
  we've accumulated, at which point we need to iterate over the
  collection and do repository.call_pubd() for each repository.
  """

  replace = True

  def __init__(self, rpkid):
    self.rpkid = rpkid
    self.clear()

  def clear(self):
    self.repositories = {}
    self.msgs = {}
    self.handlers = {}
    if self.replace:
      self.uris = {}

  def queue(self, uri, repository, handler = None,
            old_obj = None, new_obj = None, old_hash = None):

    assert old_obj is not None or new_obj is not None or old_hash is not None
    assert old_obj is None or old_hash is None
    assert old_obj is None or isinstance(old_obj, rpki.x509.uri_dispatch(uri))
    assert new_obj is None or isinstance(new_obj, rpki.x509.uri_dispatch(uri))

    logger.debug("Queuing publication action: uri %s, old %r, new %r, hash %s",
                 uri, old_obj, new_obj, old_hash)

    # id(repository) may need to change to repository.peer_contact_uri
    # once we convert from our custom SQL cache to Django ORM.

    rid = id(repository)
    if rid not in self.repositories:
      self.repositories[rid] = repository
      self.msgs[rid] = Element(rpki.publication.tag_msg, nsmap = rpki.publication.nsmap,
                               type = "query", version = rpki.publication.version)

    if self.replace and uri in self.uris:
      logger.debug("Removing publication duplicate %r", self.uris[uri])
      old_pdu = self.uris.pop(uri)
      self.msgs[rid].remove(old_pdu)
      pdu_hash = old_pdu.get("hash")
    elif old_hash is not None:
      pdu_hash = old_hash
    elif old_obj is None:
      pdu_hash = None
    else:
      pdu_hash = rpki.x509.sha256(old_obj.get_DER()).encode("hex")

    if new_obj is None:
      pdu = SubElement(self.msgs[rid], rpki.publication.tag_withdraw, uri = uri, hash = pdu_hash)
    else:
      pdu = SubElement(self.msgs[rid], rpki.publication.tag_publish,  uri = uri)
      pdu.text = new_obj.get_Base64()
      if pdu_hash is not None:
        pdu.set("hash", pdu_hash)

    if handler is not None:
      tag = str(id(pdu))
      self.handlers[tag] = handler
      pdu.set("tag", tag)

    if self.replace:
      self.uris[uri] = pdu

  def call_pubd(self, cb, eb):
    def loop(iterator, rid):
      logger.debug("Calling pubd[%r]", self.repositories[rid])
      self.repositories[rid].call_pubd(self.rpkid, iterator, eb, self.msgs[rid], self.handlers)
    def done():
      self.clear()
      cb()
    rpki.async.iterator(self.repositories, loop, done)

  @property
  def size(self):
    return sum(len(self.msgs[rid]) for rid in self.repositories)

  def empty(self):
    assert (not self.msgs) == (self.size == 0), "Assertion failure: not self.msgs: %r, self.size %r" % (not self.msgs, self.size)
    return not self.msgs
