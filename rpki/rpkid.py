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
import time
import random
import logging
import weakref
import argparse
import urlparse

import tornado.gen
import tornado.web
import tornado.locks
import tornado.ioloop
import tornado.httputil
import tornado.httpclient
import tornado.httpserver

from lxml.etree import Element, SubElement, tostring as ElementToString

import rpki.resource_set
import rpki.up_down
import rpki.left_right
import rpki.x509
import rpki.config
import rpki.exceptions
import rpki.relaxng
import rpki.log
import rpki.daemonize

import rpki.rpkid_tasks


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

        self.task_queue = []
        self.task_event = tornado.locks.Event()

        self.http_client_serialize = weakref.WeakValueDictionary()

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

        self.use_internal_cron = self.cfg.getboolean("use-internal-cron", True)

        self.initial_delay = random.randint(self.cfg.getint("initial-delay-min", 10),
                                            self.cfg.getint("initial-delay-max", 120))

        # Should be much longer in production
        self.cron_period = self.cfg.getint("cron-period", 120)

        if self.use_internal_cron:
            logger.debug("Scheduling initial cron pass in %s seconds", self.initial_delay)
            tornado.ioloop.IOLoop.current().spawn_callback(self.cron_loop)

        logger.debug("Scheduling task loop")
        tornado.ioloop.IOLoop.current().spawn_callback(self.task_loop)

        rpkid = self

        class LeftRightHandler(tornado.web.RequestHandler): # pylint: disable=W0223
            @tornado.gen.coroutine
            def post(self):
                yield rpkid.left_right_handler(self)

        class UpDownHandler(tornado.web.RequestHandler):    # pylint: disable=W0223
            @tornado.gen.coroutine
            def post(self, tenant_handle, child_handle):      # pylint: disable=W0221
                yield rpkid.up_down_handler(self, tenant_handle, child_handle)

        class CronjobHandler(tornado.web.RequestHandler):   # pylint: disable=W0223
            @tornado.gen.coroutine
            def post(self):
                yield rpkid.cronjob_handler(self)

        application = tornado.web.Application((
            (r"/left-right",                                  LeftRightHandler),
            (r"/up-down/([-a-zA-Z0-9_]+)/([-a-zA-Z0-9_]+)",   UpDownHandler),
            (r"/cronjob",                                     CronjobHandler)))

        application.listen(
            address = self.http_server_host,
            port    = self.http_server_port)

        tornado.ioloop.IOLoop.current().start()

    def task_add(self, tasks):
        """
        Add zero or more tasks to the task queue.
        """

        for task in tasks:
            if task in self.task_queue:
                logger.debug("Task %r already queued", task)
            else:
                logger.debug("Adding %r to task queue", task)
                self.task_queue.append(task)

    def task_run(self):
        """
        Kick the task loop to notice recently added tasks.
        """

        self.task_event.set()

    @tornado.gen.coroutine
    def task_loop(self):
        """
        Asynchronous infinite loop to run background tasks.

        This code is a bit finicky, because it's managing a collection of
        Future objects which are running independently of the control flow
        here, and the wave function doesn't collapse until we do a yield.

        So we keep this brutally simple and don't try to hide too much of
        it in the AbstractTask class.  For similar reasons, AbstractTask
        sets aside a .future instance variable for this method's use.
        """

        logger.debug("Starting task loop")
        task_event_future = None

        while True:
            while None in self.task_queue:
                self.task_queue.remove(None)

            futures = []
            for task in self.task_queue:
                if task.future is None:
                    task.future = task.start()
                futures.append(task.future)
            if task_event_future is None:
                task_event_future = self.task_event.wait()
            futures.append(task_event_future)
            iterator = tornado.gen.WaitIterator(*futures)

            while not iterator.done():
                yield iterator.next()
                if iterator.current_future is task_event_future:
                    self.task_event.clear()
                    task_event_future = None
                    break
                else:
                    task = self.task_queue[iterator.current_index]
                    task.future = None
                    waiting = task.waiting()
                    if not waiting:
                        self.task_queue[iterator.current_index] = None
                    for task in self.task_queue:
                        if task is not None and not task.runnable.is_set():
                            logger.debug("Reenabling task %r", task)
                            task.runnable.set()
                    if waiting:
                        break

    @tornado.gen.coroutine
    def cron_loop(self):
        """
        Asynchronous infinite loop to drive internal cron cycle.
        """

        logger.debug("cron_loop(): Starting")
        assert self.use_internal_cron
        logger.debug("cron_loop(): Startup delay %d seconds", self.initial_delay)
        yield tornado.gen.sleep(self.initial_delay)
        while True:
            logger.debug("cron_loop(): Running")
            yield self.cron_run()
            logger.debug("cron_loop(): Sleeping %d seconds", self.cron_period)
            yield tornado.gen.sleep(self.cron_period)

    @tornado.gen.coroutine
    def cron_run(self):
        """
        Schedule periodic tasks and wait for them to finish.
        """

        now = rpki.sundial.now()
        logger.debug("Starting cron run")
        try:
            tenants = rpki.rpkidb.models.Tenant.objects.all()
        except:
            logger.exception("Error pulling tenants from SQL, maybe SQL server is down?")
        else:
            tasks = tuple(task for tenant in tenants for task in tenant.cron_tasks(self))
            self.task_add(tasks)
            futures = [task.wait() for task in tasks]
            self.task_run()
            yield futures
        logger.info("Finished cron run started at %s", now)

    @tornado.gen.coroutine
    def cronjob_handler(self, handler):
        """
        External trigger to schedule periodic tasks.  Obsolete for
        produciton use, but portions of the test framework still use this.
        """

        if self.use_internal_cron:
            handler.set_status(500, "Running cron internally")
        else:
            logger.debug("Starting externally triggered cron")
            yield self.cron_run()
            handler.set_status(200)
        handler.finish()

    @tornado.gen.coroutine
    def http_fetch(self, request, serialize_on_full_url = False):
        """
        Wrapper around tornado.httpclient.AsyncHTTPClient() which
        serializes requests to any particular HTTP server, to avoid
        spurious CMS replay errors.
        """

        # The current definition of "particular HTTP server" is based only
        # on the "netloc" portion of the URL, which could in theory could
        # cause deadlocks in a loopback scenario; no such deadlocks have
        # shown up in testing, but if such a thing were to occur, it would
        # look like an otherwise inexplicable HTTP timeout.  The solution,
        # should this occur, would be to use the entire URL as the lookup
        # key, perhaps only for certain protocols.
        #
        # The reason for the current scheme is that at least one protocol
        # (publication) uses RESTful URLs but has a single service-wide
        # CMS replay detection database, which translates to meaning that
        # we need to serialize all requests for that service, not just
        # requests to a particular URL.

        if serialize_on_full_url:
            netlock = request.url
        else:
            netlock = urlparse.urlparse(request.url).netloc

        try:
            lock = self.http_client_serialize[netlock]
        except KeyError:
            lock = self.http_client_serialize[netlock] = tornado.locks.Lock()

        http_client = tornado.httpclient.AsyncHTTPClient()

        with (yield lock.acquire()):
            response = yield http_client.fetch(request)

        raise tornado.gen.Return(response)

    @staticmethod
    def compose_left_right_query():
        """
        Compose top level element of a left-right query to irdbd.
        """

        return Element(rpki.left_right.tag_msg, nsmap = rpki.left_right.nsmap,
                       type = "query", version = rpki.left_right.version)

    @tornado.gen.coroutine
    def irdb_query(self, q_msg):
        """
        Perform an IRDB callback query.
        """

        q_tags = set(q_pdu.tag for q_pdu in q_msg)

        q_der = rpki.left_right.cms_msg().wrap(q_msg, self.rpkid_key, self.rpkid_cert)

        http_request = tornado.httpclient.HTTPRequest(
            url     = self.irdb_url,
            method  = "POST",
            body    = q_der,
            headers = { "Content-Type" : rpki.left_right.content_type })

        http_response = yield self.http_fetch(http_request)

        # Tornado already checked http_response.code for us

        content_type = http_response.headers.get("Content-Type")

        if content_type not in rpki.left_right.allowed_content_types:
            raise rpki.exceptions.BadContentType("HTTP Content-Type %r, expected %r" % (rpki.left_right.content_type, content_type))

        r_der = http_response.body

        r_cms = rpki.left_right.cms_msg(DER = r_der)
        r_msg = r_cms.unwrap((self.bpki_ta, self.irdb_cert))

        self.irdbd_cms_timestamp = r_cms.check_replay(self.irdbd_cms_timestamp, self.irdb_url)

        #rpki.left_right.check_response(r_msg)

        if r_msg.get("type") != "reply" or not all(r_pdu.tag in q_tags for r_pdu in r_msg):
            raise rpki.exceptions.BadIRDBReply("Unexpected response to IRDB query: %s" % r_cms.pretty_print_content())

        raise tornado.gen.Return(r_msg)

    @tornado.gen.coroutine
    def irdb_query_child_resources(self, tenant_handle, child_handle):
        """
        Ask IRDB about a child's resources.
        """

        q_msg = self.compose_left_right_query()
        SubElement(q_msg, rpki.left_right.tag_list_resources, tenant_handle = tenant_handle, child_handle = child_handle)

        r_msg = yield self.irdb_query(q_msg)

        if len(r_msg) != 1:
            raise rpki.exceptions.BadIRDBReply("Expected exactly one PDU from IRDB: %s" % r_msg.pretty_print_content())

        bag = rpki.resource_set.resource_bag(
            asn         = rpki.resource_set.resource_set_as(r_msg[0].get("asn")),
            v4          = rpki.resource_set.resource_set_ipv4(r_msg[0].get("ipv4")),
            v6          = rpki.resource_set.resource_set_ipv6(r_msg[0].get("ipv6")),
            valid_until = rpki.sundial.datetime.fromXMLtime(r_msg[0].get("valid_until")))

        raise tornado.gen.Return(bag)

    @tornado.gen.coroutine
    def irdb_query_roa_requests(self, tenant_handle):
        """
        Ask IRDB about self's ROA requests.
        """

        q_msg = self.compose_left_right_query()
        SubElement(q_msg, rpki.left_right.tag_list_roa_requests, tenant_handle = tenant_handle)
        r_msg = yield self.irdb_query(q_msg)
        raise tornado.gen.Return(r_msg)

    @tornado.gen.coroutine
    def irdb_query_ghostbuster_requests(self, tenant_handle, parent_handles):
        """
        Ask IRDB about self's ghostbuster record requests.
        """

        q_msg = self.compose_left_right_query()
        for parent_handle in parent_handles:
            SubElement(q_msg, rpki.left_right.tag_list_ghostbuster_requests,
                       tenant_handle = tenant_handle, parent_handle = parent_handle)
        r_msg = yield self.irdb_query(q_msg)
        raise tornado.gen.Return(r_msg)

    @tornado.gen.coroutine
    def irdb_query_ee_certificate_requests(self, tenant_handle):
        """
        Ask IRDB about self's EE certificate requests.
        """

        q_msg = self.compose_left_right_query()
        SubElement(q_msg, rpki.left_right.tag_list_ee_certificate_requests, tenant_handle = tenant_handle)
        r_msg = yield self.irdb_query(q_msg)
        raise tornado.gen.Return(r_msg)

    @property
    def left_right_models(self):
        """
        Map element tag to rpkidb model.
        """

        # pylint: disable=W0621,W0201

        try:
            return self._left_right_models
        except AttributeError:
            import rpki.rpkidb.models
            self._left_right_models = {
                rpki.left_right.tag_tenant      : rpki.rpkidb.models.Tenant,
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

        # pylint: disable=W0201

        try:
            return self._left_right_trivial_handlers
        except AttributeError:
            self._left_right_trivial_handlers = {
                rpki.left_right.tag_list_published_objects  : self.handle_list_published_objects,
                rpki.left_right.tag_list_received_resources : self.handle_list_received_resources }
            return self._left_right_trivial_handlers

    def handle_list_published_objects(self, q_pdu, r_msg):
        """
        <list_published_objects/> server.
        """

        tenant_handle = q_pdu.get("tenant_handle")
        msg_tag       = q_pdu.get("tag")

        kw = dict(tenant_handle = tenant_handle)
        if msg_tag is not None:
            kw.update(tag = msg_tag)

        for ca_detail in rpki.rpkidb.models.CADetail.objects.filter(ca__parent__tenant__tenant_handle = tenant_handle, state = "active"):
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
        tenant_handle = q_pdu.get("tenant_handle")
        msg_tag       = q_pdu.get("tag")
        for ca_detail in rpki.rpkidb.models.CADetail.objects.filter(ca__parent__tenant__tenant_handle = tenant_handle,
                                                                    state = "active", latest_ca_cert__isnull = False):
            cert      = ca_detail.latest_ca_cert
            resources = cert.get_3779resources()
            r_pdu = SubElement(r_msg, rpki.left_right.tag_list_received_resources,
                               tenant_handle      = tenant_handle,
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

    @tornado.gen.coroutine
    def left_right_handler(self, handler):
        """
        Process one left-right message.
        """

        content_type = handler.request.headers["Content-Type"]
        if content_type not in rpki.left_right.allowed_content_types:
            handler.set_status(415, "No handler for Content-Type %s" % content_type)
            handler.finish()
            return

        handler.set_header("Content-Type", rpki.left_right.content_type)

        try:
            q_cms = rpki.left_right.cms_msg(DER = handler.request.body)
            q_msg = q_cms.unwrap((self.bpki_ta, self.irbe_cert))
            r_msg = Element(rpki.left_right.tag_msg, nsmap = rpki.left_right.nsmap,
                            type = "reply", version = rpki.left_right.version)
            self.irbe_cms_timestamp = q_cms.check_replay(self.irbe_cms_timestamp, handler.request.path)

            assert q_msg.tag.startswith(rpki.left_right.xmlns)
            assert all(q_pdu.tag.startswith(rpki.left_right.xmlns) for q_pdu in q_msg)

            if q_msg.get("version") != rpki.left_right.version:
                raise rpki.exceptions.BadQuery("Unrecognized protocol version")

            if q_msg.get("type") != "query":
                raise rpki.exceptions.BadQuery("Message type is not query")

            for q_pdu in q_msg:

                try:
                    action = q_pdu.get("action")
                    model  = self.left_right_models.get(q_pdu.tag)

                    if q_pdu.tag in self.left_right_trivial_handlers:
                        self.left_right_trivial_handlers[q_pdu.tag](q_pdu, r_msg)

                    elif action in ("get", "list"):
                        for obj in model.objects.xml_list(q_pdu):
                            obj.xml_template.encode(obj, q_pdu, r_msg)

                    elif action == "destroy":
                        obj = model.objects.xml_get_for_delete(q_pdu)
                        yield obj.xml_pre_delete_hook(self)
                        obj.delete()
                        obj.xml_template.acknowledge(obj, q_pdu, r_msg)

                    elif action in ("create", "set"):
                        obj = model.objects.xml_get_or_create(q_pdu)
                        obj.xml_template.decode(obj, q_pdu)
                        obj.xml_pre_save_hook(q_pdu)
                        obj.save()
                        yield obj.xml_post_save_hook(self, q_pdu)
                        obj.xml_template.acknowledge(obj, q_pdu, r_msg)

                    else:
                        raise rpki.exceptions.BadQuery("Unrecognized action %r" % action)

                except Exception, e:
                    if not isinstance(e, rpki.exceptions.NotFound):
                        logger.exception("Unhandled exception serving left-right PDU %r", q_pdu)
                    error_tenant_handle = q_pdu.get("tenant_handle")
                    error_tag           = q_pdu.get("tag")
                    r_pdu = SubElement(r_msg, rpki.left_right.tag_report_error, error_code = e.__class__.__name__)
                    r_pdu.text = str(e)
                    if error_tag is not None:
                        r_pdu.set("tag", error_tag)
                    if error_tenant_handle is not None:
                        r_pdu.set("tenant_handle", error_tenant_handle)
                    break

            handler.set_status(200)
            handler.finish(rpki.left_right.cms_msg().wrap(r_msg, self.rpkid_key, self.rpkid_cert))

        except Exception, e:
            logger.exception("Unhandled exception serving left-right request")
            handler.set_status(500, "Unhandled exception %s: %s" % (e.__class__.__name__, e))
            handler.finish()

    @tornado.gen.coroutine
    def up_down_handler(self, handler, tenant_handle, child_handle):
        """
        Process one up-down PDU.
        """

        content_type = handler.request.headers["Content-Type"]
        if content_type not in rpki.up_down.allowed_content_types:
            handler.set_status(415, "No handler for Content-Type %s" % content_type)
            handler.finish()
            return

        try:
            child = rpki.rpkidb.models.Child.objects.get(tenant__tenant_handle = tenant_handle, child_handle = child_handle)
            q_der = handler.request.body
            r_der = yield child.serve_up_down(self, q_der)
            handler.set_header("Content-Type", rpki.up_down.content_type)
            handler.set_status(200)
            handler.finish(r_der)

        except rpki.rpkidb.models.Child.DoesNotExist:
            logger.info("Child %r of tenant %r not found", child_handle, tenant_handle)
            handler.set_status(400, "Child %r not found" % child_handle)
            handler.finish()

        except Exception, e:
            logger.exception("Unhandled exception processing up-down request")
            handler.set_status(400, "Could not process PDU: %s" % e)
            handler.finish()


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

        rid = repository.peer_contact_uri
        if rid not in self.repositories:
            self.repositories[rid] = repository
            self.msgs[rid] = Element(rpki.publication.tag_msg, nsmap = rpki.publication.nsmap,
                                     type = "query", version = rpki.publication.version)

        if self.replace and uri in self.uris:
            logger.debug("Removing publication duplicate %r hash %s", self.uris[uri], self.uris[uri].get("hash"))
            old_pdu = self.uris.pop(uri)
            self.msgs[rid].remove(old_pdu)
            pdu_hash = old_pdu.get("hash")
            if pdu_hash is None and new_obj is None:
                logger.debug("Withdrawing object %r which was never published simplifies to no-op", old_pdu)
                return
        elif old_hash is not None:
            logger.debug("Old hash supplied")                   # XXX Debug log
            pdu_hash = old_hash
        elif old_obj is None:
            logger.debug("No old object present")               # XXX Debug log
            pdu_hash = None
        else:
            logger.debug("Calculating hash of old object")      # XXX Debug log
            pdu_hash = rpki.x509.sha256(old_obj.get_DER()).encode("hex")

        logger.debug("uri %s old hash %s new hash %s", uri, pdu_hash, # XXX Debug log
                     None if new_obj is None else rpki.x509.sha256(new_obj.get_DER()).encode("hex"))

        if new_obj is None:
            pdu = SubElement(self.msgs[rid], rpki.publication.tag_withdraw, uri = uri, hash = pdu_hash)
        else:
            pdu = SubElement(self.msgs[rid], rpki.publication.tag_publish,  uri = uri)
            pdu.text = new_obj.get_Base64()
            if pdu_hash is not None:
                pdu.set("hash", pdu_hash)

        if handler is not None:
            self.handlers[uri] = handler

        if self.replace:
            self.uris[uri] = pdu

    @tornado.gen.coroutine
    def call_pubd(self):
        for rid in self.repositories:
            logger.debug("Calling pubd[%r]", self.repositories[rid])
            yield self.repositories[rid].call_pubd(self.rpkid, self.msgs[rid], self.handlers)
        self.clear()

    @property
    def size(self):
        return sum(len(self.msgs[rid]) for rid in self.repositories)

    def empty(self):
        return not self.msgs
