"""
IR database daemon.

Usage: python irdbd.py [ { -c | --config } configfile ]
                       [ { -d | --debug } ]
                       [ { -f | --foreground } ]
                       [ { -h | --help } ]

$Id$

Copyright (C) 2009--2012  Internet Systems Consortium ("ISC")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.

Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import sys
import os
import time
import getopt
import urlparse
import warnings
import rpki.http
import rpki.config
import rpki.resource_set
import rpki.relaxng
import rpki.exceptions
import rpki.left_right
import rpki.log
import rpki.x509
import rpki.daemonize

class main(object):

  def handle_list_resources(self, q_pdu, r_msg):
    child  = rpki.irdb.Child.objects.get(issuer__handle__exact = q_pdu.self_handle,
                                         handle = q_pdu.child_handle)
    resources = child.resource_bag
    r_pdu = rpki.left_right.list_resources_elt()
    r_pdu.tag = q_pdu.tag
    r_pdu.self_handle = q_pdu.self_handle
    r_pdu.child_handle = q_pdu.child_handle
    r_pdu.valid_until = child.valid_until.strftime("%Y-%m-%dT%H:%M:%SZ")
    r_pdu.asn = resources.asn
    r_pdu.ipv4 = resources.v4
    r_pdu.ipv6 = resources.v6
    r_msg.append(r_pdu)

  def handle_list_roa_requests(self, q_pdu, r_msg):
    for request in rpki.irdb.ROARequest.objects.raw("""
        SELECT irdb_roarequest.*
        FROM   irdb_roarequest, irdb_resourceholderca
        WHERE  irdb_roarequest.issuer_id = irdb_resourceholderca.id
        AND    irdb_resourceholderca.handle = %s
        """, [q_pdu.self_handle]):
      prefix_bag = request.roa_prefix_bag
      r_pdu = rpki.left_right.list_roa_requests_elt()
      r_pdu.tag = q_pdu.tag
      r_pdu.self_handle = q_pdu.self_handle
      r_pdu.asn = request.asn
      r_pdu.ipv4 = prefix_bag.v4
      r_pdu.ipv6 = prefix_bag.v6
      r_msg.append(r_pdu)

  def handle_list_ghostbuster_requests(self, q_pdu, r_msg):
    ghostbusters = rpki.irdb.GhostbusterRequest.objects.filter(
      issuer__handle__exact = q_pdu.self_handle,
      parent__handle__exact = q_pdu.parent_handle)
    if ghostbusters.count() == 0:
      ghostbusters = rpki.irdb.GhostbusterRequest.objects.filter(
        issuer__handle__exact = q_pdu.self_handle,
        parent = None)
    for ghostbuster in ghostbusters:
      r_pdu = rpki.left_right.list_ghostbuster_requests_elt()
      r_pdu.tag = q_pdu.tag
      r_pdu.self_handle = q_pdu.self_handle
      r_pdu.parent_handle = q_pdu.parent_handle
      r_pdu.vcard = ghostbuster.vcard
      r_msg.append(r_pdu)

  def handler(self, query, path, cb):
    try:
      q_pdu = None
      r_msg = rpki.left_right.msg.reply()
      self.start_new_transaction()
      serverCA = rpki.irdb.ServerCA.objects.get()
      rpkid = serverCA.ee_certificates.get(purpose = "rpkid")
      try:
        q_cms = rpki.left_right.cms_msg(DER = query)
        q_msg = q_cms.unwrap((serverCA.certificate, rpkid.certificate))
        self.cms_timestamp = q_cms.check_replay(self.cms_timestamp)
        if not isinstance(q_msg, rpki.left_right.msg) or not q_msg.is_query():
          raise rpki.exceptions.BadQuery("Unexpected %r PDU" % q_msg)
        for q_pdu in q_msg:
          self.dispatch(q_pdu, r_msg)
      except (rpki.async.ExitNow, SystemExit):
        raise
      except Exception, e:
        rpki.log.traceback()
        if q_pdu is None:
          r_msg.append(rpki.left_right.report_error_elt.from_exception(e))
        else:
          r_msg.append(rpki.left_right.report_error_elt.from_exception(e, q_pdu.self_handle, q_pdu.tag))
      irdbd = serverCA.ee_certificates.get(purpose = "irdbd")
      cb(200, body = rpki.left_right.cms_msg().wrap(r_msg, irdbd.private_key, irdbd.certificate))
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception, e:
      rpki.log.traceback()
      cb(500, reason = "Unhandled exception %s: %s" % (e.__class__.__name__, e))

  def dispatch(self, q_pdu, r_msg):
    try:
      handler = self.dispatch_vector[type(q_pdu)]
    except KeyError:
      raise rpki.exceptions.BadQuery("Unexpected %r PDU" % q_pdu)
    else:
      handler(q_pdu, r_msg)

  def __init__(self, **kwargs):

    global rpki

    os.environ["TZ"] = "UTC"
    time.tzset()

    cfg_file = None
    foreground = False
    profile = None

    opts, argv = getopt.getopt(sys.argv[1:], "c:dfhp:?",
                               ["config=", "debug", "foreground", "help", "profile="])
    for o, a in opts:
      if o in ("-h", "--help", "-?"):
        print __doc__
        sys.exit(0)
      if o in ("-c", "--config"):
        cfg_file = a
      elif o in ("-d", "--debug"):
        rpki.log.use_syslog = False
        foreground = True
      elif o in ("-f", "--foreground"):
        foreground = True
      elif o in ("-p", "--profile"):
        profile = a
    if argv:
      raise rpki.exceptions.CommandParseFailure("Unexpected arguments %s" % argv)

    rpki.log.init("irdbd")

    self.cfg = rpki.config.parser(cfg_file, "irdbd")
    self.cfg.set_global_flags()

    if not foreground:
      rpki.daemonize.daemon()

    if profile:
      import cProfile
      prof = cProfile.Profile()
      try:
        prof.runcall(self.main)
      finally:
        prof.dump_stats(profile)
        rpki.log.info("Dumped profile data to %s" % profile)
    else:
      self.main()

  def main(self):

    global rpki
    from django.conf import settings

    startup_msg = self.cfg.get("startup-message", "")
    if startup_msg:
      rpki.log.info(startup_msg)

    # Do -not- turn on DEBUG here except for short-lived tests,
    # otherwise irdbd will eventually run out of memory and crash.
    #
    # If you must enable debugging, use django.db.reset_queries() to
    # clear the query list manually, but it's probably better just to
    # run with debugging disabled, since that's the expectation for
    # production code.
    #
    # https://docs.djangoproject.com/en/dev/faq/models/#why-is-django-leaking-memory

    settings.configure(
      DATABASES = {
        "default" : {
          "ENGINE"   : "django.db.backends.mysql",
          "NAME"     : self.cfg.get("sql-database"),
          "USER"     : self.cfg.get("sql-username"),
          "PASSWORD" : self.cfg.get("sql-password"),
          "HOST"     : "",
          "PORT"     : "" }},
      INSTALLED_APPS = ("rpki.irdb",),)

    import rpki.irdb

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

    self.dispatch_vector = {
      rpki.left_right.list_resources_elt            : self.handle_list_resources,
      rpki.left_right.list_roa_requests_elt         : self.handle_list_roa_requests,
      rpki.left_right.list_ghostbuster_requests_elt : self.handle_list_ghostbuster_requests }

    u = urlparse.urlparse(self.cfg.get("http-url"))

    assert u.scheme in ("", "http") and \
           u.username is None and \
           u.password is None and \
           u.params   == "" and \
           u.query    == "" and \
           u.fragment == ""

    self.cms_timestamp = None

    rpki.http.server(
      host     = u.hostname or "localhost",
      port     = u.port or 443,
      handlers = ((u.path, self.handler),))
