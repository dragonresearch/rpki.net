"""
IR database daemon.

Usage: python irdbd.py [ { -c | --config } configfile ] [ { -h | --help } ]

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

from __future__ import with_statement

import sys, os, time, getopt, urlparse, warnings
import rpki.http, rpki.config, rpki.resource_set, rpki.relaxng
import rpki.exceptions, rpki.left_right, rpki.log, rpki.x509

class main(object):

  def handle_list_resources(self, q_pdu, r_msg):
    child  = rpki.irdb.Child.objects.get(issuer__handle__exact = q_pdu.self_handle, handle = q_pdu.child_handle)
    r_pdu = rpki.left_right.list_resources_elt()
    r_pdu.tag = q_pdu.tag
    r_pdu.self_handle = q_pdu.self_handle
    r_pdu.child_handle = q_pdu.child_handle
    r_pdu.valid_until = child.valid_until.strftime("%Y-%m-%dT%H:%M:%SZ")
    r_pdu.asn = rpki.resource_set.resource_set_as.from_django(
      (a.start_as, a.end_as) for a in child.asns.all())
    r_pdu.ipv4 = rpki.resource_set.resource_set_ipv4.from_django(
      (a.start_ip, a.end_ip) for a in child.address_ranges.filter(version = 4))
    r_pdu.ipv6 = rpki.resource_set.resource_set_ipv6.from_django(
      (a.start_ip, a.end_ip) for a in child.address_ranges.filter(version = 6))
    r_msg.append(r_pdu)

  def handle_list_roa_requests(self, q_pdu, r_msg):
    for request in rpki.irdb.ROARequest.objects.filter(issuer__handle__exact = q_pdu.self_handle):
      r_pdu = rpki.left_right.list_roa_requests_elt()
      r_pdu.tag = q_pdu.tag
      r_pdu.self_handle = q_pdu.self_handle
      r_pdu.asn = request.asn
      r_pdu.ipv4 = rpki.resource_set.roa_prefix_set_ipv4.from_django(
        (p.prefix, p.prefixlen, p.max_prefixlen) for p in request.prefixes.filter(version = 4))
      r_pdu.ipv6 = rpki.resource_set.roa_prefix_set_ipv6.from_django(
        (p.prefix, p.prefixlen, p.max_prefixlen) for p in request.prefixes.filter(version = 6))
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

  def voodoo(self):
    # http://stackoverflow.com/questions/3346124/how-do-i-force-django-to-ignore-any-caches-and-reload-data
    import django.db.transaction
    with django.db.transaction.commit_manually():
      django.db.transaction.commit()

  def handler(self, query, path, cb):
    try:
      q_pdu = None
      r_msg = rpki.left_right.msg.reply()
      self.voodoo()
      serverCA = rpki.irdb.ServerCA.objects.get()
      rpkid = serverCA.ee_certificates.get(purpose = "rpkid")
      try:
        q_msg = rpki.left_right.cms_msg(DER = query).unwrap((serverCA.certificate, rpkid.certificate))
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
    from django.conf import settings

    os.environ["TZ"] = "UTC"
    time.tzset()

    cfg_file = None

    opts, argv = getopt.getopt(sys.argv[1:], "c:dh?", ["config=", "debug", "help"])
    for o, a in opts:
      if o in ("-h", "--help", "-?"):
        print __doc__
        sys.exit(0)
      if o in ("-c", "--config"):
        cfg_file = a
      elif o in ("-d", "--debug"):
        rpki.log.use_syslog = False
    if argv:
      raise rpki.exceptions.CommandParseFailure("Unexpected arguments %s" % argv)

    rpki.log.init("irdbd")

    cfg = rpki.config.parser(cfg_file, "irdbd")

    startup_msg = cfg.get("startup-message", "")
    if startup_msg:
      rpki.log.info(startup_msg)

    cfg.set_global_flags()

    settings.configure(
      DEBUG = True,
      DATABASES = { "default" : {
        "ENGINE"   : "django.db.backends.mysql",
        "NAME"     : cfg.get("sql-database"),
        "USER"     : cfg.get("sql-username"),
        "PASSWORD" : cfg.get("sql-password"),
        "HOST"     : "",
        "PORT"     : ""}},
      INSTALLED_APPS = ("rpki.irdb",),)

    import rpki.irdb

    self.dispatch_vector = {
      rpki.left_right.list_resources_elt            : self.handle_list_resources,
      rpki.left_right.list_roa_requests_elt         : self.handle_list_roa_requests,
      rpki.left_right.list_ghostbuster_requests_elt : self.handle_list_ghostbuster_requests }

    u = urlparse.urlparse(cfg.get("http-url"))

    assert u.scheme in ("", "http") and \
           u.username is None and \
           u.password is None and \
           u.params   == "" and \
           u.query    == "" and \
           u.fragment == ""

    rpki.http.server(
      host     = u.hostname or "localhost",
      port     = u.port or 443,
      handlers = ((u.path, self.handler),))
