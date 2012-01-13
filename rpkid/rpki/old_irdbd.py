"""
IR database daemon.

Usage: python irdbd.py [ { -c | --config } configfile ] [ { -h | --help } ]

This is the old (pre-Django) version of irdbd, still used by smoketest
and perhaps still useful as a minimal example.

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

import sys, os, time, getopt, urlparse, warnings
import rpki.http, rpki.config, rpki.resource_set, rpki.relaxng
import rpki.exceptions, rpki.left_right, rpki.log, rpki.x509

from rpki.mysql_import import MySQLdb

class main(object):


  def handle_list_resources(self, q_pdu, r_msg):

    r_pdu = rpki.left_right.list_resources_elt()
    r_pdu.tag = q_pdu.tag
    r_pdu.self_handle = q_pdu.self_handle
    r_pdu.child_handle = q_pdu.child_handle

    self.cur.execute(
      "SELECT registrant_id, valid_until FROM registrant WHERE registry_handle = %s AND registrant_handle = %s",
      (q_pdu.self_handle, q_pdu.child_handle))

    if self.cur.rowcount != 1:
      raise rpki.exceptions.NotInDatabase, \
            "This query should have produced a single exact match, something's messed up (rowcount = %d, self_handle = %s, child_handle = %s)" \
            % (self.cur.rowcount, q_pdu.self_handle, q_pdu.child_handle)

    registrant_id, valid_until = self.cur.fetchone()

    r_pdu.valid_until = valid_until.strftime("%Y-%m-%dT%H:%M:%SZ")

    r_pdu.asn  = rpki.resource_set.resource_set_as.from_sql(
      self.cur,
      "SELECT start_as, end_as FROM registrant_asn WHERE registrant_id = %s",
      (registrant_id,))

    r_pdu.ipv4 = rpki.resource_set.resource_set_ipv4.from_sql(
      self.cur,
      "SELECT start_ip, end_ip FROM registrant_net WHERE registrant_id = %s AND version = 4",
      (registrant_id,))

    r_pdu.ipv6 = rpki.resource_set.resource_set_ipv6.from_sql(
      self.cur,
      "SELECT start_ip, end_ip FROM registrant_net WHERE registrant_id = %s AND version = 6",
      (registrant_id,))

    r_msg.append(r_pdu)


  def handle_list_roa_requests(self, q_pdu, r_msg):

    self.cur.execute(
      "SELECT roa_request_id, asn FROM roa_request WHERE roa_request_handle = %s",
      (q_pdu.self_handle,))

    for roa_request_id, asn in self.cur.fetchall():

      r_pdu = rpki.left_right.list_roa_requests_elt()
      r_pdu.tag = q_pdu.tag
      r_pdu.self_handle = q_pdu.self_handle
      r_pdu.asn = asn

      r_pdu.ipv4 = rpki.resource_set.roa_prefix_set_ipv4.from_sql(
        self.cur,
        "SELECT prefix, prefixlen, max_prefixlen FROM roa_request_prefix WHERE roa_request_id = %s AND version = 4",
        (roa_request_id,))

      r_pdu.ipv6 = rpki.resource_set.roa_prefix_set_ipv6.from_sql(
        self.cur,
        "SELECT prefix, prefixlen, max_prefixlen FROM roa_request_prefix WHERE roa_request_id = %s AND version = 6",
        (roa_request_id,))

      r_msg.append(r_pdu)


  def handle_list_ghostbuster_requests(self, q_pdu, r_msg):

    self.cur.execute(
      "SELECT vcard  FROM ghostbuster_request WHERE self_handle = %s AND parent_handle = %s",
      (q_pdu.self_handle, q_pdu.parent_handle))

    vcards = [result[0] for result in self.cur.fetchall()]

    if not vcards:

      self.cur.execute(
        "SELECT vcard  FROM ghostbuster_request WHERE self_handle = %s AND parent_handle IS NULL",
        (q_pdu.self_handle,))

      vcards = [result[0] for result in self.cur.fetchall()]

    for vcard in vcards:
      r_pdu = rpki.left_right.list_ghostbuster_requests_elt()
      r_pdu.tag = q_pdu.tag
      r_pdu.self_handle = q_pdu.self_handle
      r_pdu.parent_handle = q_pdu.parent_handle
      r_pdu.vcard = vcard
      r_msg.append(r_pdu)


  handle_dispatch = {
    rpki.left_right.list_resources_elt            : handle_list_resources,
    rpki.left_right.list_roa_requests_elt         : handle_list_roa_requests,
    rpki.left_right.list_ghostbuster_requests_elt : handle_list_ghostbuster_requests}


  def handler(self, query, path, cb):
    try:

      self.db.ping(True)

      r_msg = rpki.left_right.msg.reply()

      try:

        q_msg = rpki.left_right.cms_msg(DER = query).unwrap((self.bpki_ta, self.rpkid_cert))

        if not isinstance(q_msg, rpki.left_right.msg) or not q_msg.is_query():
          raise rpki.exceptions.BadQuery, "Unexpected %r PDU" % q_msg

        for q_pdu in q_msg:

          try:

            try:
              h = self.handle_dispatch[type(q_pdu)]
            except KeyError:
              raise rpki.exceptions.BadQuery, "Unexpected %r PDU" % q_pdu
            else:
              h(self, q_pdu, r_msg)

          except (rpki.async.ExitNow, SystemExit):
            raise

          except Exception, e:
            rpki.log.traceback()
            r_msg.append(rpki.left_right.report_error_elt.from_exception(e, q_pdu.self_handle, q_pdu.tag))

      except (rpki.async.ExitNow, SystemExit):
        raise

      except Exception, e:
        rpki.log.traceback()
        r_msg.append(rpki.left_right.report_error_elt.from_exception(e))

      cb(200, body = rpki.left_right.cms_msg().wrap(r_msg, self.irdbd_key, self.irdbd_cert))

    except (rpki.async.ExitNow, SystemExit):
      raise

    except Exception, e:
      rpki.log.traceback()

      # We only get here in cases where we couldn't or wouldn't generate
      # <report_error/>, so just return HTTP failure.

      cb(500, reason = "Unhandled exception %s: %s" % (e.__class__.__name__, e))


  def __init__(self):

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
      raise rpki.exceptions.CommandParseFailure, "Unexpected arguments %s" % argv

    rpki.log.init("irdbd")

    self.cfg = rpki.config.parser(cfg_file, "irdbd")

    startup_msg = self.cfg.get("startup-message", "")
    if startup_msg:
      rpki.log.info(startup_msg)

    self.cfg.set_global_flags()

    self.db = MySQLdb.connect(user   = self.cfg.get("sql-username"),
                              db     = self.cfg.get("sql-database"),
                              passwd = self.cfg.get("sql-password"))

    self.cur = self.db.cursor()
    self.db.autocommit(True)

    self.bpki_ta         = rpki.x509.X509(Auto_update = self.cfg.get("bpki-ta"))
    self.rpkid_cert      = rpki.x509.X509(Auto_update = self.cfg.get("rpkid-cert"))
    self.irdbd_cert      = rpki.x509.X509(Auto_update = self.cfg.get("irdbd-cert"))
    self.irdbd_key       = rpki.x509.RSA( Auto_update = self.cfg.get("irdbd-key"))

    u = urlparse.urlparse(self.cfg.get("http-url"))

    assert u.scheme in ("", "http") and \
           u.username is None and \
           u.password is None and \
           u.params   == "" and \
           u.query    == "" and \
           u.fragment == ""

    rpki.http.server(host         = u.hostname or "localhost",
                     port         = u.port or 443,
                     handlers     = ((u.path, self.handler),))
