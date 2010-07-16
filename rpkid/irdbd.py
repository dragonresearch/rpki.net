"""
IR database daemon.

Usage: python irdbd.py [ { -c | --config } configfile ] [ { -h | --help } ]

Default configuration file is irdbd.conf, override with --config option.

$Id$

Copyright (C) 2009  Internet Systems Consortium ("ISC")

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
import rpki.https, rpki.config, rpki.resource_set, rpki.relaxng
import rpki.exceptions, rpki.left_right, rpki.log, rpki.x509

# Silence warning while loading MySQLdb in Python 2.6, sigh
if hasattr(warnings, "catch_warnings"):
  with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    import MySQLdb
else:
  import MySQLdb

def handle_list_resources(q_pdu, r_msg):

  r_pdu = rpki.left_right.list_resources_elt()
  r_pdu.tag = q_pdu.tag
  r_pdu.self_handle = q_pdu.self_handle
  r_pdu.child_handle = q_pdu.child_handle

  cur.execute(
    "SELECT registrant_id, valid_until FROM registrant WHERE registry_handle = %s AND registrant_handle = %s",
    (q_pdu.self_handle, q_pdu.child_handle))

  if cur.rowcount != 1:
    raise rpki.exceptions.NotInDatabase, \
          "This query should have produced a single exact match, something's messed up (rowcount = %d, self_handle = %s, child_handle = %s)" \
          % (cur.rowcount, q_pdu.self_handle, q_pdu.child_handle)

  registrant_id, valid_until = cur.fetchone()

  r_pdu.valid_until = valid_until.strftime("%Y-%m-%dT%H:%M:%SZ")

  r_pdu.asn  = rpki.resource_set.resource_set_as.from_sql(
    cur,
    "SELECT start_as, end_as FROM registrant_asn WHERE registrant_id = %s",
    (registrant_id,))

  r_pdu.ipv4 = rpki.resource_set.resource_set_ipv4.from_sql(
    cur,
    "SELECT start_ip, end_ip FROM registrant_net WHERE registrant_id = %s AND version = 4",
    (registrant_id,))

  r_pdu.ipv6 = rpki.resource_set.resource_set_ipv6.from_sql(
    cur,
    "SELECT start_ip, end_ip FROM registrant_net WHERE registrant_id = %s AND version = 6",
    (registrant_id,))

  r_msg.append(r_pdu)

def handle_list_roa_requests(q_pdu, r_msg):

  cur.execute(
    "SELECT roa_request_id, asn FROM roa_request WHERE roa_request_handle = %s",
    (q_pdu.self_handle,))

  for roa_request_id, asn in cur.fetchall():

    r_pdu = rpki.left_right.list_roa_requests_elt()
    r_pdu.tag = q_pdu.tag
    r_pdu.self_handle = q_pdu.self_handle
    r_pdu.asn = asn

    r_pdu.ipv4 = rpki.resource_set.roa_prefix_set_ipv4.from_sql(
      cur,
      "SELECT prefix, prefixlen, max_prefixlen FROM roa_request_prefix WHERE roa_request_id = %s AND version = 4",
      (roa_request_id,))

    r_pdu.ipv6 = rpki.resource_set.roa_prefix_set_ipv6.from_sql(
      cur,
      "SELECT prefix, prefixlen, max_prefixlen FROM roa_request_prefix WHERE roa_request_id = %s AND version = 6",
      (roa_request_id,))

    r_msg.append(r_pdu)

handle_dispatch = {
  rpki.left_right.list_resources_elt : handle_list_resources,
  rpki.left_right.list_roa_requests_elt : handle_list_roa_requests }

def handler(query, path, cb):
  try:

    db.ping(True)

    r_msg = rpki.left_right.msg.reply()

    try:

      q_msg = rpki.left_right.cms_msg.unwrap(query, (bpki_ta, rpkid_cert))

      if not isinstance(q_msg, rpki.left_right.msg) or not q_msg.is_query():
        raise rpki.exceptions.BadQuery, "Unexpected %r PDU" % q_msg

      for q_pdu in q_msg:

        try:
          if type(q_pdu) not in handle_dispatch:
            raise rpki.exceptions.BadQuery, "Unexpected %r PDU" % q_pdu
          handle_dispatch[type(q_pdu)](q_pdu, r_msg)

        except (rpki.async.ExitNow, SystemExit):
          raise

        except Exception, data:
          rpki.log.traceback()
          r_msg.append(rpki.left_right.report_error_elt.from_exception(data, q_pdu.self_handle, q_pdu.tag))

    except (rpki.async.ExitNow, SystemExit):
      raise

    except Exception, data:
      rpki.log.traceback()
      r_msg.append(rpki.left_right.report_error_elt.from_exception(data))

    cb(200, rpki.left_right.cms_msg.wrap(r_msg, irdbd_key, irdbd_cert))

  except (rpki.async.ExitNow, SystemExit):
    raise

  except Exception, data:
    rpki.log.traceback()

    # We only get here in cases where we couldn't or wouldn't generate
    # <report_error/>, so just return HTTP failure.

    cb(500, "Unhandled exception %s: %s" % (data.__class__.__name__, data))

os.environ["TZ"] = "UTC"
time.tzset()

cfg_file = "irdbd.conf"

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

cfg = rpki.config.parser(cfg_file, "irdbd")

startup_msg = cfg.get("startup-message", "")
if startup_msg:
  rpki.log.info(startup_msg)

cfg.set_global_flags()

db = MySQLdb.connect(user   = cfg.get("sql-username"),
                     db     = cfg.get("sql-database"),
                     passwd = cfg.get("sql-password"))

cur = db.cursor()
db.autocommit(True)

bpki_ta         = rpki.x509.X509(Auto_file = cfg.get("bpki-ta"))
rpkid_cert      = rpki.x509.X509(Auto_file = cfg.get("rpkid-cert"))
irdbd_cert      = rpki.x509.X509(Auto_file = cfg.get("irdbd-cert"))
irdbd_key       = rpki.x509.RSA( Auto_file = cfg.get("irdbd-key"))

u = urlparse.urlparse(cfg.get("https-url"))

assert u.scheme in ("", "https") and \
       u.username is None and \
       u.password is None and \
       u.params   == "" and \
       u.query    == "" and \
       u.fragment == ""

rpki.https.server(server_key   = irdbd_key,
                  server_cert  = irdbd_cert,
                  client_ta    = (bpki_ta, rpkid_cert),
                  host         = u.hostname or "localhost",
                  port         = u.port or 443,
                  handlers     = ((u.path, handler),))
