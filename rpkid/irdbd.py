"""
IR database daemon.

Usage: python irdbd.py [ { -c | --config } configfile ] [ { -h | --help } ]

Default configuration file is irdbd.conf, override with --config option.

$Id$

Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")

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

import sys, os, time, getopt, urlparse, traceback, MySQLdb
import rpki.https, rpki.config, rpki.resource_set, rpki.relaxng
import rpki.exceptions, rpki.left_right, rpki.log, rpki.x509

def handler(query, path, cb):
  try:

    db.ping()

    q_msg = rpki.left_right.cms_msg.unwrap(query, (bpki_ta, rpkid_cert))

    if not isinstance(q_msg, rpki.left_right.msg) or q_msg.type != "query":
      raise rpki.exceptions.BadQuery, "Unexpected %s PDU" % repr(q_msg)

    r_msg = rpki.left_right.msg()
    r_msg.type = "reply"

    for q_pdu in q_msg:

      try:
        if not isinstance(q_pdu, rpki.left_right.list_resources_elt):
          raise rpki.exceptions.BadQuery, "Unexpected %s PDU" % repr(q_pdu)

        r_pdu = rpki.left_right.list_resources_elt()
        r_pdu.tag = q_pdu.tag
        r_pdu.self_id = q_pdu.self_id
        r_pdu.child_id = q_pdu.child_id

        cur.execute(
          """
              SELECT registrant_id, subject_name, valid_until FROM registrant
              WHERE registrant.rpki_self_id = %s AND registrant.rpki_child_id = %s
          """,
          (q_pdu.self_id, q_pdu.child_id))
        if cur.rowcount != 1:
          raise rpki.exceptions.NotInDatabase, \
                "This query should have produced a single exact match, something's messed up (rowcount = %d, self_id = %s, child_id = %s)" \
                % (cur.rowcount, q_pdu.self_id, q_pdu.child_id)

        registrant_id, subject_name, valid_until = cur.fetchone()
        r_pdu.subject_name = subject_name
        r_pdu.valid_until = valid_until.strftime("%Y-%m-%dT%H:%M:%SZ")
        r_pdu.asn  = rpki.resource_set.resource_set_as.from_sql(cur,   "SELECT start_as, end_as FROM asn WHERE registrant_id = %s", (registrant_id,))
        r_pdu.ipv4 = rpki.resource_set.resource_set_ipv4.from_sql(cur, "SELECT start_ip, end_ip FROM net WHERE registrant_id = %s AND version = 4", (registrant_id,))
        r_pdu.ipv6 = rpki.resource_set.resource_set_ipv6.from_sql(cur, "SELECT start_ip, end_ip FROM net WHERE registrant_id = %s AND version = 6", (registrant_id,))

      except Exception, data:
        rpki.log.error(traceback.format_exc())
        r_pdu = rpki.left_right.report_error_elt.from_exception(data, q_pdu.self_id)

      r_msg.append(r_pdu)

    cb(200, rpki.left_right.cms_msg.wrap(r_msg, irdbd_key, irdbd_cert))

  except rpki.async.ExitNow:
    raise

  except Exception, data:
    rpki.log.error(traceback.format_exc())

    # We only get here in cases where we couldn't or wouldn't generate
    # <report_error/>, so just return HTTP failure.

    cb(500, "Unhandled exception %s: %s" % (data.__class__.__name__, data))

os.environ["TZ"] = "UTC"
time.tzset()

rpki.log.init("irdbd")

cfg_file = "irdbd.conf"

opts, argv = getopt.getopt(sys.argv[1:], "c:h?", ["config=", "help"])
for o, a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  if o in ("-c", "--config"):
    cfg_file = a
if argv:
  raise RuntimeError, "Unexpected arguments %s" % argv

cfg = rpki.config.parser(cfg_file, "irdbd")

startup_msg = cfg.get("startup-message", "")
if startup_msg:
  rpki.log.info(startup_msg)

db = MySQLdb.connect(user   = cfg.get("sql-username"),
                     db     = cfg.get("sql-database"),
                     passwd = cfg.get("sql-password"))

cur = db.cursor()

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
