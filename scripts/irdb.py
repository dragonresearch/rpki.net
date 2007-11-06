# $Id$

import tlslite.api, MySQLdb, urlparse, traceback, lxml.etree
import rpki.https, rpki.config, rpki.resource_set, rpki.cms, rpki.relaxng, rpki.exceptions, rpki.left_right

def handler(query, path):
  try:
    q_elt = rpki.cms.xml_verify(query, cms_ta)
    rpki.relaxng.left_right.assertValid(q_elt)
    q_msg = rpki.left_right.sax_handler.saxify(q_elt)
    if not isinstance(q_msg, rpki.left_right.msg):
      raise rpki.exceptions.BadQuery, "Unexpected %s PDU" % repr(q_msg)

    r_msg = rpki.left_right.msg()

    for q_pdu in q_msg:
      assert isinstance(q_pdu, rpki.left_right.list_resources_elt) and q_pdu.type == "query"

      r_pdu = rpki.left_right.list_resources_elt()
      r_pdu.type = "reply"
      r_pdu.self_id = q_pdu.self_id
      r_pdu.child_id = q_pdu.child_id

      cur.execute("""SELECT registrant_id, subject_name, valid_until FROM registrant
                     WHERE registrant.rpki_self_id = %s AND registrant.rpki_child_id = %s
                     """ % (q_pdu.self_id, q_pdu.child_id))
      assert cur.rowcount == 1, "This query should have produced a single exact match, something's messed up (self_id = %s, child_id = %s)" % (self_id, child_id)

      registrant_id, subject_name, valid_until = cur.fetchone()
      r_pdu.subject_name = subject_name
      r_pdu.valid_until = valid_until.strftime("%Y-%m-%dT%H:%M:%SZ")
      r_pdu.as   = rpki.resource_set.resource_set_as.from_sql(cur,   "SELECT start_as, end_as FROM asn WHERE registrant_id = %s" % registrant_id)
      r_pdu.ipv4 = rpki.resource_set.resource_set_ipv4.from_sql(cur, "SELECT start_ip, end_ip FROM net WHERE registrant_id = %s AND version = 4" % registrant_id)
      r_pdu.ipv6 = rpki.resource_set.resource_set_ipv6.from_sql(cur, "SELECT start_ip, end_ip FROM net WHERE registrant_id = %s AND version = 6" % registrant_id)
      r_msg.append(r_pdu)

    r_elt = r_msg.toXML()
    rpki.relaxng.left_right.assertValid(r_elt)
    return 200, rpki.cms.xml_sign(r_elt, cms_key, cms_certs)

  except Exception, data:
    # This should generate a <report_error/> PDU, but this will do for initial debugging
    traceback.print_exc()
    return 500, "Unhandled exception %s" % data

cfg = rpki.config.parser("irbe.conf")
cfg_section = "irdb"

db = MySQLdb.connect(user   = cfg.get(cfg_section, "sql-username"),
                     db     = cfg.get(cfg_section, "sql-database"),
                     passwd = cfg.get(cfg_section, "sql-password"))

cur = db.cursor()

cms_ta          = rpki.x509.X509(Auto_file = cfg.get(cfg_section, "cms-ta"))
cms_key         = rpki.x509.RSA(Auto_file = cfg.get(cfg_section, "cms-key"))
cms_certs       = rpki.x509.X509_chain(Auto_files = cfg.multiget(cfg_section, "cms-cert"))

u = urlparse.urlparse(cfg.get(cfg_section, "https-url"))

assert u.scheme in ("", "https") and \
       u.username is None and \
       u.password is None and \
       u.params   == "" and \
       u.query    == "" and \
       u.fragment == ""

rpki.https.server(privateKey = rpki.x509.RSA(Auto_file = cfg.get(cfg_section, "https-key")),
                  certChain  = rpki.x509.X509_chain(Auto_files = cfg.multiget(cfg_section, "https-cert")),
                  host       = u.hostname or "localhost",
                  port       = u.port or 443,
                  handlers   = ((u.path, handler),))
