# $Id$

import tlslite.api, MySQLdb
import rpki.https, rpki.config, rpki.resource_set, rpki.cms

def handler(query, path):
  try:
    q_xml = rpki.cms.decode(query, cms_ta)
    print q_xml
    q_elt = lxml.etree.fromstring(q_xml)
    rng.assertValid(q_elt)
    saxer = rpki.left_right.sax_handler()
    lxml.sax.saxify(q_elt, saxer)
    q_msg = saxer.result
    assert instanceof(q_msg, rpki.left_right.msg)
    r_msg = rpki.left_right.msg()
    for q_pdu in q_msg:
      assert isinstance(q_pdu, rpki.left_right.list_resources_elt) and q_pdu.type == "query"

      r_pdu = rpki.left_right.list_resources_elt()
      r_pdu.type = "reply"
      r_pdu.self_id = q_pdu.self_id
      r_pdu.child_id = q_pdu.child_id

      if q_pdu.child_id is not None:
        field = "child_id"
      else:
        field = "self_id"

      cur.execute("SELECT registrant_id, subject_name, valid_until FROM registrant WHERE registrant.%s = %s" % (field, getattr(q_pdu, field)))
      assert cur.rowcount == 1, "This query should have produced a single exact match, something's messed up (self_id = %s, child_id = %s)" % (self_id, child_id)

      registrant_id, subject_name, valid_until = cur.fetchone()
      r_pdu.subject_name = subject_name
      r_pdu.valid_until = valid_until.strftime("%Y-%m-%dT%H:%M:%SZ")
      r_pdu.as   = rpki.resource_set.resource_set_as.from_sql(cur,   "SELECT start_as, end_as FROM asn WHERE registrant_id = %s" % registrant_id)
      r_pdu.ipv4 = rpki.resource_set.resource_set_ipv4.from_sql(cur, "SELECT start_ip, end_ip FROM net WHERE registrant_id = %s AND version = 4" % registrant_id)
      r_pdu.ipv6 = rpki.resource_set.resource_set_ipv6.from_sql(cur, "SELECT start_ip, end_ip FROM net WHERE registrant_id = %s AND version = 6" % registrant_id)
      r_msg.append(r_pdu)

    r_elt = r_msg.toXML()
    rng.assertValid(r_elt)
    r_xml = lxml.etree.tostring(r_elt, pretty_print=True, encoding="us-ascii", xml_declaration=True)
    r_cms = rpki.cms.encode(r_xml, cfg.get(section, "cms-key"), cfg.multiget(section, "cms-cert"))

    return 200, r_cms

  except Exception, data:
    # This should generate a <report_error/> PDU, but this will do for initial debugging
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

rpki.https.server(privateKey = rpki.x509.RSA(Auto_file = cfg.get(cfg_section, "https-key")),
                  certChain  = rpki.x509.X509_chain(Auto_files = cfg.multiget(cfg_section, "https-cert")),
                  host       = cfg.get(cfg_section, "https-host"),
                  port       = int(cfg.get(cfg_section, "https-port")),
                  handlers   = { cfg.get(cfg_section, "https-url") : handler })
