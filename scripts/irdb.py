# $Id$

import rpki.https, tlslite.api, rpki.config, rpki.resource_set, MySQLdb, rpki.cms

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
      assert isinstance(q_pdu, rpki.left_right.list_resources_elt) and \
             q_pdu.type == "query" and \
             len(q_pdu.resources) == 0

      org_id = q_pdu.child_id
      if org_id is None:
        org_id = q_pdu.self_id
      cur.execute("""SELECT resource_class_id, subject_name
                     FROM registrant, resource_class
                     WHERE registrant.IRBE_mapped_id = '%s'
                     AND   registrant.registrant_id = resource_class.registrant_id
                  """ % org_id)
      resource_classes = cur.fetchall()

      r_pdu = rpki.left_right.list_resources_elt()
      r_pdu.type = "reply"
      r_pdu.self_id = q_pdu.self_id
      r_pdu.child_id = q_pdu.child_id

      # Hmm, I screwed up when I described this table to Tim,
      # valid_until should be on the top-level "registrant" table, not
      # the "resource_class" table.  It's an optional attribute in the
      # XML so just punt it for now.

      for resource_class_id, subject_name in resource_classes:
        resource_class = rpki.left_right.resource_class_elt()
        if subject_name:
          resource_class.subject_name = subject_name

        resource_class.as = rpki.resource_set.resource_set_as()
        resource_class.as.from_sql(cur,
                                   """SELECT start_as, end_as FROM asn
                                      WHERE resource_class_id = '%s'
                                   """ % resource_class_id)

        resource_class.ipv4 = rpki.resource_set.resource_set_ipv4()
        resource_class.ipv4.from_sql(cur,
                                     """SELECT start_ip, end_ip FROM net
                                        WHERE resource_class_id = '%s' AND version = 4
                                     """ % resource_class_id)

        resource_class.ipv6 = rpki.resource_set.resource_set_ipv6()
        resource_class.ipv6.from_sql(cur,
                                     """SELECT start_ip, end_ip FROM net
                                        WHERE resource_class_id = '%s' AND version = 6
                                     """ % resource_class_id)

        r_pdu.resources.append(resource_class)

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
section = "irdb"

db = MySQLdb.connect(user   = cfg.get(section, "sql-username"),
                     db     = cfg.get(section, "sql-database"),
                     passwd = cfg.get(section, "sql-password"))

cur = db.cursor()

cms_ta = cfg.get(section, "cms-ta")

privateKey = rpki.x509.RSA_Keypair(PEM_file = cfg.get(section, "https-key"))

certChain = rpki.x509.X509_chain()
certChain.load_from_PEM(cfg.multiget(section, "https-cert"))

rpki.https.server(privateKey=privateKey, certChain=certChain, handlers={"/" : handler})
