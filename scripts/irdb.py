# $Id$

import rpki.https, tlslite.api, rpki.config, MySQLdb

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
      # XML so maybe just punt it for now.

      for resource_class_id, subject_name in resource_classes:
        cur.execute("""SELECT start_as, end_as
                       FROM asn
                       WHERE resource_class_id = '%s'
                    """ % resource_class_id)
        as_ranges = cur.fetchall()
        cur.execute("""SELECT start_ip, end_ip, version
                       FROM net
                       WHERE resource_class_id = '%s'
                    """ % resource_class_id)
        ip_ranges = cur.fetchall()
        

    assert False, "Not finished"

    return 200, "Something more useful than this string, please"

  except Exception, data:
    # This should generate a <report_error/> PDU, but this will do for initial debugging
    return 500, "Unhandled exception %s" % data

cfg = rpki.config.parser("irbe.conf")
section = "irdb"

db = MySQLdb.connect(user   = cfg.get(section, "username"),
                     db     = cfg.get(section, "database"),
                     passwd = cfg.get(section, "password"))

cur = db.cursor()

cms_ta = cfg.get("cms-peer")

privateKey = rpki.x509.RSA_Keypair(PEM_file = cfg.get(section, "https-key"))

certChain = rpki.x509.X509_chain()
certChain.load_from_PEM(cfg.multiget(section, "https-cert"))

rpki.https.server(privateKey=privateKey, certChain=certChain, handlers={"/" : handler})
