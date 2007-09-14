# $Id$

"""
Start at the RPKI daemon.  This isn't real yet.  So far it's just a
framework onto which I'm bolting various parts for testing.
"""

import rpki.https, tlslite.api, rpki.config, rpki.resource_set, MySQLdb, rpki.cms

def left_right_handler(query, path):
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

      # Do something useful here

      raise NotImplementedError

      r_msg.append(r_pdu)

    r_elt = r_msg.toXML()
    rng.assertValid(r_elt)
    r_xml = lxml.etree.tostring(r_elt, pretty_print=True, encoding="us-ascii", xml_declaration=True)
    r_cms = rpki.cms.encode(r_xml, cfg.get(section, "cms-key"), cfg.multiget(section, "cms-cert"))

    return 200, r_cms

  except Exception, data:
    return 500, "Unhandled exception %s" % data

def up_down_handler(query, path):
  raise NotImplementedError

def cronjob_handler(query, path):
  raise NotImplementedError

cfg = rpki.config.parser("re.conf")
section = "rpki"

db = MySQLdb.connect(user   = cfg.get(section, "sql-username"),
                     db     = cfg.get(section, "sql-database"),
                     passwd = cfg.get(section, "sql-password"))

cur = db.cursor()

cms_ta = cfg.get(section, "cms-ta")

privateKey = rpki.x509.RSA_Keypair(PEM_file = cfg.get(section, "https-key"))

certChain = rpki.x509.X509_chain()
certChain.load_from_PEM(cfg.multiget(section, "https-cert"))

rpki.https.server(privateKey=privateKey,
                  certChain=certChain,
                  handlers={"/left-right" : left_right_handler,
                            "/up-down"    : up_down_handler,
                            "/cronjob"    : cronjob_handler })
