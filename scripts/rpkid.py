# $Id$

"""
Start at the RPKI daemon.  This isn't real yet.  So far it's just a
framework onto which I'm bolting various parts for testing.
"""

import rpki.https, tlslite.api, rpki.config, rpki.resource_set, MySQLdb, rpki.cms

def left_right_handler(query, path):
  try:
    q_elt = lxml.etree.fromstring(rpki.cms.decode(query, cms_ta))
    rng.assertValid(q_elt)
    saxer = rpki.left_right.sax_handler()
    lxml.sax.saxify(q_elt, saxer)
    q_msg = saxer.result
    r_msg = rpki.left_right.msg()
    for q_pdu in q_msg:

      # Do something useful here

      raise NotImplementedError

      r_msg.append(r_pdu)

    r_elt = r_msg.toXML()
    rng.assertValid(r_elt)
    r_cms = rpki.cms.encode(lxml.etree.tostring(r_elt, pretty_print=True, encoding="us-ascii", xml_declaration=True),
                            cms_key, cms_certs)

    return 200, r_cms

  except Exception, data:
    return 500, "Unhandled exception %s" % data

def up_down_handler(query, path):
  print "up-down handler called"
  raise NotImplementedError

def cronjob_handler(query, path):
  print "cronjob handler called"
  raise NotImplementedError

cfg = rpki.config.parser("re.conf")
section = "rpki"

db = MySQLdb.connect(user   = cfg.get(section, "sql-username"),
                     db     = cfg.get(section, "sql-database"),
                     passwd = cfg.get(section, "sql-password"))

cur = db.cursor()

cms_ta_irdb = cfg.get(section, "cms-ta-irdb")
cms_ta_irbe = cfg.get(section, "cms-ta-irbe")
cms_key     = cfg.get(section, "cms-key")
cms_certs   = cfg.multiget(section, "cms-cert")

https_key   = rpki.x509.RSA_Keypair(PEM_file = cfg.get(section, "https-key"))
https_certs = certChain = rpki.x509.X509_chain()

https_certs.load_from_PEM(cfg.multiget(section, "https-cert"))

rpki.https.server(privateKey=https_key, certChain=https_certs,
                  handlers=(("/left-right", left_right_handler),
                            ("/up-down",    up_down_handler),
                            ("/cronjob",    cronjob_handler)))
