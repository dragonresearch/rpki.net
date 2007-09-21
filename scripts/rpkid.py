# $Id$

"""
Start at the RPKI daemon.  This isn't real yet.  So far it's just a
framework onto which I'm bolting various parts for testing.
"""

import tlslite.api, MySQLdb, xml.sax, lxml.etree, lxml.sax, POW, POW.pkix, traceback
import rpki.https, rpki.config, rpki.resource_set, rpki.up_down, rpki.left_right, rpki.relaxng, rpki.cms, rpki.exceptions

def decode(msg, cms_ta):
  return lxml.etree.fromstring(rpki.cms.decode(msg, cms_ta))

def encode(msg, cms_key, cms_certs):
  return rpki.cms.encode(lxml.etree.tostring(msg, pretty_print=True, encoding="us-ascii", xml_declaration=True), cms_key, cms_certs)

def left_right_handler(query, path):
  try:
    q_elt = decode(query, cms_ta_irbe)
    rpki.relaxng.left_right.assertValid(q_elt)
    q_msg = rpki.left_right.sax_handler.saxify(q_elt)
    r_msg = q_msg.serve_top_level(db, cur)
    r_elt = r_msg.toXML()
    rpki.relaxng.left_right.assertValid(r_elt)
    return 200, encode(r_elt, cms_key, cms_certs)
  except Exception, data:
    traceback.print_exc()
    return 500, "Unhandled exception %s" % data

def up_down_handler(query, path):
  try:
    child_id = path.partition("/up-down/")[2]
    if not child_id.isdigit():
      raise rpki.exceptions.BadContactURL, "Bad path: %s" % path
    child = rpki.left_right.child_elt.sql_fetch(db, cur, long(child_id))
    if child is None:
      raise rpki.exceptions.NotFound, "Could not find CMS TA to verify request"
    bsc = rpki.left_right.bsc_elt.sql_fetch(db, cur, child.bsc_id)

    q_elt = decode(query, child.peer_ta)
    rpki.relaxng.up_down.assertValid(q_elt)
    q_msg = rpki.up_down.sax_handler.saxify(q_elt)
    r_msg = q_msg.serve_top_level(db, cur)
    r_elt = r_msg.toXML()
    rpki.relaxng.up_down.assertValid(r_elt)
    return 200, encode(r_elt, bsc.private_key_id, bsc.signing_cert)
  except Exception, data:
    traceback.print_exc()
    return 500, "Unhandled exception %s" % data

def cronjob_handler(query, path):
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
                            ("/up-down/",   up_down_handler),
                            ("/cronjob",    cronjob_handler)))
