# $Id$

"""
Start at the RPKI daemon.  This isn't real yet.  So far it's just a
framework onto which I'm bolting various parts for testing.
"""

import tlslite.api, MySQLdb, xml.sax, lxml.etree, lxml.sax, POW, POW.pkix, traceback, os, time
import rpki.https, rpki.config, rpki.resource_set, rpki.up_down, rpki.left_right, rpki.relaxng, rpki.cms, rpki.exceptions, rpki.x509

def left_right_handler(query, path):
  try:
    q_elt = rpki.cms.xml_decode(query, gctx.cms_ta_irbe)
    rpki.relaxng.left_right.assertValid(q_elt)
    q_msg = rpki.left_right.sax_handler.saxify(q_elt)
    r_msg = q_msg.serve_top_level(gctx)
    r_elt = r_msg.toXML()
    rpki.relaxng.left_right.assertValid(r_elt)
    return 200, rpki.cms.xml_encode(r_elt, gctx.cms_key, gctx.cms_certs)
  except Exception, data:
    traceback.print_exc()
    return 500, "Unhandled exception %s" % data

def up_down_handler(query, path):
  try:
    child_id = path.partition("/up-down/")[2]
    if not child_id.isdigit():
      raise rpki.exceptions.BadContactURL, "Bad path: %s" % path
    child = rpki.left_right.child_elt.sql_fetch(gctx.db, gctx.cur, long(child_id))
    if child is None:
      raise rpki.exceptions.NotFound, "Could not find child %s" % child_id
    return 200, child.serve_up_down(gctx, query)
  except Exception, data:
    traceback.print_exc()
    return 500, "Unhandled exception %s" % data

def cronjob_handler(query, path):
  raise NotImplementedError

class global_context(object):
  """A place to stash various global parameters."""
  pass

os.environ["TZ"] = "UTC"
time.tzset()

gctx = global_context()

gctx.cfg = rpki.config.parser("re.conf")
gctx.cfg_section = "rpki"

gctx.db = MySQLdb.connect(user   = gctx.cfg.get(gctx.cfg_section, "sql-username"),
                          db     = gctx.cfg.get(gctx.cfg_section, "sql-database"),
                          passwd = gctx.cfg.get(gctx.cfg_section, "sql-password"))

gctx.cur = gctx.db.cursor()

gctx.cms_ta_irdb = rpki.x509.X509(Auto_file = gctx.cfg.get(gctx.cfg_section, "cms-ta-irdb"))
gctx.cms_ta_irbe = rpki.x509.X509(Auto_file = gctx.cfg.get(gctx.cfg_section, "cms-ta-irbe"))
gctx.cms_key     = rpki.x509.RSA_Keypair(Auto_file = gctx.cfg.get(gctx.cfg_section, "cms-key"))
gctx.cms_certs   = rpki.x509.X509_chain(Auto_files = gctx.cfg.multiget(gctx.cfg_section, "cms-cert"))

gctx.https_key   = rpki.x509.RSA_Keypair(Auto_file = gctx.cfg.get(gctx.cfg_section, "https-key"))
gctx.https_certs = rpki.x509.X509_chain(Auto_files = gctx.cfg.multiget(gctx.cfg_section, "https-cert"))
gctx.https_tas   = rpki.x509.X509_chain(Auto_files = gctx.cfg.multiget(gctx.cfg_section, "https-ta"))

gctx.irdb_host   = gctx.cfg.get(gctx.cfg_section, "irdb-host")
gctx.irdb_port   = gctx.cfg.get(gctx.cfg_section, "irdb-port")
gctx.irdb_url    = gctx.cfg.get(gctx.cfg_section, "irdb-url")

rpki.https.server(privateKey=gctx.https_key, certChain=gctx.https_certs,
                  handlers=(("/left-right", left_right_handler),
                            ("/up-down/",   up_down_handler),
                            ("/cronjob",    cronjob_handler)))
