# $Id$

"""
RPKI engine daemon.  This is still very much a work in progress.

Usage: python rpkid.py [ { -c | --config } configfile ] [ { -h | --help } ]

Default configuration file is rpkid.conf, override with --config option.
"""

import traceback, os, time, getopt, sys, MySQLdb
import rpki.resource_set, rpki.up_down, rpki.left_right, rpki.x509
import rpki.https, rpki.config, rpki.cms, rpki.exceptions, rpki.relaxng

def left_right_handler(query, path):
  try:
    q_elt = rpki.cms.xml_verify(query, gctx.cms_ta_irbe)
    rpki.relaxng.left_right.assertValid(q_elt)
    q_msg = rpki.left_right.sax_handler.saxify(q_elt)
    r_msg = q_msg.serve_top_level(gctx)
    r_elt = r_msg.toXML()
    rpki.relaxng.left_right.assertValid(r_elt)
    return 200, rpki.cms.xml_sign(r_elt, gctx.cms_key, gctx.cms_certs)
  except Exception, data:
    traceback.print_exc()
    return 500, "Unhandled exception %s" % data

def up_down_handler(query, path):
  try:
    child_id = path.partition("/up-down/")[2]
    if not child_id.isdigit():
      raise rpki.exceptions.BadContactURL, "Bad path: %s" % path
    child = rpki.left_right.child_elt.sql_fetch(gctx, long(child_id))
    if child is None:
      raise rpki.exceptions.ChildNotFound, "Could not find child %s" % child_id
    return 200, child.serve_up_down(gctx, query)
  except Exception, data:
    traceback.print_exc()
    return 400, "Could not process PDU: %s" % data

def cronjob_handler(query, path):
  for s in rpki.left_right.self_elt.sql_fetch_all(gctx):
    s.client_poll(gctx)
  return 200, "OK"

class global_context(object):
  """A container for various global parameters."""

  def __init__(self, cfg, section):

    self.db = MySQLdb.connect(user   = cfg.get(section, "sql-username"),
                              db     = cfg.get(section, "sql-database"),
                              passwd = cfg.get(section, "sql-password"))
    self.cur = self.db.cursor()

    self.cms_ta_irdb = rpki.x509.X509(Auto_file = cfg.get(section, "cms-ta-irdb"))
    self.cms_ta_irbe = rpki.x509.X509(Auto_file = cfg.get(section, "cms-ta-irbe"))
    self.cms_key     = rpki.x509.RSA(Auto_file = cfg.get(section, "cms-key"))
    self.cms_certs   = rpki.x509.X509_chain(Auto_files = cfg.multiget(section, "cms-cert"))

    self.https_key   = rpki.x509.RSA(Auto_file = cfg.get(section, "https-key"))
    self.https_certs = rpki.x509.X509_chain(Auto_files = cfg.multiget(section, "https-cert"))
    self.https_tas   = rpki.x509.X509_chain(Auto_files = cfg.multiget(section, "https-ta"))

    self.irdb_url    = cfg.get(section, "irdb-url")

    self.https_server_host = cfg.get(section, "server-host", "")
    self.https_server_port = int(cfg.get(section, "server-port", "4433"))

    self.publication_kludge_base = cfg.get(section, "publication-kludge-base", "publication/")

os.environ["TZ"] = "UTC"
time.tzset()

cfg_file = "rpkid.conf"

opts,argv = getopt.getopt(sys.argv[1:], "c:h?", ["config=", "help"])
for o,a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  if o in ("-c", "--config"):
    cfg_file = a
if argv:
  raise RuntimeError, "Unexpected arguments %s" % argv

gctx = global_context(cfg = rpki.config.parser(cfg_file), section = "rpkid")

rpki.https.server(privateKey = gctx.https_key,
                  certChain = gctx.https_certs,
                  host = gctx.https_server_host,
                  port = gctx.https_server_port,
                  handlers=(("/left-right", left_right_handler),
                            ("/up-down/",   up_down_handler),
                            ("/cronjob",    cronjob_handler)))
