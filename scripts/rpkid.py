# $Id$

"""
RPKI engine daemon.  This is still very much a work in progress.

Usage: python rpkid.py [ { -c | --config } configfile ] [ { -h | --help } ]

Default configuration file is rpkid.conf, override with --config option.
"""

import traceback, os, time, getopt, sys, MySQLdb, lxml.etree
import rpki.resource_set, rpki.up_down, rpki.left_right, rpki.x509, rpki.sql
import rpki.https, rpki.config, rpki.cms, rpki.exceptions, rpki.relaxng, rpki.log

def left_right_handler(query, path):
  """Process one left-right PDU."""
  rpki.log.trace()
  try:
    q_elt = rpki.cms.xml_verify(query, gctx.cms_ta_irbe)
    rpki.relaxng.left_right.assertValid(q_elt)
    q_msg = rpki.left_right.sax_handler.saxify(q_elt)
    r_msg = q_msg.serve_top_level(gctx)
    r_elt = r_msg.toXML()
    rpki.relaxng.left_right.assertValid(r_elt)
    reply = rpki.cms.xml_sign(r_elt, gctx.cms_key, gctx.cms_certs)
    rpki.sql.sql_sweep(gctx)
    return 200, reply
  except lxml.etree.DocumentInvalid:
    rpki.log.warning("Received reply document does not pass schema check: " + lxml.etree.tostring(r_elt, pretty_print = True))
    rpki.log.warning(traceback.format_exc())
    return 500, "Schema violation"
  except Exception, data:
    rpki.log.error(traceback.format_exc())
    return 500, "Unhandled exception %s" % data

def up_down_handler(query, path):
  """Process one up-down PDU."""
  rpki.log.trace()
  try:
    child_id = path.partition("/up-down/")[2]
    if not child_id.isdigit():
      raise rpki.exceptions.BadContactURL, "Bad path: %s" % path
    child = rpki.left_right.child_elt.sql_fetch(gctx, long(child_id))
    if child is None:
      raise rpki.exceptions.ChildNotFound, "Could not find child %s" % child_id
    reply = child.serve_up_down(gctx, query)
    rpki.sql.sql_sweep(gctx)
    return 200, reply
  except Exception, data:
    rpki.log.error(traceback.format_exc())
    return 400, "Could not process PDU: %s" % data

def cronjob_handler(query, path):
  """Periodic tasks.  As simple as possible for now, may need to break
  this up into separate handlers later.
  """

  rpki.log.trace()
  for s in rpki.left_right.self_elt.sql_fetch_all(gctx):
    s.client_poll(gctx)
    s.update_children(gctx)
    s.regenerate_crls_and_manifests(gctx)
  rpki.sql.sql_sweep(gctx)
  return 200, "OK"

class global_context(object):
  """A container for various global parameters."""

  def __init__(self, cfg):

    self.db = MySQLdb.connect(user   = cfg.get("sql-username"),
                              db     = cfg.get("sql-database"),
                              passwd = cfg.get("sql-password"))
    self.cur = self.db.cursor()

    self.cms_ta_irdb = rpki.x509.X509(Auto_file = cfg.get("cms-ta-irdb"))
    self.cms_ta_irbe = rpki.x509.X509(Auto_file = cfg.get("cms-ta-irbe"))
    self.cms_key     = rpki.x509.RSA(Auto_file = cfg.get("cms-key"))
    self.cms_certs   = rpki.x509.X509_chain(Auto_files = cfg.multiget("cms-cert"))

    self.https_key   = rpki.x509.RSA(Auto_file = cfg.get("https-key"))
    self.https_certs = rpki.x509.X509_chain(Auto_files = cfg.multiget("https-cert"))
    self.https_ta    = rpki.x509.X509_chain(Auto_files = cfg.multiget("https-ta"))

    self.irdb_url    = cfg.get("irdb-url")

    self.https_server_host = cfg.get("server-host", "")
    self.https_server_port = int(cfg.get("server-port", "4433"))

    self.publication_kludge_base = cfg.get("publication-kludge-base", "publication/")

os.environ["TZ"] = "UTC"
time.tzset()

rpki.log.init("rpkid")

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

cfg = rpki.config.parser(cfg_file, "rpkid")

startup_msg = cfg.get("startup-message", "")
if startup_msg:
  rpki.log.info(startup_msg)

gctx = global_context(cfg)

rpki.https.server(privateKey = gctx.https_key,
                  certChain = gctx.https_certs,
                  host = gctx.https_server_host,
                  port = gctx.https_server_port,
                  handlers=(("/left-right", left_right_handler),
                            ("/up-down/",   up_down_handler),
                            ("/cronjob",    cronjob_handler)))
