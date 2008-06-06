# $Id$

# Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
RPKI publication engine.

Usage: python pubd.py [ { -c | --config } configfile ]
                      [ { -h | --help } ]
                      [ { -p | --profile } outputfile ]

Default configuration file is pubd.conf, override with --config option.
"""

import traceback, os, time, getopt, sys, MySQLdb, lxml.etree
import rpki.resource_set, rpki.up_down, rpki.left_right, rpki.x509, rpki.sql
import rpki.https, rpki.config, rpki.exceptions, rpki.relaxng, rpki.log
import rpki.rpki_engine, rpki.publication

class pubd_context(rpki.rpki_engine.rpkid_context):
  """A container for various pubd parameters."""

  def __init__(self, cfg):

    self.db = rpki.sql.connect(cfg)
    self.cur = self.db.cursor()

    self.bpki_ta   = rpki.x509.X509(Auto_file = cfg.get("bpki-ta"))
    self.irbe_cert = rpki.x509.X509(Auto_file = cfg.get("irbe-cert"))
    self.pubd_cert = rpki.x509.X509(Auto_file = cfg.get("pubd-cert"))
    self.pubd_key  = rpki.x509.RSA( Auto_file = cfg.get("pubd-key"))

    self.https_server_host = cfg.get("server-host", "")
    self.https_server_port = int(cfg.get("server-port", "4434"))

    self.publication_base = cfg.get("publication-base", "publication/")

    self.sql_cache = {}
    self.sql_dirty = set()

  def handler_common(self, query, client, certs, crl = None):
    """Common PDU handler code."""
    q_msg = rpki.publication.cms_msg.unwrap(query, certs)
    r_msg = q_msg.serve_top_level(self, client)
    reply = rpki.publication.cms_msg.wrap(r_msg, self.pubd_key, self.pubd_cert, crl)
    self.sql_sweep()
    return reply

  def control_handler(self, query, path):
    """Process one PDU from the IRBE."""
    rpki.log.trace()
    try:
      self.db.ping(True)
      return 200, self.handler_common(query, None, (self.bpki_ta, self.irbe_cert))
    except Exception, data:
      rpki.log.error(traceback.format_exc())
      return 500, "Unhandled exception %s" % data

  def client_handler(self, query, path):
    """Process one PDU from a client."""
    rpki.log.trace()
    try:
      self.db.ping(True)
      client_id = path.partition("/client/")[2]
      if not client_id.isdigit():
        raise rpki.exceptions.BadContactURL, "Bad path: %s" % path
      client = rpki.publication.client_elt.sql_fetch(self, long(client_id))
      if client is None:
        raise rpki.exceptions.ClientNotFound, "Could not find client %s" % client_id
      config = rpki.publication.config_elt.fetch(self)
      if config is None or config.bpki_crl is None:
        raise rpki.exceptions.CMSCRLNotSet
      return 200, self.handler_common(query, client, (self.bpki_ta, client.bpki_cert, client.bpki_glue), config.bpki_crl)
    except Exception, data:
      rpki.log.error(traceback.format_exc())
      return 500, "Could not process PDU: %s" % data

  def build_https_ta_cache(self):
    """Build dynamic TLS trust anchors."""
    if self.https_ta_cache is None:
      clients = rpki.publication.client_elt.sql_fetch_all(self)
      self.https_ta_cache = rpki.https.build_https_ta_cache(
        [c.bpki_cert for c in clients if c.bpki_cert is not None] +
        [c.bpki_glue for c in clients if c.bpki_glue is not None] +
        [self.irbe_cert, self.bpki_ta])
    return self.https_ta_cache

os.environ["TZ"] = "UTC"
time.tzset()

rpki.log.init("pubd")

cfg_file = "pubd.conf"
profile = False

opts,argv = getopt.getopt(sys.argv[1:], "c:hp:?", ["config=", "help"])
for o,a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  elif o in ("-c", "--config"):
    cfg_file = a
  elif o in ("-p", "--profile"):
    profile = a
if argv:
  raise RuntimeError, "Unexpected arguments %s" % argv

def main():

  cfg = rpki.config.parser(cfg_file, "pubd")

  if profile:
    rpki.log.info("Running in profile mode with output to %s" % profile)

  pctx = pubd_context(cfg)

  rpki.https.server(
    dynamic_https_trust_anchor    = pctx.build_https_ta_cache,
    host                          = pctx.https_server_host,
    port                          = pctx.https_server_port,
    server_key                    = pctx.pubd_key,
    server_cert                   = pctx.pubd_cert,
    handlers                      = (("/control", pctx.control_handler),
                                     ("/client/", pctx.client_handler)))

if profile:
  import cProfile
  cProfile.run("main()", profile)
else:
  main()
