"""
RPKI publication engine.

Usage: python pubd.py [ { -c | --config } configfile ]
                      [ { -h | --help } ]
                      [ { -p | --profile } outputfile ]

Default configuration file is pubd.conf, override with --config option.

$Id$

Copyright (C) 2009-2010  Internet Systems Consortium ("ISC")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.

Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import os, time, getopt, sys, re
import rpki.resource_set, rpki.up_down, rpki.x509, rpki.sql
import rpki.https, rpki.config, rpki.exceptions, rpki.relaxng
import rpki.log, rpki.publication

class pubd_context(object):
  """
  A container for various pubd parameters.
  """

  def __init__(self, cfg):

    self.sql = rpki.sql.session(cfg)

    self.bpki_ta   = rpki.x509.X509(Auto_file = cfg.get("bpki-ta"))
    self.irbe_cert = rpki.x509.X509(Auto_file = cfg.get("irbe-cert"))
    self.pubd_cert = rpki.x509.X509(Auto_file = cfg.get("pubd-cert"))
    self.pubd_key  = rpki.x509.RSA( Auto_file = cfg.get("pubd-key"))

    self.https_server_host = cfg.get("server-host", "")
    self.https_server_port = int(cfg.get("server-port", "4434"))

    self.publication_base = cfg.get("publication-base", "publication/")

    self.publication_multimodule = cfg.getboolean("publication-multimodule", False)

  def handler_common(self, query, client, cb, certs, crl = None):
    """
    Common PDU handler code.
    """

    def done(r_msg):
      reply = rpki.publication.cms_msg.wrap(r_msg, self.pubd_key, self.pubd_cert, crl)
      self.sql.sweep()
      cb(reply)

    q_msg = rpki.publication.cms_msg.unwrap(query, certs)
    q_msg.serve_top_level(self, client, done)

  def control_handler(self, query, path, cb):
    """
    Process one PDU from the IRBE.
    """

    def done(x):
      cb(200, x)

    rpki.log.trace()
    try:
      self.sql.ping()
      self.handler_common(query, None, done, (self.bpki_ta, self.irbe_cert))
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception, data:
      rpki.log.traceback()
      cb(500, "Unhandled exception %s" % data)

  client_url_regexp = re.compile("/client/([-A-Z0-9_/]+)$", re.I)

  def client_handler(self, query, path, cb):
    """
    Process one PDU from a client.
    """

    def done(x):
      cb(200, x)

    rpki.log.trace()
    try:
      self.sql.ping()
      match = self.client_url_regexp.search(path)
      if match is None:
        raise rpki.exceptions.BadContactURL, "Bad path: %s" % path
      client_handle = match.group(1)
      client = rpki.publication.client_elt.sql_fetch_where1(self, "client_handle = %s", (client_handle,))
      if client is None:
        raise rpki.exceptions.ClientNotFound, "Could not find client %s" % client_handle
      config = rpki.publication.config_elt.fetch(self)
      if config is None or config.bpki_crl is None:
        raise rpki.exceptions.CMSCRLNotSet
      self.handler_common(query, client, done, (self.bpki_ta, client.bpki_cert, client.bpki_glue), config.bpki_crl)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception, data:
      rpki.log.traceback()
      cb(500, "Could not process PDU: %s" % data)

  ## @var https_ta_cache
  # HTTPS trust anchor cache, to avoid regenerating it for every TLS connection.
  https_ta_cache = None

  def clear_https_ta_cache(self):
    """
    Clear dynamic TLS trust anchors.
    """
    if self.https_ta_cache is not None:
      rpki.log.debug("Clearing HTTPS trusted cert cache")
      self.https_ta_cache = None

  def build_https_ta_cache(self):
    """
    Build dynamic TLS trust anchors.
    """
    if self.https_ta_cache is None:
      clients = rpki.publication.client_elt.sql_fetch_all(self)
      self.https_ta_cache = rpki.https.build_https_ta_cache(
        [c.bpki_cert for c in clients if c.bpki_cert is not None] +
        [c.bpki_glue for c in clients if c.bpki_glue is not None] +
        [self.irbe_cert, self.bpki_ta])
    return self.https_ta_cache

os.environ["TZ"] = "UTC"
time.tzset()

cfg_file = "pubd.conf"
profile = False

opts, argv = getopt.getopt(sys.argv[1:], "c:dhp:?", ["config=", "debug", "help"])
for o, a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  elif o in ("-c", "--config"):
    cfg_file = a
  elif o in ("-d", "--debug"):
    rpki.log.use_syslog = False
  elif o in ("-p", "--profile"):
    profile = a
if argv:
  raise RuntimeError, "Unexpected arguments %s" % argv

rpki.log.init("pubd")

def main():

  cfg = rpki.config.parser(cfg_file, "pubd")

  if profile:
    rpki.log.info("Running in profile mode with output to %s" % profile)

  cfg.set_global_flags()

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
