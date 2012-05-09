"""
RPKI publication engine.

Usage: python pubd.py [ { -c | --config } configfile ]
                      [ { -d | --debug } ]
                      [ { -f | --foreground } ]
                      [ { -h | --help } ]
                      [ { -p | --profile } outputfile ]

$Id$

Copyright (C) 2009--2012  Internet Systems Consortium ("ISC")

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

import os
import time
import getopt
import sys
import re
import rpki.resource_set
import rpki.up_down
import rpki.x509
import rpki.sql
import rpki.http
import rpki.config
import rpki.exceptions
import rpki.relaxng
import rpki.log
import rpki.publication
import rpki.daemonize

class main(object):
  """
  Main program for pubd.
  """

  def __init__(self):

    os.environ["TZ"] = "UTC"
    time.tzset()

    self.cfg_file = None
    self.profile = False
    self.foreground = False

    opts, argv = getopt.getopt(sys.argv[1:], "c:dfhp:?",
                               ["config=", "debug", "foreground", "help", "profile="])
    for o, a in opts:
      if o in ("-h", "--help", "-?"):
        print __doc__
        sys.exit(0)
      elif o in ("-c", "--config"):
        self.cfg_file = a
      elif o in ("-d", "--debug"):
        rpki.log.use_syslog = False
        self.foreground = True
      elif o in ("-f", "--foreground"):
        self.foreground = True
      elif o in ("-p", "--profile"):
        self.profile = a
    if argv:
      raise rpki.exceptions.CommandParseFailure, "Unexpected arguments %s" % argv

    rpki.log.init("pubd")

    self.cfg = rpki.config.parser(self.cfg_file, "pubd")
    self.cfg.set_global_flags()

    if not self.foreground:
      rpki.daemonize.daemon()

    if self.profile:
      import cProfile
      cProfile.run("self.main()", self.profile)
    else:
      self.main()

  def main(self):

    if self.profile:
      rpki.log.info("Running in profile mode with output to %s" % self.profile)

    self.sql = rpki.sql.session(self.cfg)

    self.bpki_ta   = rpki.x509.X509(Auto_update = self.cfg.get("bpki-ta"))
    self.irbe_cert = rpki.x509.X509(Auto_update = self.cfg.get("irbe-cert"))
    self.pubd_cert = rpki.x509.X509(Auto_update = self.cfg.get("pubd-cert"))
    self.pubd_key  = rpki.x509.RSA( Auto_update = self.cfg.get("pubd-key"))

    self.http_server_host = self.cfg.get("server-host", "")
    self.http_server_port = int(self.cfg.get("server-port", "4434"))

    self.publication_base = self.cfg.get("publication-base", "publication/")

    self.publication_multimodule = self.cfg.getboolean("publication-multimodule", False)

    rpki.http.server(
      host                          = self.http_server_host,
      port                          = self.http_server_port,
      handlers                      = (("/control", self.control_handler),
                                       ("/client/", self.client_handler)))

  def handler_common(self, query, client, cb, certs, crl = None):
    """
    Common PDU handler code.
    """

    def done(r_msg):
      reply = rpki.publication.cms_msg().wrap(r_msg, self.pubd_key, self.pubd_cert, crl)
      self.sql.sweep()
      cb(reply)

    q_msg = rpki.publication.cms_msg(DER = query).unwrap(certs)
    q_msg.serve_top_level(self, client, done)

  def control_handler(self, query, path, cb):
    """
    Process one PDU from the IRBE.
    """

    def done(body):
      cb(200, body = body)

    rpki.log.trace()
    try:
      self.sql.ping()
      self.handler_common(query, None, done, (self.bpki_ta, self.irbe_cert))
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception, e:
      rpki.log.traceback()
      cb(500, reason = "Unhandled exception %s: %s" % (e.__class__.__name__, e))

  client_url_regexp = re.compile("/client/([-A-Z0-9_/]+)$", re.I)

  def client_handler(self, query, path, cb):
    """
    Process one PDU from a client.
    """

    def done(body):
      cb(200, body = body)

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
    except Exception, e:
      rpki.log.traceback()
      cb(500, reason = "Could not process PDU: %s" % e)
