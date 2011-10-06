"""
Trivial RPKI up-down protocol root server, for testing.  Not suitable
for production use.  Overrides a bunch of method definitions from the
rpki.* classes in order to reuse as much code as possible.

Usage: python rootd.py [ { -c | --config } configfile ] [ { -h | --help } ]

$Id$

Copyright (C) 2009--2011  Internet Systems Consortium ("ISC")

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

import os, time, getopt, sys
import rpki.resource_set, rpki.up_down, rpki.left_right, rpki.x509
import rpki.http, rpki.config, rpki.exceptions, rpki.relaxng
import rpki.sundial, rpki.log

rootd = None

class list_pdu(rpki.up_down.list_pdu):
  def serve_pdu(self, q_msg, r_msg, ignored, callback, errback):
    r_msg.payload = rpki.up_down.list_response_pdu()
    rootd.compose_response(r_msg)
    callback()

class issue_pdu(rpki.up_down.issue_pdu):
  def serve_pdu(self, q_msg, r_msg, ignored, callback, errback):
    self.pkcs10.check_valid_rpki()
    r_msg.payload = rpki.up_down.issue_response_pdu()
    rootd.compose_response(r_msg, self.pkcs10)
    callback()

class revoke_pdu(rpki.up_down.revoke_pdu):
  def serve_pdu(self, q_msg, r_msg, ignored, callback, errback):
    rootd.subject_cert = get_subject_cert()
    if subject_cert is None or subject_cert.gSKI() != self.ski:
      raise rpki.exceptions.NotInDatabase
    rootd.del_subject_cert()
    rootd.del_subject_pkcs10()
    r_msg.payload = rpki.up_down.revoke_response_pdu()
    r_msg.payload.class_name = self.class_name
    r_msg.payload.ski = self.ski
    callback()

class message_pdu(rpki.up_down.message_pdu):

  name2type = {
    "list"            : list_pdu,
    "list_response"   : rpki.up_down.list_response_pdu,
    "issue"           : issue_pdu,
    "issue_response"  : rpki.up_down.issue_response_pdu,
    "revoke"          : revoke_pdu,
    "revoke_response" : rpki.up_down.revoke_response_pdu,
    "error_response"  : rpki.up_down.error_response_pdu }

  type2name = dict((v, k) for k, v in name2type.items())

  def log_query(self, child):
    """
    Log query we're handling.
    """
    rpki.log.info("Serving %s query" % self.type)

class sax_handler(rpki.up_down.sax_handler):
  pdu = message_pdu

class cms_msg(rpki.up_down.cms_msg):
  saxify = sax_handler.saxify

class main(object):

  rpki_root_cert = None

  def get_root_cert(self):
    rpki.log.debug("Read root cert %s" % self.rpki_root_cert_file)
    self.rpki_root_cert = rpki.x509.X509(Auto_file = self.rpki_root_cert_file)

  def root_newer_than_subject(self):
    return os.stat(self.rpki_root_cert_file).st_mtime > os.stat(self.rpki_root_dir + self.rpki_subject_cert).st_mtime

  def get_subject_cert(self):
    filename = self.rpki_root_dir + self.rpki_subject_cert
    try:
      x = rpki.x509.X509(Auto_file = filename)
      rpki.log.debug("Read subject cert %s" % filename)
      return x
    except IOError:
      return None

  def set_subject_cert(self, cert):
    filename = self.rpki_root_dir + self.rpki_subject_cert
    rpki.log.debug("Writing subject cert %s, SKI %s" % (filename, cert.hSKI()))
    f = open(filename, "wb")
    f.write(cert.get_DER())
    f.close()

  def del_subject_cert(self):
    filename = self.rpki_root_dir + self.rpki_subject_cert
    rpki.log.debug("Deleting subject cert %s" % filename)
    os.remove(filename)

  def get_subject_pkcs10(self):
    try:
      x = rpki.x509.PKCS10(Auto_file = self.rpki_subject_pkcs10)
      rpki.log.debug("Read subject PKCS #10 %s" % self.rpki_subject_pkcs10)
      return x
    except IOError:
      return None

  def set_subject_pkcs10(self, pkcs10):
    rpki.log.debug("Writing subject PKCS #10 %s" % self.rpki_subject_pkcs10)
    f = open(self.rpki_subject_pkcs10, "wb")
    f.write(pkcs10.get_DER())
    f.close()

  def del_subject_pkcs10(self):
    rpki.log.debug("Deleting subject PKCS #10 %s" % self.rpki_subject_pkcs10)
    try:
      os.remove(self.rpki_subject_pkcs10)
    except OSError:
      pass

  def issue_subject_cert_maybe(self, new_pkcs10):
    now = rpki.sundial.now()
    subject_cert = self.get_subject_cert()
    old_pkcs10 = self.get_subject_pkcs10()
    if new_pkcs10 is not None and new_pkcs10 != old_pkcs10:
      self.set_subject_pkcs10(new_pkcs10)
      if subject_cert is not None:
        rpki.log.debug("PKCS #10 changed, regenerating subject certificate")
        subject_cert = None
    if subject_cert is not None and subject_cert.getNotAfter() <= now + self.rpki_subject_regen:
      rpki.log.debug("Subject certificate has reached expiration threshold, regenerating")
      subject_cert = None
    if subject_cert is not None and self.root_newer_than_subject():
      rpki.log.debug("Root certificate has changed, regenerating subject")
      subject_cert = None
    self.get_root_cert()
    if subject_cert is not None:
      return subject_cert
    pkcs10 = old_pkcs10 if new_pkcs10 is None else new_pkcs10
    if pkcs10 is None:
      rpki.log.debug("No PKCS #10 request, can't generate subject certificate yet")
      return None
    resources = self.rpki_root_cert.get_3779resources()
    rpki.log.info("Generating subject cert with resources " + str(resources))
    req_key = pkcs10.getPublicKey()
    req_sia = pkcs10.get_SIA()
    crldp = self.rpki_base_uri + self.rpki_root_crl
    serial = now.totimestamp()
    subject_cert = self.rpki_root_cert.issue(
      keypair     = self.rpki_root_key,
      subject_key = req_key,
      serial      = serial,
      sia         = req_sia,
      aia         = self.rpki_root_cert_uri,
      crldp       = crldp,
      resources   = resources,
      notAfter    = now + self.rpki_subject_lifetime)
    crl = rpki.x509.CRL.generate(
      keypair             = self.rpki_root_key,
      issuer              = self.rpki_root_cert,
      serial              = serial,
      thisUpdate          = now,
      nextUpdate          = now + self.rpki_subject_lifetime,
      revokedCertificates = ())
    rpki.log.debug("Writing CRL %s" % (self.rpki_root_dir + self.rpki_root_crl))
    f = open(self.rpki_root_dir + self.rpki_root_crl, "wb")
    f.write(crl.get_DER())
    f.close()
    manifest_resources = rpki.resource_set.resource_bag.from_inheritance()
    manifest_keypair = rpki.x509.RSA.generate()
    manifest_cert = self.rpki_root_cert.issue(
      keypair     = self.rpki_root_key,
      subject_key = manifest_keypair.get_RSApublic(),
      serial      = serial + 1,
      sia         = None,
      aia         = self.rpki_root_cert_uri,
      crldp       = crldp,
      resources   = manifest_resources,
      notAfter    = now + self.rpki_subject_lifetime,
      is_ca       = False)
    manifest = rpki.x509.SignedManifest.build(
      serial         = serial,
      thisUpdate     = now,
      nextUpdate     = now + self.rpki_subject_lifetime,
      names_and_objs = [(self.rpki_subject_cert, subject_cert), (self.rpki_root_crl, crl)],
      keypair        = manifest_keypair,
      certs          = manifest_cert)
    rpki.log.debug("Writing manifest %s" % (self.rpki_root_dir + self.rpki_root_manifest))
    f = open(self.rpki_root_dir + self.rpki_root_manifest, "wb")
    f.write(manifest.get_DER())
    f.close()
    self.set_subject_cert(subject_cert)
    return subject_cert

  def compose_response(self, r_msg, pkcs10 = None):
    subject_cert = self.issue_subject_cert_maybe(pkcs10)
    rc = rpki.up_down.class_elt()
    rc.class_name = self.rpki_class_name
    rc.cert_url = rpki.up_down.multi_uri(self.rpki_root_cert_uri)
    rc.from_resource_bag(self.rpki_root_cert.get_3779resources())
    rc.issuer = self.rpki_root_cert
    r_msg.payload.classes.append(rc)
    if subject_cert is not None:
      rc.certs.append(rpki.up_down.certificate_elt())
      rc.certs[0].cert_url = rpki.up_down.multi_uri(self.rpki_base_uri + self.rpki_subject_cert)
      rc.certs[0].cert = subject_cert

  def up_down_handler(self, query, path, cb):
    try:
      q_msg = cms_msg(DER = query).unwrap((self.bpki_ta, self.child_bpki_cert))
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception, e:
      rpki.log.traceback()
      return cb(400, reason = "Could not process PDU: %s" % e)

    def done(r_msg):
      cb(200, body = cms_msg().wrap(r_msg, self.rootd_bpki_key, self.rootd_bpki_cert, self.rootd_bpki_crl))

    try:
      q_msg.serve_top_level(None, done)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception, e:
      rpki.log.traceback()
      try:
        done(q_msg.serve_error(e))
      except (rpki.async.ExitNow, SystemExit):
        raise
      except Exception, e:
        rpki.log.traceback()
        cb(500, reason = "Could not process PDU: %s" % e)

  def __init__(self):

    global rootd
    rootd = self                        # Gross, but simpler than what we'd have to do otherwise

    os.environ["TZ"] = "UTC"
    time.tzset()

    self.cfg_file = None

    opts, argv = getopt.getopt(sys.argv[1:], "c:dh?", ["config=", "debug", "help"])
    for o, a in opts:
      if o in ("-h", "--help", "-?"):
        print __doc__
        sys.exit(0)
      elif o in ("-c", "--config"):
        self.cfg_file = a
      elif o in ("-d", "--debug"):
        rpki.log.use_syslog = False
    if argv:
      raise rpki.exceptions.CommandParseFailure, "Unexpected arguments %s" % argv

    rpki.log.init("rootd")

    self.cfg = rpki.config.parser(self.cfg_file, "rootd")

    self.cfg.set_global_flags()

    self.bpki_ta                 = rpki.x509.X509(Auto_update = self.cfg.get("bpki-ta"))
    self.rootd_bpki_key          = rpki.x509.RSA( Auto_update = self.cfg.get("rootd-bpki-key"))
    self.rootd_bpki_cert         = rpki.x509.X509(Auto_update = self.cfg.get("rootd-bpki-cert"))
    self.rootd_bpki_crl          = rpki.x509.CRL( Auto_update = self.cfg.get("rootd-bpki-crl"))
    self.child_bpki_cert         = rpki.x509.X509(Auto_update = self.cfg.get("child-bpki-cert"))

    self.http_server_host        = self.cfg.get("server-host", "")
    self.http_server_port        = int(self.cfg.get("server-port"))

    self.rpki_class_name         = self.cfg.get("rpki-class-name", "wombat")

    self.rpki_root_dir           = self.cfg.get("rpki-root-dir")
    self.rpki_base_uri           = self.cfg.get("rpki-base-uri", "rsync://" + self.rpki_class_name + ".invalid/")

    self.rpki_root_key           = rpki.x509.RSA( Auto_file = self.cfg.get("rpki-root-key"))
    self.rpki_root_cert_file     = self.cfg.get("rpki-root-cert")
    self.rpki_root_cert_uri      = self.cfg.get("rpki-root-cert-uri", self.rpki_base_uri + "Root.cer")

    self.rpki_root_manifest      = self.cfg.get("rpki-root-manifest", "Root.mnf")
    self.rpki_root_crl           = self.cfg.get("rpki-root-crl",      "Root.crl")
    self.rpki_subject_cert       = self.cfg.get("rpki-subject-cert",  "Child.cer")
    self.rpki_subject_pkcs10     = self.cfg.get("rpki-subject-pkcs10", "Child.pkcs10")

    self.rpki_subject_lifetime   = rpki.sundial.timedelta.parse(self.cfg.get("rpki-subject-lifetime", "30d"))
    self.rpki_subject_regen      = rpki.sundial.timedelta.parse(self.cfg.get("rpki-subject-regen", self.rpki_subject_lifetime.convert_to_seconds() / 2))

    rpki.http.server(host     = self.http_server_host,
                     port     = self.http_server_port,
                     handlers = self.up_down_handler)
