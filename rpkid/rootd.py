"""
Trivial RPKI up-down protocol root server, for testing.  Not suitable
for production use.  Overrides a bunch of method definitions from the
rpki.* classes in order to reuse as much code as possible.

Usage: python rootd.py [ { -c | --config } configfile ] [ { -h | --help } ]

Default configuration file is rootd.conf, override with --config option.

$Id$

Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")

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

import traceback, os, time, getopt, sys, lxml
import rpki.resource_set, rpki.up_down, rpki.left_right, rpki.x509
import rpki.https, rpki.config, rpki.exceptions, rpki.relaxng
import rpki.sundial, rpki.log

rpki_subject_lifetime = rpki.sundial.timedelta(days = 30)

def get_subject_cert():
  filename = rpki_root_dir + rpki_subject_cert
  try:
    x = rpki.x509.X509(Auto_file = filename)
    rpki.log.debug("Read subject cert %s" % filename)
    return x
  except IOError:
    rpki.log.debug("Failed to read subject cert %s" % filename)
    return None

def set_subject_cert(cert):
  filename = rpki_root_dir + rpki_subject_cert
  rpki.log.debug("Writing subject cert %s" % filename)
  f = open(filename, "wb")
  f.write(cert.get_DER())
  f.close()

def del_subject_cert():
  filename = rpki_root_dir + rpki_subject_cert
  rpki.log.debug("Deleting subject cert %s" % filename)
  os.remove(filename)

def stash_subject_pkcs10(pkcs10):
  if rpki_subject_pkcs10:
    rpki.log.debug("Writing subject PKCS #10 %s" % rpki_subject_pkcs10)
    f = open(rpki_subject_pkcs10, "wb")
    f.write(pkcs10.get_DER())
    f.close()

def compose_response(r_msg):
  rc = rpki.up_down.class_elt()
  rc.class_name = rpki_class_name
  rc.cert_url = rpki.up_down.multi_uri(rpki_root_cert_uri)
  rc.from_resource_bag(rpki_root_cert.get_3779resources())
  rc.issuer = rpki_root_cert
  r_msg.payload.classes.append(rc)
  subject_cert = get_subject_cert()
  if subject_cert is not None:
    rc.certs.append(rpki.up_down.certificate_elt())
    rc.certs[0].cert_url = rpki.up_down.multi_uri(rpki_base_uri + rpki_subject_cert)
    rc.certs[0].cert = subject_cert

class list_pdu(rpki.up_down.list_pdu):
  def serve_pdu(self, q_msg, r_msg, ignored):
    r_msg.payload = rpki.up_down.list_response_pdu()
    compose_response(r_msg)

class issue_pdu(rpki.up_down.issue_pdu):
  def serve_pdu(self, q_msg, r_msg, ignored):
    stash_subject_pkcs10(self.pkcs10)
    self.pkcs10.check_valid_rpki()
    r_msg.payload = rpki.up_down.issue_response_pdu()
    subject_cert = get_subject_cert()
    if subject_cert is None:
      resources = rpki_root_cert.get_3779resources()
      rpki.log.info("Generating subject cert with resources " + str(resources))
      req_key = self.pkcs10.getPublicKey()
      req_sia = self.pkcs10.get_SIA()
      crldp = rpki_base_uri + rpki_root_crl
      now = rpki.sundial.now()
      subject_cert = rpki_root_cert.issue(
        keypair     = rpki_root_key,
        subject_key = req_key,
        serial      = int(time.time()),
        sia         = req_sia,
        aia         = rpki_root_cert_uri,
        crldp       = crldp,
        resources   = resources,
        notAfter    = now + rpki_subject_lifetime)
      set_subject_cert(subject_cert)
      crl = rpki.x509.CRL.generate(
        keypair             = rpki_root_key,
        issuer              = rpki_root_cert,
        serial              = 1,
        thisUpdate          = now,
        nextUpdate          = now + rpki_subject_lifetime,
        revokedCertificates = ())
      rpki.log.debug("Writing CRL %s" % rpki_root_dir + rpki_root_crl)
      f = open(rpki_root_dir + rpki_root_crl, "wb")
      f.write(crl.get_DER())
      f.close()
      manifest_resources = rpki.resource_set.resource_bag(
        asn = rpki.resource_set.resource_set_as("<inherit>"),
        v4 = rpki.resource_set.resource_set_ipv4("<inherit>"),
        v6 = rpki.resource_set.resource_set_ipv6("<inherit>"))
      manifest_keypair = rpki.x509.RSA.generate()
      manifest_cert = rpki_root_cert.issue(
        keypair     = rpki_root_key,
        subject_key = manifest_keypair.get_RSApublic(),
        serial      = int(time.time()) + 1,
        sia         = None,
        aia         = rpki_root_cert_uri,
        crldp       = crldp,
        resources   = manifest_resources,
        notAfter    = now + rpki_subject_lifetime,
        is_ca       = False)
      manifest = rpki.x509.SignedManifest.build(
        serial         = int(time.time()),
        thisUpdate     = now,
        nextUpdate     = now + rpki_subject_lifetime,
        names_and_objs = [(rpki_subject_cert, subject_cert), (rpki_root_crl, crl)],
        keypair        = manifest_keypair,
        certs          = manifest_cert)
      rpki.log.debug("Writing manifest %s" % rpki_root_dir + rpki_root_manifest)
      f = open(rpki_root_dir + rpki_root_manifest, "wb")
      f.write(manifest.get_DER())
      f.close()
    compose_response(r_msg)

class revoke_pdu(rpki.up_down.revoke_pdu):
  def serve_pdu(self, q_msg, r_msg, ignored):
    subject_cert = get_subject_cert()
    if subject_cert is None or subject_cert.gSKI() != self.ski:
      raise rpki.exceptions.NotInDatabase
    del_subject_cert()
    r_msg.payload = rpki.up_down.revoke_response_pdu()
    r_msg.payload.class_name = self.class_name
    r_msg.payload.ski = self.ski

class message_pdu(rpki.up_down.message_pdu):
  name2type = {
    "list"            : list_pdu,
    "list_response"   : rpki.up_down.list_response_pdu,
    "issue"           : issue_pdu,
    "issue_response"  : rpki.up_down.issue_response_pdu,
    "revoke"          : revoke_pdu,
    "revoke_response" : rpki.up_down.revoke_response_pdu,
    "error_response"  : rpki.up_down.error_response_pdu }
  type2name = dict((v,k) for k,v in name2type.items())

class sax_handler(rpki.up_down.sax_handler):
  pdu = message_pdu

class cms_msg(rpki.up_down.cms_msg):
  saxify = sax_handler.saxify

def up_down_handler(query, path):
  try:
    q_msg = cms_msg.unwrap(query, (bpki_ta, child_bpki_cert))
  except Exception, data:
    rpki.log.error(traceback.format_exc())
    return 400, "Could not process PDU: %s" % data
  try:
    r_msg = q_msg.serve_top_level(None)
    r_cms = cms_msg.wrap(r_msg, rootd_bpki_key, rootd_bpki_cert, rootd_bpki_crl)
    return 200, r_cms
  except Exception, data:
    rpki.log.error(traceback.format_exc())
    try:
      r_msg = q_msg.serve_error(data)
      r_cms = cms_msg.wrap(r_msg, rootd_bpki_key, rootd_bpki_cert, rootd_bpki_crl)
      return 200, r_cms
    except Exception, data:
      rpki.log.error(traceback.format_exc())
      return 500, "Could not process PDU: %s" % data

os.environ["TZ"] = "UTC"
time.tzset()

rpki.log.init("rootd")

cfg_file = "rootd.conf"

opts,argv = getopt.getopt(sys.argv[1:], "c:h?", ["config=", "help"])
for o,a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  if o in ("-c", "--config"):
    cfg_file = a
if argv:
  raise RuntimeError, "Unexpected arguments %s" % argv

cfg = rpki.config.parser(cfg_file, "rootd")

bpki_ta                 = rpki.x509.X509(Auto_file = cfg.get("bpki-ta"))
rootd_bpki_key          = rpki.x509.RSA( Auto_file = cfg.get("rootd-bpki-key"))
rootd_bpki_cert         = rpki.x509.X509(Auto_file = cfg.get("rootd-bpki-cert"))
rootd_bpki_crl          = rpki.x509.CRL( Auto_file = cfg.get("rootd-bpki-crl"))
child_bpki_cert         = rpki.x509.X509(Auto_file = cfg.get("child-bpki-cert"))

https_server_host       = cfg.get("server-host", "")
https_server_port       = int(cfg.get("server-port"))

rpki_class_name         = cfg.get("rpki-class-name", "wombat")

rpki_root_dir           = cfg.get("rpki-root-dir")
rpki_base_uri           = cfg.get("rpki-base-uri", "rsync://" + rpki_class_name + ".invalid/")

rpki_root_key           = rpki.x509.RSA( Auto_file = cfg.get("rpki-root-key"))
rpki_root_cert          = rpki.x509.X509(Auto_file = cfg.get("rpki-root-cert"))
rpki_root_cert_uri      = cfg.get("rpki-root-cert-uri", rpki_base_uri + "Root.cer")

rpki_root_manifest      = cfg.get("rpki-root-manifest", "Root.mnf")
rpki_root_crl           = cfg.get("rpki-root-crl",      "Root.crl")
rpki_subject_cert       = cfg.get("rpki-subject-cert",  "Subroot.cer")
rpki_subject_pkcs10     = cfg.get("rpki-subject-pkcs10", "")

rpki.https.server(server_key   = rootd_bpki_key,
                  server_cert  = rootd_bpki_cert,
                  client_ta    = (bpki_ta, child_bpki_cert),
                  host         = https_server_host,
                  port         = https_server_port,
                  handlers     = up_down_handler)
