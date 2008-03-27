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
Trivial RPKI up-down protocol root server, for testing.  Not suitable
for production use.  Overrides a bunch of method definitions from the
rpki.* classes in order to reuse as much code as possible.

Usage: python rootd.py [ { -c | --config } configfile ] [ { -h | --help } ]

Default configuration file is rootd.conf, override with --config option.
"""

import traceback, os, time, getopt, sys, lxml
import rpki.resource_set, rpki.up_down, rpki.left_right, rpki.x509
import rpki.https, rpki.config, rpki.cms, rpki.exceptions, rpki.relaxng
import rpki.sundial, rpki.log

rpki_subject_lifetime = rpki.sundial.timedelta(days = 30)

def get_subject_cert():
  try:
    x = rpki.x509.X509(Auto_file = rpki_subject_filename)
    return x
  except IOError:
    return None

def set_subject_cert(cert):
  f = open(rpki_subject_filename, "wb")
  f.write(cert.get_DER())
  f.close()

def del_subject_cert():
  os.remove(rpki_subject_filename)

def stash_subject_pkcs10(pkcs10):
  if rpki_pkcs10_filename:
    f = open(rpki_pkcs10_filename, "wb")
    f.write(pkcs10.get_DER())
    f.close()

def compose_response(r_msg):
    rc = rpki.up_down.class_elt()
    rc.class_name = rootd_name
    rc.cert_url = rpki.up_down.multi_uri(rootd_cert)
    rc.from_resource_bag(rpki_issuer.get_3779resources())
    rc.issuer = rpki_issuer
    r_msg.payload.classes.append(rc)
    rpki_subject = get_subject_cert()
    if rpki_subject is not None:
      rc.certs.append(rpki.up_down.certificate_elt())
      rc.certs[0].cert_url = rpki.up_down.multi_uri(rootd_cert)
      rc.certs[0].cert = rpki_subject

class list_pdu(rpki.up_down.list_pdu):
  def serve_pdu(self, xxx1, q_msg, r_msg, xxx2):
    r_msg.payload = rpki.up_down.list_response_pdu()
    compose_response(r_msg)

class issue_pdu(rpki.up_down.issue_pdu):
  def serve_pdu(self, xxx1, q_msg, r_msg, xxx2):
    stash_subject_pkcs10(self.pkcs10)
    self.pkcs10.check_valid_rpki()
    r_msg.payload = rpki.up_down.issue_response_pdu()
    rpki_subject = get_subject_cert()
    if rpki_subject is None:
      resources = rpki_issuer.get_3779resources()
      rpki.log.info("Generating subject cert with resources " + str(resources))
      req_key = self.pkcs10.getPublicKey()
      req_sia = self.pkcs10.get_SIA()
      crldp = rootd_base + rpki_issuer.gSKI() + ".crl"
      set_subject_cert(rpki_issuer.issue(keypair     = rpki_key,
                                         subject_key = req_key,
                                         serial      = int(time.time()),
                                         sia         = req_sia,
                                         aia         = rootd_cert,
                                         crldp       = crldp,
                                         resources   = resources,
                                         notAfter    = rpki.sundial.now() + rpki_subject_lifetime))
      now = rpki.sundial.now()
      crl = rpki.x509.CRL.generate(
        keypair             = rpki_key,
        issuer              = rpki_issuer,
        serial              = 1,
        thisUpdate          = now,
        nextUpdate          = now + rpki_subject_lifetime,
        revokedCertificates = ())
      f = open(os.path.dirname(rpki_subject_filename) + "/" + rpki_issuer.gSKI() + ".crl", "wb")
      f.write(crl.get_DER())
      f.close()
    compose_response(r_msg)

class revoke_pdu(rpki.up_down.revoke_pdu):
  def serve_pdu(self, xxx1, q_msg, r_msg, xxx2):
    rpki_subject = get_subject_cert()
    if rpki_subject is None or rpki_subject.gSKI() != self.ski:
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

class sax_handler(rpki.sax_utils.handler):
  def create_top_level(self, name, attrs):
    return message_pdu()

def up_down_handler(query, path):
  try:
    q_elt = rpki.cms.xml_verify(query, cms_ta)
    rpki.relaxng.up_down.assertValid(q_elt)
    q_msg = sax_handler.saxify(q_elt)
  except Exception, data:
    rpki.log.error(traceback.format_exc())
    return 400, "Could not process PDU: %s" % data
  try:
    r_msg = q_msg.serve_top_level(None, None)
    r_elt = r_msg.toXML()
    try:
      rpki.relaxng.up_down.assertValid(r_elt)
    except lxml.etree.DocumentInvalid:
      rpki.log.debug(lxml.etree.tostring(r_elt, pretty_print = True, encoding ="utf-8", xml_declaration = True))
      raise
    return 200, rpki.cms.xml_sign(r_elt, cms_key, cms_certs, encoding = "utf-8")
  except Exception, data:
    rpki.log.error(traceback.format_exc())
    try:
      r_msg = q_msg.serve_error(data)
      r_elt = r_msg.toXML()
      rpki.relaxng.up_down.assertValid(r_elt)
      return 200, rpki.cms.xml_sign(r_elt, cms_key, cms_certs, encoding = "utf-8")
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

cms_ta      = rpki.x509.X509(Auto_file = cfg.get("cms-ta"))
cms_key     = rpki.x509.RSA(Auto_file = cfg.get("cms-key"))
cms_certs   = rpki.x509.X509_chain(Auto_files = cfg.multiget("cms-cert"))

https_key   = rpki.x509.RSA(Auto_file = cfg.get("https-key"))
https_certs = rpki.x509.X509_chain(Auto_files = cfg.multiget("https-cert"))
https_ta    = rpki.x509.X509_chain(Auto_files = cfg.multiget("https-ta"))

https_server_host = cfg.get("server-host", "")
https_server_port = int(cfg.get("server-port"))

rpki_key    = rpki.x509.RSA(Auto_file = cfg.get("rpki-key"))
rpki_issuer = rpki.x509.X509(Auto_file = cfg.get("rpki-issuer"))

rpki_subject_filename = cfg.get("rpki-subject-filename")
rpki_pkcs10_filename  = cfg.get("rpki-pkcs10-filename", "")

rootd_name  = cfg.get("rootd_name", "wombat")
rootd_base  = cfg.get("rootd_base", "rsync://" + rootd_name + ".invalid/")
rootd_cert  = cfg.get("rootd_cert", rootd_base + "rootd.cer")

rpki.https.server(privateKey    = https_key,
                  certChain     = https_certs,
                  x509TrustList = https_ta,
                  host          = https_server_host,
                  port          = https_server_port,
                  handlers      = up_down_handler)
