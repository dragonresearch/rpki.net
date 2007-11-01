# $Id$

"""
Trivial RPKI up-down protocol root server, for testing.  Not suitable
for production use.  Overrides a bunch of method definitions from the
rpki.* classes in order to reuse as much code as possible.

Usage: python testroot.py [ { -c | --config } configfile ] [ { -h | --help } ]

Default configuration file is testroot.conf, override with --config option.
"""

import traceback, os, time, getopt, sys, lxml
import rpki.resource_set, rpki.up_down, rpki.left_right, rpki.x509
import rpki.https, rpki.config, rpki.cms, rpki.exceptions, rpki.relaxng

root_name = "wombat"
root_base = "rsync://" + root_name + ".invalid/"
root_cert = root_base + "testroot.cer"

def get_subject_cert():
  try:
    return rpki.x509.X509(Auto_file = rpki_subject_filename)
  except IOError:
    return None

def set_subject_cert(cert):
  f = open(rpki_subject_filename, "wb")
  f.write(cert.get_DER())
  f.close()

def compose_response(r_msg):
    rc = rpki.up_down.class_elt()
    rc.class_name = root_name
    rc.cert_url = rpki.up_down.multi_uri(root_cert)
    rc.resource_set_as, rc.resource_set_ipv4, rc.resource_set_ipv6 = rpki_issuer.get_3779resources()
    rc.issuer = rpki_issuer
    r_msg.payload.classes.append(rc)
    rpki_subject = get_subject_cert()
    if rpki_subject is not None:
      rc.certs.append(rpki.up_down.certificate_elt())
      rc.certs[0].cert_url = rpki.up_down.multi_uri(root_base + rpki_subject.gSKI() + ".cer")
      rc.certs[0].cert = rpki_subject

class list_pdu(rpki.up_down.list_pdu):
  def serve_pdu(self, xxx1, q_msg, r_msg, xxx2):
    r_msg.payload = rpki.up_down.list_response_pdu()
    compose_response(r_msg)

class issue_pdu(rpki.up_down.issue_pdu):
  def serve_pdu(self, xxx1, q_msg, r_msg, xxx2):
    self.pkcs10.check_valid_rpki()
    rpki_subject = get_subject_cert()
    if rpki_subject is not None:
      as, v4, v6 = rpki_issuer.get_3779resources()
      req_key = self.pkcs10.getPublicKey()
      req_sia = self.pkcs10.get_SIA()
      req_ski = self.pkcs10.get_SKI()
      crldp = root_base + rpki_issuer.gSKI() + ".crl"
      set_subject_cert(rpki_issuer.issue(keypair = rpki_key, subject_key = req_key, serial = int(time.time()), aia = test_cert, crldp = crldp, as = as, v4 = v4, v6 = v6))
    compose_response(r_msg)

class revoke_pdu(rpki.up_down.revoke_pdu):
  def serve_pdu(self, xxx1, q_msg, r_msg, xxx2):
    raise rpki.exceptions.NotImplementedYet

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
    traceback.print_exc()
    return 400, "Could not process PDU: %s" % data
  try:
    r_msg = q_msg.serve_top_level(None, None)
    r_elt = r_msg.toXML()
    try:
      rpki.relaxng.up_down.assertValid(r_elt)
    except lxml.etree.DocumentInvalid:
      print
      print lxml.etree.tostring(r_elt, pretty_print = True, encoding ="utf-8", xml_declaration = True)
      print
      raise
    return 200, rpki.cms.xml_sign(r_elt, cms_key, cms_certs, encoding = "utf-8")
  except Exception, data:
    traceback.print_exc()
    try:
      r_msg = q_msg.serve_error(data)
      r_elt = r_msg.toXML()
      rpki.relaxng.up_down.assertValid(r_elt)
      return 200, rpki.cms.xml_sign(r_elt, cms_key, cms_certs, encoding = "utf-8")
    except Exception, data:
      traceback.print_exc()
      return 500, "Could not process PDU: %s" % data

os.environ["TZ"] = "UTC"
time.tzset()

cfg_file = "testroot.conf"

opts,argv = getopt.getopt(sys.argv[1:], "c:h?", ["config=", "help"])
for o,a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  if o in ("-c", "--config"):
    cfg_file = a
if argv:
  raise RuntimeError, "Unexpected arguments %s" % argv

cfg = rpki.config.parser(cfg_file)
section = "testroot"

cms_ta      = rpki.x509.X509(Auto_file = cfg.get(section, "cms-ta"))
cms_key     = rpki.x509.RSA(Auto_file = cfg.get(section, "cms-key"))
cms_certs   = rpki.x509.X509_chain(Auto_files = cfg.multiget(section, "cms-cert"))

https_key   = rpki.x509.RSA(Auto_file = cfg.get(section, "https-key"))
https_certs = rpki.x509.X509_chain(Auto_files = cfg.multiget(section, "https-cert"))
https_tas   = rpki.x509.X509_chain(Auto_files = cfg.multiget(section, "https-ta"))

https_server_host = cfg.get(section, "server-host", "")
https_server_port = int(cfg.get(section, "server-port"))

rpki_key    = rpki.x509.RSA(Auto_file = cfg.get(section, "rpki-key"))
rpki_issuer = rpki.x509.X509(Auto_file = cfg.get(section, "rpki-issuer"))

rpki_subject_filename = cfg.get(section, "rpki-subject-filename")

rpki.https.server(privateKey    = https_key,
                  certChain     = https_certs,
                  host          = https_server_host,
                  port          = https_server_port,
                  handlers      = up_down_handler)
