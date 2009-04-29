"""
Trivial RPKI up-down protocol client, for testing.

Configuration file is YAML to be compatable with APNIC rpki_poke.pl tool.

Usage: python testpoke.py [ { -y | --yaml }    configfile ]
                          [ { -r | --request } requestname ]
                          [ { -d | --debug } ]
                          [ { -h | --help } ]

Default configuration file is testpoke.yaml, override with --yaml option.

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

import os, time, getopt, sys, yaml
import rpki.resource_set, rpki.up_down, rpki.left_right, rpki.x509
import rpki.https, rpki.config, rpki.exceptions
import rpki.relaxng, rpki.oids, rpki.log

os.environ["TZ"] = "UTC"
time.tzset()

def usage(code):
  print __doc__
  sys.exit(code)

yaml_file = "testpoke.yaml"
yaml_cmd = None
debug = False

opts,argv = getopt.getopt(sys.argv[1:], "y:r:h?d", ["yaml=", "request=", "help", "debug"])
for o,a in opts:
  if o in ("-h", "--help", "-?"):
    usage(0)
  elif o in ("-y", "--yaml"):
    yaml_file = a
  elif o in ("-r", "--request"):
    yaml_cmd = a
  elif o in ("-d", "--debug"):
    debug = True
if argv:
  usage(1)

rpki.log.init("testpoke")

if debug:
  rpki.log.set_trace(True)

f = open(yaml_file)
yaml_data = yaml.load(f)
f.close()

if yaml_cmd is None and len(yaml_data["requests"]) == 1:
  yaml_cmd = yaml_data["requests"].keys()[0]

if yaml_cmd is None:
  usage(1)

yaml_req = yaml_data["requests"][yaml_cmd]

def get_PEM(name, cls, y = yaml_data):
  if name in y:
    return cls(PEM = y[name])
  if name + "-file" in y:
    return cls(PEM_file = y[name + "-file"])
  return None

def get_PEM_chain(name, cert = None):
  chain = []
  if cert is not None:
    chain.append(cert)
  if name in yaml_data:
    chain.extend([rpki.x509.X509(PEM = x) for x in yaml_data[name]])
  elif name + "-file" in yaml_data:
    chain.extend([rpki.x509.X509(PEM_file = x) for x in yaml_data[name + "-file"]])
  return chain

def query_up_down(q_pdu):
  q_msg = rpki.up_down.message_pdu.make_query(
    payload = q_pdu,
    sender = yaml_data["sender-id"],
    recipient = yaml_data["recipient-id"])
  q_cms = rpki.up_down.cms_msg.wrap(q_msg, cms_key, cms_certs, cms_crl)

  def done(der):
    r_msg, r_xml = rpki.up_down.cms_msg.unwrap(der, [cms_ta] + cms_ca_certs, pretty_print = True)
    print r_xml
    r_msg.payload.check_response()

  rpki.https.client(
    server_ta    = [https_ta] + https_ca_certs,
    client_key   = https_key,
    client_cert  = https_certs,
    msg          = q_cms,
    url          = yaml_data["posturl"],
    callback     = done)

def do_list():
  query_up_down(rpki.up_down.list_pdu())

def do_issue():
  q_pdu = rpki.up_down.issue_pdu()
  req_key = get_PEM("cert-request-key", rpki.x509.RSA, yaml_req) or cms_key
  sia = ((rpki.oids.name2oid["id-ad-caRepository"], ("uri", yaml_req["sia"][0])),
         (rpki.oids.name2oid["id-ad-rpkiManifest"], ("uri", yaml_req["sia"][0] + req_key.gSKI() + ".mnf")))
  q_pdu.class_name = yaml_req["class"]
  q_pdu.pkcs10 = rpki.x509.PKCS10.create_ca(req_key, sia)
  query_up_down(q_pdu)

def do_revoke():
  q_pdu = rpki.up_down.revoke_pdu()
  q_pdu.class_name = yaml_req["class"]
  q_pdu.ski = yaml_req["ski"]
  query_up_down(q_pdu)

dispatch = { "list" : do_list, "issue" : do_issue, "revoke" : do_revoke }

cms_ta         = get_PEM("cms-ca-cert", rpki.x509.X509)
cms_cert       = get_PEM("cms-cert", rpki.x509.X509)
cms_key        = get_PEM("cms-key", rpki.x509.RSA)
cms_crl        = get_PEM("cms-crl", rpki.x509.CRL)
cms_certs      = get_PEM_chain("cms-cert-chain", cms_cert)
cms_ca_certs   = get_PEM_chain("cms-ca-certs")

https_ta       = get_PEM("ssl-ca-cert", rpki.x509.X509)
https_key      = get_PEM("ssl-key", rpki.x509.RSA)
https_cert     = get_PEM("ssl-cert", rpki.x509.X509)
https_certs    = get_PEM_chain("ssl-cert-chain", https_cert)
https_ca_certs = get_PEM_chain("ssl-ca-certs")

if debug:
  dispatch[yaml_req["type"]]()
else:
  try:
    dispatch[yaml_req["type"]]()
  except Exception, edata:
    print "Failed:", edata
