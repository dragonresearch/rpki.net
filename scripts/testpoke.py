# $Id$

"""
Trivial RPKI up-down protocol client, for testing.

Configuration file is YAML to be compatable with APNIC rpki_poke.pl tool.

Usage: python testpoke.py [ { -c | --config } configfile ] [ { -r | --request } requestname ] [ { -h | --help } ]

Default configuration file is testpoke.yaml, override with --config option.
"""

import traceback, os, time, getopt, sys, lxml, yaml
import rpki.resource_set, rpki.up_down, rpki.left_right, rpki.x509
import rpki.https, rpki.config, rpki.cms, rpki.exceptions
import rpki.relaxng, rpki.oids

os.environ["TZ"] = "UTC"
time.tzset()

def usage(code):
  print __doc__
  sys.exit(code)

yaml_file = "testpoke.yaml"
yaml_cmd = None

opts,argv = getopt.getopt(sys.argv[1:], "c:r:h?", ["config=", "request=", "help"])
for o,a in opts:
  if o in ("-h", "--help", "-?"):
    usage(0)
  elif o in ("-c", "--config"):
    yaml_file = a
  elif o in ("-r", "--request"):
    yaml_cmd = a
if argv:
  usage(1)

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
  chain = rpki.x509.X509_chain()
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
  q_elt = q_msg.toXML()
  rpki.relaxng.up_down.assertValid(q_elt)
  q_cms = rpki.cms.xml_sign(q_elt, cms_key, cms_certs, encoding = "UTF-8")
  r_cms = rpki.https.client(
    x509TrustList = https_tas,
    privateKey = https_key,
    certChain = https_certs,
    msg = q_cms,
    url = yaml_data["posturl"])
  r_xml = rpki.cms.verify(r_cms, cms_ta)
  r_elt = lxml.etree.fromstring(r_xml)
  rpki.relaxng.up_down.assertValid(r_elt)
  return r_xml

def do_list():
  print query_up_down(rpki.up_down.list_pdu())

def do_issue():
  q_pdu = rpki.up_down.issue_pdu()
  req_key = get_PEM("cert-request-key", rpki.x509.RSA, yaml_req) or cms_key
  sia = ((rpki.oids.name2oid["id-ad-caRepository"], ("uri", yaml_req["sia"][0])),
         (rpki.oids.name2oid["id-ad-rpkiManifest"], ("uri", yaml_req["sia"][0] + req_key.gSKI() + ".mnf")))
  q_pdu.class_name = yaml_req["class"]
  q_pdu.pkcs10 = rpki.x509.PKCS10.create_ca(req_key, sia)
  print query_up_down(q_pdu)

def do_revoke():
  q_pdu = rpki.up_down.revoke_pdu()
  q_pdu.class_name = yaml_req["class"]
  q_pdu.ski = yaml_req["ski"]
  print query_up_down(q_pdu)

dispatch = { "list" : do_list, "issue" : do_issue, "revoke" : do_revoke }

cms_ta      = get_PEM("cms-ca-cert", rpki.x509.X509)
cms_cert    = get_PEM("cms-cert", rpki.x509.X509)
cms_key     = get_PEM("cms-key", rpki.x509.RSA)
cms_certs   = get_PEM_chain("cms-cert-chain", cms_cert)

https_ta    = get_PEM("ssl-ta", rpki.x509.X509)
https_key   = get_PEM("ssl-key", rpki.x509.RSA)
https_cert  = get_PEM("ssl-cert", rpki.x509.X509)
https_certs = get_PEM_chain("ssl-cert-chain", https_cert)

https_tas   = rpki.x509.X509_chain()
if https_ta is not None:
  https_tas.append(https_ta)

dispatch[yaml_req["type"]]()
