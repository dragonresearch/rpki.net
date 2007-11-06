# $Id$

"""
Trivial RPKI up-down protocol client, for testing.

Configuration file is YAML to be compatable with APNIC rpki_poke.pl tool.

Usage: python testpoke.py [ { -c | --config } configfile ] [ { -r | --request } requestname ] [ { -h | --help } ]

Default configuration file is testpoke.yaml, override with --config option.
"""

import traceback, os, time, getopt, sys, lxml, yaml
import rpki.resource_set, rpki.up_down, rpki.left_right, rpki.x509
import rpki.https, rpki.config, rpki.cms, rpki.exceptions, rpki.relaxng

def get_PEM(name, cls):
  if name in yaml_data:
    return cls(PEM = yaml_data[name])
  if name + "-file" in yaml_data:
    return cls(PEM_file = yaml_data[name + "-file"])
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
  q_msg = rpki.up_down.message_pdu.make_query(q_pdu, sender = yaml_data["sender-id"], recipient = yaml_data["recipient-id"])
  q_elt = q_msg.toXML()
  rpki.relaxng.up_down.assertValid(q_elt)
  q_cms = rpki.cms.xml_sign(q_elt, cms_key, cms_certs, encoding = "UTF-8")
  r_cms = rpki.https.client(x509TrustList = https_tas, privateKey = https_key, certChain = https_certs, msg = q_cms, url = yaml_data["posturl"])
  r_xml = rpki.cms.verify(r_cms, cms_ta)
  r_elt = lxml.etree.fromstring(r_xml)
  rpki.relaxng.up_down.assertValid(r_elt)
  return r_xml

def do_list():
  print query_up_down(rpki.up_down.list_pdu())

def do_issue():
  raise NotImplementedError

def do_revoke():
  raise NotImplementedError

dispatch = { "list" : do_list, "issue" : do_issue, "revoke" : do_revoke }

os.environ["TZ"] = "UTC"
time.tzset()

yaml_file = "testpoke.yaml"
yaml_req = None

opts,argv = getopt.getopt(sys.argv[1:], "c:r:h?", ["config=", "request=", "help"])
for o,a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  elif o in ("-c", "--config"):
    yaml_file = a
  elif o in ("r", "--request"):
    yaml_req = a
if argv:
  raise RuntimeError, "Unexpected arguments %s" % argv

f = open(yaml_file)
yaml_data = yaml.load(f)
f.close()

if yaml_req is None and len(yaml_data["requests"]) == 1:
  yaml_req = yaml_data["requests"].keys()[0]

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

dispatch[yaml_data["requests"][yaml_req]["type"]]()
