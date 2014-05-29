# $Id$
#
# Copyright (C) 2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2009--2012  Internet Systems Consortium ("ISC")
# Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL, ISC, AND ARIN DISCLAIM ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL DRL,
# ISC, OR ARIN BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
# OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
Trivial RPKI up-down protocol client, for testing.

Configuration file is YAML to be compatable with APNIC rpki_poke.pl tool.
"""

import os
import time
import argparse
import sys
import yaml
import rpki.resource_set
import rpki.up_down
import rpki.left_right
import rpki.x509
import rpki.http
import rpki.config
import rpki.exceptions
import rpki.relaxng
import rpki.log
import rpki.async

os.environ["TZ"] = "UTC"
time.tzset()

parser = argparse.ArgumentParser(description = __doc__)
parser.add_argument("-y", "--yaml", required = True, type = argparse.FileType("r"),
                    help = "configuration file")
parser.add_argument("-r", "--request",
                    help = "request name")
parser.add_argument("-d", "--debug",
                    help = "enable debugging")
args = parser.parse_args()

rpki.log.init("testpoke")

yaml_data = yaml.load(args.yaml)

yaml_cmd = args.request

if yaml_cmd is None and len(yaml_data["requests"]) == 1:
  yaml_cmd = yaml_data["requests"].keys()[0]

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
  q_der = rpki.up_down.cms_msg().wrap(q_msg, cms_key, cms_certs, cms_crl)

  def done(r_der):
    global last_cms_timestamp
    r_cms = rpki.up_down.cms_msg(DER = r_der)
    r_msg = r_cms.unwrap([cms_ta] + cms_ca_certs)
    last_cms_timestamp = r_cms.check_replay(last_cms_timestamp)
    print r_cms.pretty_print_content()
    try:
      r_msg.payload.check_response()
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception, e:
      fail(e)

  rpki.http.want_persistent_client = False

  rpki.http.client(
    msg          = q_der,
    url          = yaml_data["posturl"],
    callback     = done,
    errback      = fail)

def do_list():
  query_up_down(rpki.up_down.list_pdu())

def do_issue():
  q_pdu = rpki.up_down.issue_pdu()
  req_key = get_PEM("cert-request-key", rpki.x509.RSA, yaml_req) or cms_key
  q_pdu.class_name = yaml_req["class"]
  q_pdu.pkcs10 = rpki.x509.PKCS10.create(
    keypair = req_key,
    is_ca = True,
    caRepository = yaml_req["sia"][0],
    rpkiManifest = yaml_req["sia"][0] + req_key.gSKI() + ".mft")
  query_up_down(q_pdu)

def do_revoke():
  q_pdu = rpki.up_down.revoke_pdu()
  q_pdu.class_name = yaml_req["class"]
  q_pdu.ski = yaml_req["ski"]
  query_up_down(q_pdu)

dispatch = { "list" : do_list, "issue" : do_issue, "revoke" : do_revoke }

def fail(e):                            # pylint: disable=W0621
  sys.exit("Testpoke failed: %s" % e)

cms_ta         = get_PEM("cms-ca-cert", rpki.x509.X509)
cms_cert       = get_PEM("cms-cert", rpki.x509.X509)
cms_key        = get_PEM("cms-key", rpki.x509.RSA)
cms_crl        = get_PEM("cms-crl", rpki.x509.CRL)
cms_certs      = get_PEM_chain("cms-cert-chain", cms_cert)
cms_ca_certs   = get_PEM_chain("cms-ca-certs")

last_cms_timestamp = None

try:
  dispatch[yaml_req["type"]]()
  rpki.async.event_loop()
except Exception, e:
  fail(e)
