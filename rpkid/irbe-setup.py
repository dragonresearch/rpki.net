"""
Set up the relationship between an IRBE and an RPKI engine given an
IRDB.  Our main task here is to create child objects in the RPKI
engine for every registrant object in the IRDB.

NB: This code is badly out of date, and has been kept only because
some of what it's doing might be useful in other tools that haven't
been written yet.  Don't believe anything you see here.


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

import os, MySQLdb
import rpki.left_right, rpki.relaxng, rpki.https
import rpki.x509, rpki.config, rpki.log

rpki.log.init("irbe-setup")

cfg = rpki.config.parser("irbe.conf", "irbe_cli")

db = MySQLdb.connect(user   = cfg.get("sql-username", section = "irdbd"),
                     db     = cfg.get("sql-database", section = "irdbd"),
                     passwd = cfg.get("sql-password", section = "irdbd"))
cur = db.cursor()
db.autocommit(True)

bpki_ta     = rpki.x509.X509(Auto_file  = cfg.get("bpki-ta"))
rpkid_cert  = rpki.x509.X509(Auto_files = cfg.get("rpkid-cert"))
irbe_cert   = rpki.x509.X509(Auto_files = cfg.get("irbe-cert"))
irbe_key    = rpki.x509.RSA( Auto_file  = cfg.get("irbe-key"))
https_url   = cfg.get("https-url")

def call_rpkid(pdu):
  """
  Hand a PDU to rpkid and get back the response.  Just throw an
  exception if anything bad happens, no fancy error handling.
  """

  msg = rpki.left_right.msg.query((pdu,))
  cms = rpki.left_right.cms_msg.wrap(msg, irbe_key, irbe_cert)
  der = rpki.https.client(client_key   = irbe_key,
                          client_cert  = irbe_cert,
                          server_ta    = (bpki_ta, rpkid_cert),
                          url          = https_url,
                          msg          = cms)
  msg = rpki.left_right.cms_msg.unwrap(der, (bpki_ta, rpkid_cert))
  pdu = msg[0]
  assert len(msg) == 1 and msg.type == "reply" and not isinstance(pdu, rpki.left_right.report_error_elt)
  return pdu

print "Create a self instance"
pdu = call_rpkid(rpki.left_right.self_elt.make_pdu(action = "create", crl_interval = 84600))
self_id = pdu.self_id

print "Create a business signing context"
pdu = rpki.left_right.bsc_elt.make_pdu(action = "create", self_id = self_id, generate_keypair = True)
pdu = call_rpkid(pdu)
bsc_id = pdu.bsc_id

print "Issue the business cert"
i, o = os.popen2(("openssl", "x509", "-req",
                  "-CA", "biz-certs/Bob-CA.cer",
                  "-CAkey", "biz-certs/Bob-CA.key",
                  "-CAserial", "biz-certs/Bob-CA.srl"))
i.write(pdu.pkcs10_request.get_PEM())
i.close()
cer = rpki.x509.X509(PEM = o.read())
o.close()

print "Set up the business cert chain"
pdu = rpki.left_right.bsc_elt.make_pdu(action = "set", self_id = self_id, bsc_id = bsc_id, signing_cert = cer)
call_rpkid(pdu)

print "Create a repository context"
pdu = call_rpkid(rpki.left_right.repository_elt.make_pdu(action = "create", self_id = self_id, bsc_id = bsc_id))
repository_id = pdu.repository_id

print "Create a parent context"
ta = rpki.x509.X509(Auto_file = "biz-certs/Elena-Root.cer")
pdu = call_rpkid(rpki.left_right.parent_elt.make_pdu(
  action = "create", self_id = self_id, bsc_id = bsc_id, repository_id = repository_id, bpki_cms_cert = ta,
  peer_contact_uri = "https://localhost:44333/", sia_base = "rsync://wombat.invalid/"))
parent_id = pdu.parent_id

print "Create child contexts for everybody"
print "Using a single cert for all of these registrants is a crock"

cer = rpki.x509.X509(Auto_file = "biz-certs/Frank-Root.cer")

cur.execute("SELECT registrant_id, registrant_name FROM registrant")
registrants = cur.fetchall()

for registrant_id, registrant_name  in registrants:
  print "Attempting to bind", registrant_id, registrant_name
  pdu = call_rpkid(rpki.left_right.child_elt.make_pdu(action = "create", self_id = self_id, bsc_id = bsc_id, bpki_cms_cert = cer))
  print "Attempting to bind", registrant_id, registrant_name, pdu.child_id
  cur.execute(
    """
      UPDATE registrant
      SET rpki_self_id = %d, rpki_child_id = %d
      WHERE registrant_id = %d
    """,
    (self_id, pdu.child_id, registrant_id))
