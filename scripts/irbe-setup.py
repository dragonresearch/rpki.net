# $Id$

"""Set up the relationship between an IRBE and an RPKI engine given an
IRDB.  Our main task here is to create child objects in the RPKI
engine for every registrant object in the IRDB.
"""

import os, MySQLdb, getopt, sys, lxml.etree, lxml.sax
import rpki.left_right, rpki.relaxng, rpki.cms, rpki.https
import rpki.x509, rpki.config, rpki.log

rpki.log.init("irbe-setup")

cfg = rpki.config.parser("irbe.conf")

db = MySQLdb.connect(user   = cfg.get("irdb", "sql-username"),
                     db     = cfg.get("irdb", "sql-database"),
                     passwd = cfg.get("irdb", "sql-password"))
cur = db.cursor()

cms_certs   = rpki.x509.X509_chain(Auto_files = cfg.multiget("irbe-cli", "cms-cert"))
cms_key     = rpki.x509.RSA(       Auto_file  = cfg.get(     "irbe-cli", "cms-key"))
cms_ta      = rpki.x509.X509(      Auto_file  = cfg.get(     "irbe-cli", "cms-ta"))
https_certs = rpki.x509.X509_chain(Auto_files = cfg.multiget("irbe-cli", "https-cert"))
https_key   = rpki.x509.RSA(       Auto_file  = cfg.get(     "irbe-cli", "https-key"))
https_tas   = rpki.x509.X509_chain(Auto_files = cfg.multiget("irbe-cli", "https-ta"))
https_url   = cfg.get(                                       "irbe-cli", "https-url")

def call_rpkid(pdu):
  """Hand a PDU to rpkid and get back the response.  Just throw an
  exception if anything bad happens, no fancy error handling.
  """

  pdu.type = "query"
  msg = rpki.left_right.msg((pdu,))
  elt = msg.toXML()
  try:
    rpki.relaxng.left_right.assertValid(elt)
  except lxml.etree.DocumentInvalid:
    print lxml.etree.tostring(elt, pretty_print = True, encoding = "us-ascii")
    raise
  elt = rpki.cms.xml_verify(cms = rpki.https.client(privateKey    = https_key,
                                                    certChain     = https_certs,
                                                    x509TrustList = https_tas,
                                                    url           = https_url,
                                                    msg           = rpki.cms.xml_sign(elt   = elt,
                                                                                      key   = cms_key,
                                                                                      certs = cms_certs)),
                            ta = cms_ta)
  try:
    rpki.relaxng.left_right.assertValid(elt)
  except lxml.etree.DocumentInvalid:
    print lxml.etree.tostring(elt, pretty_print = True, encoding = "us-ascii")
    raise
  msg = rpki.left_right.sax_handler.saxify(elt)
  pdu = msg[0]
  assert len(msg) == 1 and pdu.type == "reply" and not isinstance(pdu, rpki.left_right.report_error_elt)
  return pdu

print "Create a self instance"
pdu = rpki.left_right.self_elt()
pdu.action = "create"
pdu.crl_interval = 84600
pdu = call_rpkid(pdu)
self_id = pdu.self_id

print "Create a business signing context"
pdu = rpki.left_right.bsc_elt()
pdu.action = "create"
pdu.self_id = self_id
pdu.generate_keypair = True
pdu.signing_cert.append(rpki.x509.X509(Auto_file = "biz-certs/Bob-CA.cer"))
pdu = call_rpkid(pdu)
bsc_id = pdu.bsc_id

print "Issue the business cert"
i,o = os.popen2(("openssl", "x509", "-req",
                 "-CA", "biz-certs/Bob-CA.cer",
                 "-CAkey", "biz-certs/Bob-CA.key",
                 "-CAserial", "biz-certs/Bob-CA.srl"))
i.write(pdu.pkcs10_cert_request.get_PEM())
i.close()
cer = rpki.x509.X509(PEM = o.read())
o.close()

print "Set up the business cert chain"
pdu = rpki.left_right.bsc_elt()
pdu.action = "set"
pdu.self_id = self_id
pdu.bsc_id = bsc_id
pdu.signing_cert.append(cer)
call_rpkid(pdu)

print "Create a repository context"
pdu = rpki.left_right.repository_elt()
pdu.action = "create"
pdu.self_id = self_id
pdu.bsc_id = bsc_id
pdu = call_rpkid(pdu)
repository_id = pdu.repository_id

print "Create a parent context"
pdu = rpki.left_right.parent_elt()
pdu.action = "create"
pdu.self_id = self_id
pdu.bsc_id = bsc_id
pdu.repository_id = repository_id
pdu.peer_contact_uri = "https://localhost:44333/" 
pdu.cms_ta = rpki.x509.X509(Auto_file = "biz-certs/Elena-Root.cer")
pdu.https_ta = pdu.cms_ta
pdu.sia_base = "rsync://wombat.invalid/"
pdu = call_rpkid(pdu)
parent_id = pdu.parent_id

print "Create child contexts for everybody"
print "Using a single cert for all of these registrants is a crock"

cer = rpki.x509.X509(Auto_file = "biz-certs/Frank-Root.cer")

cur.execute("SELECT registrant_id, subject_name FROM registrant")
registrants = cur.fetchall()

for registrant_id, subject_name  in registrants:
  print "Attempting to bind", registrant_id, subject_name
  pdu = rpki.left_right.child_elt()
  pdu.action = "create"
  pdu.self_id = self_id
  pdu.bsc_id = bsc_id
  pdu.cms_ta = cer
  pdu = call_rpkid(pdu)
  print "Attempting to bind", registrant_id, subject_name, pdu.child_id
  cur.execute("""UPDATE registrant
                 SET rpki_self_id = %d, rpki_child_id = %d
                 WHERE registrant_id = %d
              """ % (self_id, pdu.child_id, registrant_id))
