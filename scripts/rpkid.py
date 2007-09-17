# $Id$

"""
Start at the RPKI daemon.  This isn't real yet.  So far it's just a
framework onto which I'm bolting various parts for testing.
"""

import tlslite.api, MySQLdb, xml.sax, lxml.etree, lxml.sax, POW, POW.pkix, traceback
import rpki.https, rpki.config, rpki.resource_set, rpki.up_down, rpki.left_right, rpki.relaxng, rpki.cms

show_traceback = True

def decode(msg, cms_ta):
  return lxml.etree.fromstring(rpki.cms.decode(msg, cms_ta))

def encode(msg, cms_key, cms_certs):
  return rpki.cms.encode(lxml.etree.tostring(msg, pretty_print=True, encoding="us-ascii", xml_declaration=True), cms_key, cms_certs)

def left_right_handler(query, path):

  def make_reply(q_pdu, r_pdu=None):
    if r_pdu is None:
      r_pdu = q_pdu.__class__()
      r_pdu.self_id = q_pdu.self_id
      setattr(r_pdu, q_pdu.sql_template.index, getattr(q_pdu, q_pdu.sql_template.index))
    r_pdu.action = q_pdu.action
    r_pdu.type = "reply"
    return r_pdu

  def destroy_handler(q_pdu):
    r_pdu = make_reply(q_pdu)
    q_pdu.sql_delete()    
    r_msg.append(r_pdu)

  def create_handler(q_pdu):
    r_pdu = make_reply(q_pdu)
    q_pdu.sql_store(db, cur)
    setattr(r_pdu, q_pdu.sql_template.index, getattr(q_pdu, q_pdu.sql_template.index))
    r_msg.append(r_pdu)

  def get_handler(q_pdu):
    r_pdu = q_pdu.sql_fetch(db, cur, getattr(q_pdu, q_pdu.sql_template.index))
    if r_pdu is not None:
      make_reply(q_pdu, r_pdu)
      r_msg.append(r_pdu)
    else:
      r_msg.append(make_error_report(q_pdu))

  def set_handler(q_pdu):
    data = q_pdu.sql_fetch(db, cur, getattr(q_pdu, q_pdu.sql_template.index))
    if data is not None:
      for a in data.sql_template.columns[1:]:
        v = getattr(q_pdu, a)
        if v is not None:
          setattr(data, a, v)
      q_pdu.sql_store(db, cur)
      r_pdu = make_reply(q_pdu)
      r_msg.append(r_pdu)
    else:
      r_msg.append(make_error_report(q_pdu))

  def list_handler(q_pdu):
    for r_pdu in q_pdu.sql_fetch_all(db, cur):
      make_reply(q_pdu, r_pdu)
      r_msg.append(r_pdu)

  try:
    q_elt = decode(query, cms_ta_irbe)
    lr_rng.assertValid(q_elt)
    saxer = rpki.left_right.sax_handler()
    lxml.sax.saxify(q_elt, saxer)
    q_msg = saxer.result
    r_msg = rpki.left_right.msg()
    for q_pdu in q_msg:
      assert isinstance(q_pdu, rpki.left_right.data_elt) and q_pdu.type == "query"
      { "create"  : create_handler,
        "set"     : set_handler,
        "get"     : get_handler,
        "list"    : list_handler,
        "destroy" : destroy_handler }[q_pdu.action](q_pdu)
    r_elt = r_msg.toXML()
    try:
      lr_rng.assertValid(r_elt)
    except lxml.etree.DocumentInvalid:
      print lxml.etree.tostring(r_elt, pretty_print=True, encoding="us-ascii", xml_declaration=True)
      raise
    return 200, encode(r_elt, cms_key, cms_certs)

  except Exception, data:
    if show_traceback:
      traceback.print_exc()
    raise
    return 500, "Unhandled exception %s" % data

def up_down_handler(query, path):
  raise NotImplementedError

def cronjob_handler(query, path):
  raise NotImplementedError

cfg = rpki.config.parser("re.conf")
section = "rpki"

db = MySQLdb.connect(user   = cfg.get(section, "sql-username"),
                     db     = cfg.get(section, "sql-database"),
                     passwd = cfg.get(section, "sql-password"))

cur = db.cursor()

lr_rng = rpki.relaxng.RelaxNG("left-right-schema.rng")
ud_rng = rpki.relaxng.RelaxNG("up-down-schema.rng")

cms_ta_irdb = cfg.get(section, "cms-ta-irdb")
cms_ta_irbe = cfg.get(section, "cms-ta-irbe")
cms_key     = cfg.get(section, "cms-key")
cms_certs   = cfg.multiget(section, "cms-cert")

https_key   = rpki.x509.RSA_Keypair(PEM_file = cfg.get(section, "https-key"))
https_certs = certChain = rpki.x509.X509_chain()

https_certs.load_from_PEM(cfg.multiget(section, "https-cert"))

rpki.https.server(privateKey=https_key, certChain=https_certs,
                  handlers=(("/left-right", left_right_handler),
                            ("/up-down",    up_down_handler),
                            ("/cronjob",    cronjob_handler)))
