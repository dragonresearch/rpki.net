"""
IRBE-side stuff for myrpki testbed.

$Id$

Copyright (C) 2009  Internet Systems Consortium ("ISC")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import lxml.etree, base64, subprocess, sys, os, time, getopt, MySQLdb
import rpki.https, rpki.config, rpki.resource_set, rpki.relaxng
import rpki.exceptions, rpki.left_right, rpki.log, rpki.x509, rpki.async
import myrpki

rng = lxml.etree.RelaxNG(lxml.etree.parse("myrpki.rng"))

def tag(t):
  return "{http://www.hactrn.net/uris/rpki/myrpki/}" + t

def findbase64(tree, name, b64type = rpki.x509.X509):
  x = tree.findtext(tag(name))
  return b64type(Base64 = x) if x else None

# For simple cases we don't really care what these values are, so long
# as we're consistant about them, so just wire them in for now.
repository_handle = "r"
bsc_handle = "b"

class caller(object):
  """
  Handle client-side mechanics for left-right and publication
  protocols.
  """

  debug = True

  def __init__(self, proto, client_key, client_cert, server_ta, server_cert, url):
    self.proto = proto
    self.client_key = client_key
    self.client_cert = client_cert
    self.server_ta = server_ta
    self.server_cert = server_cert
    self.url = url

  def __call__(self, cb, eb, pdus):

    def done(cms):
      msg, xml = self.proto.cms_msg.unwrap(cms, (self.server_ta, self.server_cert), pretty_print = True)
      if self.debug:
        print "Reply:", xml
      cb(msg)

    msg = self.proto.msg.query(pdus)
    cms, xml = self.proto.cms_msg.wrap(msg, self.client_key, self.client_cert, pretty_print = True)
    if self.debug:
      print "Query:", xml

    rpki.https.client(
      client_key   = self.client_key,
      client_cert  = self.client_cert,
      server_ta    = self.server_ta,
      url          = self.url,
      msg          = cms,
      callback     = done,
      errback      = eb)

os.environ["TZ"] = "UTC"
time.tzset()

rpki.log.init("myirbe")

cfg_file = "myrpki.conf"

opts, argv = getopt.getopt(sys.argv[1:], "c:h?", ["config=", "help"])
for o, a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  if o in ("-c", "--config"):
    cfg_file = a
if argv:
  raise RuntimeError, "Unexpected arguments %s" % argv

cfg = rpki.config.parser(cfg_file, "myirbe")

modified = False

# I suppose the distinguished names in these certificates might need
# to become configurable eventually.

bpki_rpkid = myrpki.CA(cfg_file, cfg.get("rpkid_ca_directory"))
modified |= bpki_rpkid.setup("/CN=rpkid TA")
for name in ("rpkid", "irdbd", "irbe_cli"):
  modified |= bpki_rpkid.ee("/CN=%s EE" % name, name)

bpki_pubd  = myrpki.CA(cfg_file, cfg.get("pubd_ca_directory"))
modified |= bpki_pubd.setup("/CN=pubd TA")
for name in ("pubd", "irbe_cli"):
  modified |= bpki_pubd.ee("/CN=%s EE" % name, name)

bpki_rootd = myrpki.CA(cfg_file, cfg.get("rootd_ca_directory"))
modified |= bpki_rootd.setup("/CN=rootd TA")
modified |= bpki_rootd.ee("/CN=rootd EE", "rootd")

if modified:
  print "BPKI (re)initialized.  You need to (re)start daemons before continuing."
  sys.exit()

irdbd_cfg = rpki.config.parser(cfg.get("irdbd_conf"), "irdbd")

db = MySQLdb.connect(user   = irdbd_cfg.get("sql-username"),
                     db     = irdbd_cfg.get("sql-database"),
                     passwd = irdbd_cfg.get("sql-password"))

cur = db.cursor()

if cfg.has_section("myrpki"):
  myrpki.main()
  # We should set a variable here with the generated filename, both to
  # automate things without user intervention and also because we
  # might care that this one .xml file was generated from our own
  # config rather than by somebody we're hosting.

# This will need to come from the command line or a csv file or
# something, except in the case where it's our own (self-hosted case).
# Eventually this will most likely turn into a loop over all the .xml
# files we need to process, including our own.
#
xmlfile = "myrpki.xml"

tree = lxml.etree.parse(xmlfile).getroot()
rng.assertValid(tree)

my_handle = tree.get("handle")

cur.execute(
  """
  DELETE
  FROM  roa_request_prefix
  USING roa_request, roa_request_prefix
  WHERE roa_request.roa_request_id = roa_request_prefix.roa_request_id AND roa_request.roa_request_handle = %s
  """, (my_handle,))

cur.execute("DELETE FROM roa_request WHERE roa_request.roa_request_handle = %s", (my_handle,))

for x in tree.getiterator(tag("roa_request")):
  cur.execute("INSERT roa_request (roa_request_handle, asn) VALUES (%s, %s)", (my_handle, x.get("asn")))
  roa_request_id = cur.lastrowid
  for version, prefix_set in ((4, rpki.resource_set.roa_prefix_set_ipv4(x.get("v4"))), (6, rpki.resource_set.roa_prefix_set_ipv6(x.get("v6")))):
    if prefix_set:
      cur.executemany("INSERT roa_request_prefix (roa_request_id, prefix, prefixlen, max_prefixlen, version) VALUES (%s, %s, %s, %s, %s)",
                      ((roa_request_id, p.prefix, p.prefixlen, p.max_prefixlen, version) for p in prefix_set))

cur.execute(
  """
  DELETE
  FROM   registrant_asn
  USING registrant, registrant_asn
  WHERE registrant.registrant_id = registrant_asn.registrant_id AND registrant.registry_handle = %s
  """ , (my_handle,))

cur.execute(
  """
  DELETE FROM registrant_net USING registrant, registrant_net
  WHERE registrant.registrant_id = registrant_net.registrant_id AND registrant.registry_handle = %s
  """ , (my_handle,))

cur.execute("DELETE FROM registrant WHERE registrant.registry_handle = %s" , (my_handle,))

for x in tree.getiterator(tag("child")):
  child_handle = x.get("handle")
  asns = rpki.resource_set.resource_set_as(x.get("asns"))
  ipv4 = rpki.resource_set.resource_set_ipv4(x.get("v4"))
  ipv6 = rpki.resource_set.resource_set_ipv6(x.get("v6"))

  cur.execute("INSERT registrant (registrant_handle, registry_handle, registrant_name, valid_until) VALUES (%s, %s, %s, %s)",
              (child_handle, my_handle, child_handle, rpki.sundial.datetime.fromXMLtime(x.get("valid_until")).to_sql()))
  child_id = cur.lastrowid
  if asns:
    cur.executemany("INSERT registrant_asn (start_as, end_as, registrant_id) VALUES (%s, %s, %s)",
                    ((a.min, a.max, child_id) for a in asns))
  if ipv4:
    cur.executemany("INSERT registrant_net (start_ip, end_ip, version, registrant_id) VALUES (%s, %s, 4, %s)",
                    ((a.min, a.max, child_id) for a in ipv4))
  if ipv6:
    cur.executemany("INSERT registrant_net (start_ip, end_ip, version, registrant_id) VALUES (%s, %s, 6, %s)",
                    ((a.min, a.max, child_id) for a in ipv6))

db.commit()

# Various parameters that ought to come out of a config or xml file eventually

# These probably come from the .conf file
rsync_base = "rsync://server.example/"
pubd_base  = "https://localhost:4402"
rpkid_base = "https://localhost:4404"

# These are specific to the entity under discussion, and in this
# script's case may differ depending on whether this is the
# self-hosting case or not.

my_parent_handle = "and-where-exactly-do-i-get-this-question-mark"

# This is wrong, should be parent's sia_base + my_handle + "/", but
# how do we get parent's sia_base in this setup?
#
parent_sia_base = rsync_base + my_handle + "/"
pubd_base_uri = parent_sia_base

repository_peer_contact_uri = pubd_base + "/client/" + my_handle

parent_peer_contact_uri = rpkid_base + "/up-down/" + my_parent_handle + "/" + my_handle

# These are constants and could easily come out of [myirbe] config section.
self_crl_interval = 300
self_regen_margin = 120

hosted_cacert = findbase64(tree, "bpki_ca_certificate")
if not hosted_cacert:
  print "Nothing else I can do without a trust anchor for the entity I'm hosting."
  sys.exit()

rpkid_xcert = rpki.x509.X509(PEM_file = bpki_rpkid.fxcert(my_handle + ".cacert.cer", hosted_cacert.get_PEM(), path_restriction = 1))
pubd_xcert  = rpki.x509.X509(PEM_file = bpki_pubd.fxcert(my_handle + ".cacert.cer", hosted_cacert.get_PEM()))

call_rpkid = rpki.async.sync_wrapper(caller(
  proto       = rpki.left_right,
  client_key  = rpki.x509.RSA( PEM_file = bpki_rpkid.dir + "/irbe_cli.key"),
  client_cert = rpki.x509.X509(PEM_file = bpki_rpkid.dir + "/irbe_cli.cer"),
  server_ta   = rpki.x509.X509(PEM_file = bpki_rpkid.cer),
  server_cert = rpki.x509.X509(PEM_file = bpki_rpkid.dir + "/rpkid.cer"),
  url         = rpkid_base + "/left-right"))

call_pubd = rpki.async.sync_wrapper(caller(
  proto       = rpki.publication,
  client_key  = rpki.x509.RSA( PEM_file = bpki_pubd.dir + "/irbe_cli.key"),
  client_cert = rpki.x509.X509(PEM_file = bpki_pubd.dir + "/irbe_cli.cer"),
  server_ta   = rpki.x509.X509(PEM_file = bpki_pubd.cer),
  server_cert = rpki.x509.X509(PEM_file = bpki_pubd.dir + "/pubd.cer"),
  url         = pubd_base + "/control"))

pubd_reply = call_pubd((
  rpki.publication.client_elt.make_pdu(action = "get", tag = "client", client_handle = my_handle),))

client_pdu = pubd_reply[0]

if isinstance(client_pdu, rpki.publication.report_error_elt) or client_pdu.base_uri != pubd_base_uri or client_pdu.bpki_cert != pubd_xcert:
  pubd_reply = call_pubd((rpki.publication.client_elt.make_pdu(
    action = "create" if isinstance(client_pdu, rpki.publication.report_error_elt) else "set",
    tag = "client",
    client_handle = my_handle,
    bpki_cert = pubd_xcert,
    base_uri = pubd_base_uri),))
  assert len(pubd_reply) == 1 and isinstance(pubd_reply[0], rpki.publication.client_elt) and pubd_reply[0].client_handle == my_handle

rpkid_reply = call_rpkid((
  rpki.left_right.self_elt.make_pdu(      action = "get",  tag = "self",       self_handle = my_handle),
  rpki.left_right.bsc_elt.make_pdu(       action = "list", tag = "bsc",        self_handle = my_handle),
  rpki.left_right.repository_elt.make_pdu(action = "list", tag = "repository", self_handle = my_handle),
  rpki.left_right.parent_elt.make_pdu(    action = "list", tag = "parent",     self_handle = my_handle),
  rpki.left_right.child_elt.make_pdu(     action = "list", tag = "child",      self_handle = my_handle)))

self_pdu        = rpkid_reply[0]
bsc_pdus        = dict((x.bsc_handle, x) for x in rpkid_reply if isinstance(x, rpki.left_right.bsc_elt))
repository_pdus = dict((x.repository_handle, x) for x in rpkid_reply if isinstance(x, rpki.left_right.repository_elt))
parent_pdus     = dict((x.parent_handle, x) for x in rpkid_reply if isinstance(x, rpki.left_right.parent_elt))
child_pdus      = dict((x.child_handle, x) for x in rpkid_reply if isinstance(x, rpki.left_right.child_elt))

rpkid_query = []

if (isinstance(self_pdu, rpki.left_right.report_error_elt) or
    self_pdu.crl_interval != self_crl_interval or
    self_pdu.regen_margin != self_regen_margin or
    self_pdu.bpki_cert != pubd_xcert):
  rpkid_query.append(rpki.left_right.self_elt.make_pdu(
    action = "create" if isinstance(self_pdu, rpki.left_right.report_error_elt) else "set",
    tag = "self",
    self_handle = my_handle,
    bpki_cert = pubd_xcert,
    crl_interval = self_crl_interval,
    regen_margin = self_regen_margin))

bsc_cert = findbase64(tree, "bpki_bsc_certificate")
bsc_crl  = findbase64(tree, "bpki_crl", rpki.x509.CRL)

bsc_pdu = bsc_pdus.pop(bsc_handle, None)

if bsc_pdu is None:
  rpkid_query.append(rpki.left_right.bsc_elt.make_pdu(
    action = "create",
    tag = "bsc",
    self_handle = my_handle,
    bsc_handle = bsc_handle,
    generate_keypair = "yes"))
elif bsc_pdu.signing_cert != bsc_cert or bsc_pdu.signing_cert_crl != bsc_crl:
  rpkid_query.append(rpki.left_right.bsc_elt.make_pdu(
    action = "set",
    tag = "bsc",
    self_handle = my_handle,
    bsc_handle = bsc_handle,
    signing_cert = bsc_cert,
    signing_cert_crl = bsc_crl))

rpkid_query.extend(rpki.left_right.bsc_elt.make_pdu(
  action = "destroy", self_handle = my_handle, bsc_handle = b) for b in bsc_pdus)

bsc_req = None

if bsc_pdu and bsc_pdu.pkcs10_request:
  bsc_req = bsc_pdu.pkcs10_request

repository_pdu = repository_pdus.pop(repository_handle, None)

if (repository_pdu is None or
    repository_pdu.bsc_handle != bsc_handle or
    repository_pdu.peer_contact_uri != repository_peer_contact_uri or
    repository_pdu.bpki_cms_cert != rpkid_xcert or
    repository_pdu.bpki_https_cert != rpkid_xcert):
  rpkid_query.append(rpki.left_right.repository_elt.make_pdu(
    action = "create" if repository_pdu is None else "set",
    tag = "repository",
    self_handle = my_handle,
    repository_handle = repository_handle,
    bsc_handle = bsc_handle,
    peer_contact_uri = repository_peer_contact_uri,
    bpki_cms_cert = rpkid_xcert,
    bpki_https_cert = rpkid_xcert))

rpkid_query.extend(rpki.left_right.repository_elt.make_pdu(
  action = "destroy", self_handle = my_handle, repository_handle = r) for r in repository_pdus)

for parent in tree.getiterator(tag("parent")):

  parent_handle = parent.get("handle")
  parent_pdu = parent_pdus.pop(parent_handle, None)

  if (parent_pdu is None or
      parent_pdu.bsc_handle != bsc_handle or
      parent_pdu.repository_handle != repository_handle or
      parent_pdu.peer_contact_uri != parent.get("uri") or
      parent_pdu.sia_base != parent_sia_base or
      parent_pdu.sender_name != my_handle or
      parent_pdu.recipient_name != parent_handle or
      parent_pdu.bpki_cms_cert != rpkid_xcert or
      parent_pdu.bpki_https_cert != rpkid_xcert):
    rpkid_query.append(rpki.left_right.parent_elt.make_pdu(
      action = "create" if parent_pdu is None else "set",
      tag = parent_handle,
      self_handle = my_handle,
      parent_handle = parent_handle,
      bsc_handle = bsc_handle,
      repository_handle = repository_handle,
      peer_contact_uri = parent.get("uri"),
      sia_base = parent_sia_base,
      sender_name = my_handle,
      recipient_name = parent_handle,
      bpki_cms_cert = rpkid_xcert,
      bpki_https_cert = rpkid_xcert))

rpkid_query.extend(rpki.left_right.parent_elt.make_pdu(
  action = "destroy", self_handle = my_handle, parent_handle = p) for p in parent_pdus)

for child in tree.getiterator(tag("child")):

  child_handle = child.get("handle")
  child_pdu = child_pdus.pop(child_handle, None)

  if (child_pdu is None or
      child_pdu.bsc_handle != bsc_handle or
      child_pdu.bpki_cert != rpkid_xcert):
    rpkid_query.append(rpki.left_right.child_elt.make_pdu(
      action = "create" if child_pdu is None else "set",
      tag = child_handle,
      self_handle = my_handle,
      child_handle = child_handle,
      bsc_handle = bsc_handle,
      bpki_cert = rpkid_xcert))

rpkid_query.extend(rpki.left_right.child_elt.make_pdu(
  action = "destroy", self_handle = my_handle, child_handle = c) for c in child_pdus)

if rpkid_query:
  rpkid_reply = call_rpkid(rpkid_query)
  bsc_pdus = dict((x.bsc_handle, x) for x in rpkid_reply if isinstance(x, rpki.left_right.bsc_elt))
  if bsc_handle in bsc_pdus and bsc_pdus[bsc_handle].pkcs10_request:
    bsc_req = bsc_pdus[bsc_handle].pkcs10_request

e = tree.find(tag("bpki_bsc_pkcs10"))
if e is None and bsc_req is not None:
  e = lxml.etree.SubElement(tree, "bpki_bsc_pkcs10")
elif bsc_req is None:
  tree.remove(e)

if bsc_req is not None:
  assert e is not None
  e.text = bsc_req.get_Base64()

rng.assertValid(tree)
lxml.etree.ElementTree(tree).write(xmlfile + ".tmp", pretty_print = True)
os.rename(xmlfile + ".tmp", xmlfile)

if False:

  for x in tree.getiterator(tag("child")):
    ta = findbase64(x, "bpki_ta")
    if ta:
      ta.pprint()

  for x in tree.getiterator(tag("parent")):
    print "Parent URI:", x.get("uri")
    ta = findbase64(x, "bpki_ta")
    if ta:
      ta.pprint()

  ca = findbase64(tree, "bpki_ca_certificate")
  if ca:
    ca.pprint()

  bsc = findbase64(tree, "bpki_bsc_certificate")
  if bsc:
    bsc.pprint()

  req = findbase64(tree, "bpki_bsc_pkcs10", rpki.x509.PKCS10)
  if req:
    req.pprint()

  crl = findbase64(tree, "bpki_crl", rpki.x509.CRL)
  if crl:
    crl.pprint()

db.close()
