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
import rpki.exceptions, rpki.left_right, rpki.log, rpki.x509
import myrpki

rng = lxml.etree.RelaxNG(lxml.etree.parse("myrpki.rng"))

def tag(t):
  return "{http://www.hactrn.net/uris/rpki/myrpki/}" + t

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
  print "BPKI initialized.  You need to start daemons before continuing."
  sys.exit()

if cfg.has_section("myrpki"):
  myrpki.main()

# This probably ought to come from the command line
tree = lxml.etree.parse("myrpki.xml").getroot()
rng.assertValid(tree)

irdbd_cfg = rpki.config.parser(cfg.get("irdbd_conf"), "irdbd")

db = MySQLdb.connect(user   = irdbd_cfg.get("sql-username"),
                     db     = irdbd_cfg.get("sql-database"),
                     passwd = irdbd_cfg.get("sql-password"))

cur = db.cursor()

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
db.close()

hosted_cacert = tree.findtext(tag("bpki_ca_certificate"))
if hosted_cacert:
  p = subprocess.Popen(("openssl", "x509", "-inform", "DER"), stdin = subprocess.PIPE, stdout = subprocess.PIPE)
  hosted_cacert = p.communicate(base64.b64decode(hosted_cacert))[0]
  if p.wait() != 0:
    raise RuntimeError, "Couldn't convert certificate to PEM format"


if hosted_cacert:
  bpki_rpkid.fxcert(my_handle + ".cacert.cer", hosted_cacert, restrict_pathlen = False)

if hosted_cacert:
  bpki_pubd.fxcert(my_handle + ".cacert.cer", hosted_cacert)

rpkid_pdus = [
  rpki.left_right.self_elt.make_pdu(      action = "get",  self_handle = my_handle),
  rpki.left_right.bsc_elt.make_pdu(       action = "list", self_handle = my_handle),
  rpki.left_right.parent_elt.make_pdu(    action = "list", self_handle = my_handle),
  rpki.left_right.child_elt.make_pdu(     action = "list", self_handle = my_handle),
  rpki.left_right.repository_elt.make_pdu(action = "list", self_handle = my_handle) ]

pubd_pdus = [
  rpki.publication.client_elt.make_pdu(   action = "get", client_handle = my_handle) ]

def showcerts():

  def showpem(label, b64, kind):
    cmd = ("openssl", kind, "-noout", "-text", "-inform", "DER")
    p = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE)
    text = p.communicate(input = base64.b64decode(b64))[0]
    if p.returncode != 0:
      raise subprocess.CalledProcessError(returncode = p.returncode, cmd = cmd)
    print label, text

  for x in tree.getiterator(tag("child")):
    ta = x.findtext(tag("bpki_ta"))
    if ta:
      showpem("Child", ta, "x509")

  for x in tree.getiterator(tag("parent")):
    print "Parent URI:", x.get("uri")
    ta = x.findtext(tag("bpki_ta"))
    if ta:
      showpem("Parent", ta, "x509")

  ca = tree.findtext(tag("bpki_ca_certificate"))
  if ca:
    showpem("CA", ca, "x509")

  bsc = tree.findtext(tag("bpki_bsc_certificate"))
  if bsc:
    showpem("BSC EE", bsc, "x509")

  req = tree.findtext(tag("bpki_bsc_pkcs10"))
  if req:
    showpem("BSC EE", req, "req")

  crl = tree.findtext(tag("bpki_crl"))
  if crl:
    showpem("CA", crl, "crl")

#showcerts()
