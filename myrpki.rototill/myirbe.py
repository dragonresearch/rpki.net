"""
IRBE-side stuff for myrpki tools.

The basic model here is that each entity with resources to certify
runs the myrpki tool, but not all of them necessarily run their own
RPKi engines.  The entities that do run RPKI engines get data from the
entities they host via the XML files output by the myrpki tool.  Those
XML files are the input to this script, which uses them to do all the
work of constructing certificates, populating SQL databases, and so
forth.  A few operations (eg, BSC construction) generate data which
has to be shipped back to the resource holder, which we do by updating
the same XML file.

In essence, the XML files are a sneakernet (or email, or carrier
pigeon) communication channel between the resource holders and the
RPKI engine operators.

As a convenience, for the normal case where the RPKI engine operator
is itself a resource holder, this script also runs the myrpki script
directly to process the RPKI engine operator's own resources.

Note that, due to the back and forth nature of some of these
operations, it may take several cycles for data structures to stablize
and everything to reach a steady state.  This is normal.


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

from __future__ import with_statement

import lxml.etree, base64, subprocess, sys, os, time, re, getopt, warnings
import rpki.https, rpki.config, rpki.resource_set, rpki.relaxng
import rpki.exceptions, rpki.left_right, rpki.log, rpki.x509, rpki.async
import myrpki, schema

# Silence warning while loading MySQLdb in Python 2.6, sigh
if hasattr(warnings, "catch_warnings"):
  with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    import MySQLdb
else:
  import MySQLdb

def tag(t):
  """
  Wrap an element name in the right XML namespace goop.
  """
  return "{http://www.hactrn.net/uris/rpki/myrpki/}" + t

def findbase64(tree, name, b64type = rpki.x509.X509):
  """
  Find and extract a base64-encoded XML element, if present.
  """
  x = tree.findtext(tag(name))
  return b64type(Base64 = x) if x else None

# For simple cases we don't really care what these value are, so long
# as we're consistant about them, so wiring them in is fine.

bsc_handle = "bsc"
repository_handle = "repository"

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

    msg = self.proto.msg.query(*pdus)
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

bpki_only = False

opts, argv = getopt.getopt(sys.argv[1:], "bc:h?", ["bpki_only", "config=", "help"])
for o, a in opts:
  if o in ("-b", "--bpki_only"):
    bpki_only = True
  elif o in ("-c", "--config"):
    cfg_file = a
  elif o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)

cfg = rpki.config.parser(cfg_file, "myrpki")

cfg.set_global_flags()

myrpki.openssl = cfg.get("openssl", "openssl", "myrpki")

handle = cfg.get("handle", cfg.get("handle", "Amnesiac", "myrpki"))

want_pubd = cfg.getboolean("want_pubd", False)
want_rootd = cfg.getboolean("want_rootd", False)

bpki_modified = False

bpki = myrpki.CA(cfg_file, cfg.get("myirbe_bpki_directory"))
bpki_modified |= bpki.setup(cfg.get("bpki_ta_dn",       "/CN=%s BPKI TA"  % handle))
bpki_modified |= bpki.ee(   cfg.get("bpki_rpkid_ee_dn", "/CN=%s rpkid EE" % handle), "rpkid")
bpki_modified |= bpki.ee(   cfg.get("bpki_irdbd_ee_dn", "/CN=%s irdbd EE" % handle), "irdbd")
bpki_modified |= bpki.ee(   cfg.get("bpki_irbe_ee_dn",  "/CN=%s irbe EE"  % handle), "irbe")
if want_pubd:
  bpki_modified |= bpki.ee( cfg.get("bpki_pubd_ee_dn",  "/CN=%s pubd EE"  % handle), "pubd")
if want_rootd:
  bpki_modified |= bpki.ee( cfg.get("bpki_rootd_ee_dn", "/CN=%s rootd EE" % handle), "rootd")

if bpki_modified:
  print "BPKI (re)initialized.  You need to (re)start daemons before continuing."

if bpki_modified or bpki_only:
  sys.exit()

# Default values for CRL parameters are very low, for testing.

self_crl_interval = cfg.getint("self_crl_interval", 900)
self_regen_margin = cfg.getint("self_regen_margin", 300)
pubd_base         = cfg.get("pubd_base").rstrip("/") + "/"
rpkid_base        = cfg.get("rpkid_base").rstrip("/") + "/"

# Nasty regexp for parsing rpkid's up-down service URLs.

updown_regexp = re.compile(re.escape(rpkid_base) + "up-down/([-A-Z0-9_]+)/([-A-Z0-9_]+)$", re.I)

# Wrappers to simplify calling rpkid and pubd.

call_rpkid = rpki.async.sync_wrapper(caller(
  proto       = rpki.left_right,
  client_key  = rpki.x509.RSA( PEM_file = bpki.dir + "/irbe.key"),
  client_cert = rpki.x509.X509(PEM_file = bpki.dir + "/irbe.cer"),
  server_ta   = rpki.x509.X509(PEM_file = bpki.cer),
  server_cert = rpki.x509.X509(PEM_file = bpki.dir + "/rpkid.cer"),
  url         = rpkid_base + "left-right"))

if want_pubd:

  call_pubd = rpki.async.sync_wrapper(caller(
    proto       = rpki.publication,
    client_key  = rpki.x509.RSA( PEM_file = bpki.dir + "/irbe.key"),
    client_cert = rpki.x509.X509(PEM_file = bpki.dir + "/irbe.cer"),
    server_ta   = rpki.x509.X509(PEM_file = bpki.cer),
    server_cert = rpki.x509.X509(PEM_file = bpki.dir + "/pubd.cer"),
    url         = pubd_base + "control"))

  # Make sure that pubd's BPKI CRL is up to date.

  call_pubd((rpki.publication.config_elt.make_pdu(
    action = "set",
    bpki_crl = rpki.x509.CRL(PEM_file = bpki.crl)),))

irdbd_cfg = rpki.config.parser(cfg.get("irdbd_conf", cfg_file), "irdbd")

db = MySQLdb.connect(user   = irdbd_cfg.get("sql-username"),
                     db     = irdbd_cfg.get("sql-database"),
                     passwd = irdbd_cfg.get("sql-password"))

cur = db.cursor()

xmlfiles = []

# If [myrpki] section includes an "xml_filename" setting, run
# myrpki.py internally, as a convenience, and include its output at
# the head of our list of XML files to process.

if cfg.has_option("xml_filename"):
  myrpki.main(("-c", cfg_file))
  my_xmlfile = cfg.get("xml_filename")
  xmlfiles.append(my_xmlfile)

# Add any other XML files specified on the command line

xmlfiles.extend(argv)

my_handle = None

for xmlfile in xmlfiles:

  # Parse XML file and validate it against our scheme

  tree = lxml.etree.parse(xmlfile).getroot()
  try:
    schema.myrpki.assertValid(tree)
  except lxml.etree.DocumentInvalid:
    print lxml.etree.tostring(tree, pretty_print = True)
    raise

  handle = tree.get("handle")

  if xmlfile == my_xmlfile:
    my_handle = handle

  # Update IRDB with parsed resource and roa-request data.

  cur.execute(
    """
    DELETE
    FROM  roa_request_prefix
    USING roa_request, roa_request_prefix
    WHERE roa_request.roa_request_id = roa_request_prefix.roa_request_id AND roa_request.roa_request_handle = %s
    """, (handle,))

  cur.execute("DELETE FROM roa_request WHERE roa_request.roa_request_handle = %s", (handle,))

  for x in tree.getiterator(tag("roa_request")):
    cur.execute("INSERT roa_request (roa_request_handle, asn) VALUES (%s, %s)", (handle, x.get("asn")))
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
    """ , (handle,))

  cur.execute(
    """
    DELETE FROM registrant_net USING registrant, registrant_net
    WHERE registrant.registrant_id = registrant_net.registrant_id AND registrant.registry_handle = %s
    """ , (handle,))

  cur.execute("DELETE FROM registrant WHERE registrant.registry_handle = %s" , (handle,))

  for x in tree.getiterator(tag("child")):
    child_handle = x.get("handle")
    asns = rpki.resource_set.resource_set_as(x.get("asns"))
    ipv4 = rpki.resource_set.resource_set_ipv4(x.get("v4"))
    ipv6 = rpki.resource_set.resource_set_ipv6(x.get("v6"))

    cur.execute("INSERT registrant (registrant_handle, registry_handle, registrant_name, valid_until) VALUES (%s, %s, %s, %s)",
                (child_handle, handle, child_handle, rpki.sundial.datetime.fromXMLtime(x.get("valid_until")).to_sql()))
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

  # Check for certificates before attempting anything else

  hosted_cacert = findbase64(tree, "bpki_ca_certificate")
  if not hosted_cacert:
    print "Nothing else I can do without a trust anchor for the entity I'm hosting."
    continue

  rpkid_xcert = rpki.x509.X509(PEM_file = bpki.fxcert(handle + ".cacert.cer",
                                                      hosted_cacert.get_PEM(),
                                                      path_restriction = 1))

  # See what rpkid and pubd already have on file for this entity.

  if want_pubd:
    client_pdus = dict((x.client_handle, x)
                       for x in call_pubd((rpki.publication.client_elt.make_pdu(action = "list"),))
                       if isinstance(x, rpki.publication.client_elt))

  rpkid_reply = call_rpkid((
    rpki.left_right.self_elt.make_pdu(      action = "get",  tag = "self",       self_handle = handle),
    rpki.left_right.bsc_elt.make_pdu(       action = "list", tag = "bsc",        self_handle = handle),
    rpki.left_right.repository_elt.make_pdu(action = "list", tag = "repository", self_handle = handle),
    rpki.left_right.parent_elt.make_pdu(    action = "list", tag = "parent",     self_handle = handle),
    rpki.left_right.child_elt.make_pdu(     action = "list", tag = "child",      self_handle = handle)))

  self_pdu        = rpkid_reply[0]
  bsc_pdus        = dict((x.bsc_handle, x) for x in rpkid_reply if isinstance(x, rpki.left_right.bsc_elt))
  repository_pdus = dict((x.repository_handle, x) for x in rpkid_reply if isinstance(x, rpki.left_right.repository_elt))
  parent_pdus     = dict((x.parent_handle, x) for x in rpkid_reply if isinstance(x, rpki.left_right.parent_elt))
  child_pdus      = dict((x.child_handle, x) for x in rpkid_reply if isinstance(x, rpki.left_right.child_elt))

  pubd_query = []
  rpkid_query = []

  # There should be exactly one <self/> object per hosted entity, by definition

  if (isinstance(self_pdu, rpki.left_right.report_error_elt) or
      self_pdu.crl_interval != self_crl_interval or
      self_pdu.regen_margin != self_regen_margin or
      self_pdu.bpki_cert != rpkid_xcert):
    rpkid_query.append(rpki.left_right.self_elt.make_pdu(
      action = "create" if isinstance(self_pdu, rpki.left_right.report_error_elt) else "set",
      tag = "self",
      self_handle = handle,
      bpki_cert = rpkid_xcert,
      crl_interval = self_crl_interval,
      regen_margin = self_regen_margin))

  # In general we only need one <bsc/> per <self/>.  BSC objects are a
  # little unusual in that the PKCS #10 subelement is generated by rpkid
  # in response to generate_keypair, so there's more of a separation
  # between create and set than with other objects.

  bsc_cert = findbase64(tree, "bpki_bsc_certificate")
  bsc_crl  = findbase64(tree, "bpki_crl", rpki.x509.CRL)

  bsc_pdu = bsc_pdus.pop(bsc_handle, None)

  if bsc_pdu is None:
    rpkid_query.append(rpki.left_right.bsc_elt.make_pdu(
      action = "create",
      tag = "bsc",
      self_handle = handle,
      bsc_handle = bsc_handle,
      generate_keypair = "yes"))
  elif bsc_pdu.signing_cert != bsc_cert or bsc_pdu.signing_cert_crl != bsc_crl:
    rpkid_query.append(rpki.left_right.bsc_elt.make_pdu(
      action = "set",
      tag = "bsc",
      self_handle = handle,
      bsc_handle = bsc_handle,
      signing_cert = bsc_cert,
      signing_cert_crl = bsc_crl))

  rpkid_query.extend(rpki.left_right.bsc_elt.make_pdu(
    action = "destroy", self_handle = handle, bsc_handle = b) for b in bsc_pdus)

  bsc_req = None

  if bsc_pdu and bsc_pdu.pkcs10_request:
    bsc_req = bsc_pdu.pkcs10_request

  # In general we need one <repository/> per publication daemon with
  # whom this <self/> has a relationship.  In practice there is rarely
  # (never?) a good reason for a single <self/> to use multiple
  # publication services, so in normal use we only need one
  # <repository/> object.  If for some reason you really need more
  # than this, you'll have to hack.

  repository_cert = findbase64(tree, "bpki_repository_certificate")
  if repository_cert:

    repository_pdu = repository_pdus.pop(repository_handle, None)
    repository_uri = pubd_base + "client/" + tree.get("repository_handle")

    if (repository_pdu is None or
        repository_pdu.bsc_handle != bsc_handle or
        repository_pdu.peer_contact_uri != repository_uri or
        repository_pdu.bpki_cert != repository_cert):
      rpkid_query.append(rpki.left_right.repository_elt.make_pdu(
        action = "create" if repository_pdu is None else "set",
        tag = repository_handle,
        self_handle = handle,
        repository_handle = repository_handle,
        bsc_handle = bsc_handle,
        peer_contact_uri = repository_uri,
        bpki_cert = repository_cert))

  rpkid_query.extend(rpki.left_right.repository_elt.make_pdu(
    action = "destroy", self_handle = handle, repository_handle = r) for r in repository_pdus)

  # <parent/> setup code here used to be ridiculously complex.  Most
  # of the insanity was due to a misguided attempt to deduce pubd
  # setup from other data; now that pubd setup is driven by
  # pubclients.csv, parent setup should be relatively straightforward,
  # but beware of lingering excessive cleverness in anything dealing
  # with parent objects in this script.

  for parent in tree.getiterator(tag("parent")):

    parent_handle = parent.get("handle")
    parent_pdu = parent_pdus.pop(parent_handle, None)
    parent_uri = parent.get("service_uri")
    parent_myhandle = parent.get("myhandle")
    parent_sia_base = parent.get("sia_base")
    parent_cms_cert = findbase64(parent, "bpki_cms_certificate")
    parent_https_cert = findbase64(parent, "bpki_https_certificate")

    if (parent_pdu is None or
        parent_pdu.bsc_handle != bsc_handle or
        parent_pdu.repository_handle != repository_handle or
        parent_pdu.peer_contact_uri != parent_uri or
        parent_pdu.sia_base != parent_sia_base or
        parent_pdu.sender_name != parent_myhandle or
        parent_pdu.recipient_name != parent_handle or
        parent_pdu.bpki_cms_cert != parent_cms_cert or
        parent_pdu.bpki_https_cert != parent_https_cert):
      rpkid_query.append(rpki.left_right.parent_elt.make_pdu(
        action = "create" if parent_pdu is None else "set",
        tag = parent_handle,
        self_handle = handle,
        parent_handle = parent_handle,
        bsc_handle = bsc_handle,
        repository_handle = repository_handle,
        peer_contact_uri = parent_uri,
        sia_base = parent_sia_base,
        sender_name = parent_myhandle,
        recipient_name = parent_handle,
        bpki_cms_cert = parent_cms_cert,
        bpki_https_cert = parent_https_cert))

  rpkid_query.extend(rpki.left_right.parent_elt.make_pdu(
    action = "destroy", self_handle = handle, parent_handle = p) for p in parent_pdus)

  # Children are simpler than parents, because they call us, so no URL
  # to construct and figuring out what certificate to use is their
  # problem, not ours.

  for child in tree.getiterator(tag("child")):

    child_handle = child.get("handle")
    child_pdu = child_pdus.pop(child_handle, None)
    child_cert = findbase64(child, "bpki_certificate")

    if (child_pdu is None or
        child_pdu.bsc_handle != bsc_handle or
        child_pdu.bpki_cert != child_cert):
      rpkid_query.append(rpki.left_right.child_elt.make_pdu(
        action = "create" if child_pdu is None else "set",
        tag = child_handle,
        self_handle = handle,
        child_handle = child_handle,
        bsc_handle = bsc_handle,
        bpki_cert = child_cert))

  rpkid_query.extend(rpki.left_right.child_elt.make_pdu(
    action = "destroy", self_handle = handle, child_handle = c) for c in child_pdus)

  # Publication setup, used to be inferred (badly) from parent setup,
  # now handled explictly via yet another freaking .csv file.

  if want_pubd:

    for client_handle, client_bpki_cert, client_base_uri in myrpki.csv_open(cfg.get("pubclients_csv", "pubclients.csv")):

      if os.path.exists(client_bpki_cert):

        client_pdu = client_pdus.pop(client_handle, None)

        client_bpki_cert = rpki.x509.X509(PEM_file = bpki.xcert(client_bpki_cert))

        if (client_pdu is None or
            client_pdu.base_uri != client_base_uri or
            client_pdu.bpki_cert != client_bpki_cert):
          pubd_query.append(rpki.publication.client_elt.make_pdu(
            action = "create" if client_pdu is None else "set",
            client_handle = client_handle,
            bpki_cert = client_bpki_cert,
            base_uri = client_base_uri))

    pubd_query.extend(rpki.publication.client_elt.make_pdu(
        action = "destroy", client_handle = p) for p in client_pdus)

  # If we changed anything, ship updates off to daemons

  if rpkid_query:
    rpkid_reply = call_rpkid(rpkid_query)
    bsc_pdus = dict((x.bsc_handle, x) for x in rpkid_reply if isinstance(x, rpki.left_right.bsc_elt))
    if bsc_handle in bsc_pdus and bsc_pdus[bsc_handle].pkcs10_request:
      bsc_req = bsc_pdus[bsc_handle].pkcs10_request
    for r in rpkid_reply:
      assert not isinstance(r, rpki.left_right.report_error_elt)

  if pubd_query:
    assert want_pubd
    pubd_reply = call_pubd(pubd_query)
    for r in pubd_reply:
      assert not isinstance(r, rpki.publication.report_error_elt)

  # Rewrite XML.

  e = tree.find(tag("bpki_bsc_pkcs10"))
  if e is None and bsc_req is not None:
    e = lxml.etree.SubElement(tree, "bpki_bsc_pkcs10")
  elif bsc_req is None:
    tree.remove(e)

  if bsc_req is not None:
    assert e is not None
    e.text = bsc_req.get_Base64()

  # Something weird going on here with lxml linked against recent
  # versions of libxml2.  Looks like modifying the tree above somehow
  # produces validation errors, but it works fine if we convert it to
  # a string and parse it again.  I'm not seeing any problems with any
  # of the other code that uses lxml to do validation, just this one
  # place.  Weird.  Kludge around it for now.

  tree = lxml.etree.fromstring(lxml.etree.tostring(tree))

  try:
    schema.myrpki.assertValid(tree)
  except lxml.etree.DocumentInvalid:
    print lxml.etree.tostring(tree, pretty_print = True)
    raise

  lxml.etree.ElementTree(tree).write(xmlfile + ".tmp", pretty_print = True)
  os.rename(xmlfile + ".tmp", xmlfile)

db.close()
