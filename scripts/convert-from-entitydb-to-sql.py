"""
Merge XML entitydb and OpenSSL command-line BPKI into SQL IRDB.

This is a work in progress, don't use it unless you really know what
you're doing.

$Id$

Copyright (C) 2011-2012  Internet Systems Consortium ("ISC")

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

import sys, os, time, getopt, glob, subprocess, base64
import rpki.config, rpki.x509, rpki.relaxng, rpki.sundial
from rpki.mysql_import import MySQLdb
from lxml.etree import ElementTree

cfg_file        = "rpki.conf"
entitydb        = "entitydb"
bpki            = "bpki"
copy_csv_data   = True
force           = False

opts, argv = getopt.getopt(sys.argv[1:], "c:fh?", ["config=", "force", "help"])
for o, a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  if o in ("-c", "--config"):
    cfg_file = a
  elif o in ("-f", "--force"):
    force = True
if argv:
  sys.exit("Unexpected arguments %s" % argv)

if not force:
  print """
        WARNING WARNING WARNING

        This script attempts to upgrade an existing rpkid instance to
        work with the newer SQL-based back end code.  It has worked in
        the handful of cases where we've tested it, but it's dangerous
        and relies heavily on guesses about how your existing instance
        was originally set up.  It may not work right.  It may not
        work at all.  It may turn your cat blue.

        Please back up all your data (MySQL databases, bpki/ and
        entitydb/ directories) and configuration (rpki.conf file) before
        running this script.
        """
  while True:
    answer = raw_input("Are you SURE you want to proceed? (yes/NO) ").strip().lower()
    if answer in ("", "n", "no"):
      sys.exit("You have chosen wisely")
    elif answer in ("y", "yes"):
      print "You have been warned"
      break
    else:
      print 'Please answer "yes" or "no"'

cfg = rpki.config.parser(cfg_file)

sql_database = cfg.get("sql-database", section = "irdbd")
sql_username = cfg.get("sql-username", section = "irdbd")
sql_password = cfg.get("sql-password", section = "irdbd")

db = MySQLdb.connect(user = sql_username, db = sql_database, passwd = sql_password)
cur = db.cursor()

# Configure the Django model system

from django.conf import settings

settings.configure(
  DATABASES = { "default" : {
    "ENGINE"   : "django.db.backends.mysql",
    "NAME"     : sql_database,
    "USER"     : sql_username,
    "PASSWORD" : sql_password,
    "HOST"     : "",
    "PORT"     : "",
    "OPTIONS"  : { "init_command": "SET storage_engine=INNODB" }}},
  INSTALLED_APPS = ("rpki.irdb",),
)

import rpki.irdb

# Create the model-based tables if they don't already exist

import django.core.management

django.core.management.call_command("syncdb", verbosity = 4, load_initial_data = False)

# From here down will be an awful lot of messing about with XML and
# X.509 data, extracting stuff from the old SQL database and whacking
# it into the new.  Still working out these bits.

xmlns = "{http://www.hactrn.net/uris/rpki/myrpki/}"

tag_authorization    = xmlns + "authorization"
tag_bpki_child_ta    = xmlns + "bpki_child_ta"
tag_bpki_client_ta   = xmlns + "bpki_client_ta"
tag_bpki_resource_ta = xmlns + "bpki_resource_ta"
tag_bpki_server_ta   = xmlns + "bpki_server_ta"
tag_bpki_ta          = xmlns + "bpki_ta"
tag_contact_info     = xmlns + "contact_info"
tag_identity         = xmlns + "identity"
tag_parent           = xmlns + "parent"
tag_repository       = xmlns + "repository"

def read_element_tree(filename, tag):
  print "Reading file %s, tag %s" % (filename, tag)
  e = ElementTree(file = filename).getroot()
  rpki.relaxng.myrpki.assertValid(e)
  assert e.tag == tag
  return e

e = read_element_tree(os.path.join(entitydb, "identity.xml"), tag_identity)

self_handle = e.get("handle")
assert self_handle == cfg.get("handle", section = "myrpki")

# Some BPKI utillity routines

def read_openssl_serial(filename):
  f = open(filename, "r")
  text = f.read()
  f.close()
  return int(text.strip(), 16)

def get_or_create_ServerEE(issuer, purpose):
  cer = rpki.x509.X509(Auto_file = os.path.join(bpki, "servers", purpose + ".cer"))
  key = rpki.x509.RSA(Auto_file  = os.path.join(bpki, "servers", purpose + ".key"))
  rpki.irdb.ServerEE.objects.get_or_create(
    issuer      = issuer,
    purpose     = purpose,
    certificate = cer,
    private_key = key)

# Load BPKI CAs and directly certified EEs

cer = rpki.x509.X509(Auto_file = os.path.join(bpki, "resources", "ca.cer"))
key = rpki.x509.RSA(Auto_file  = os.path.join(bpki, "resources", "ca.key"))
crl = rpki.x509.CRL(Auto_file  = os.path.join(bpki, "resources", "ca.crl"))
serial     = read_openssl_serial(os.path.join(bpki, "resources", "serial"))
crl_number = read_openssl_serial(os.path.join(bpki, "resources", "crl_number"))

resource_ca = rpki.irdb.ResourceHolderCA.objects.get_or_create(
  handle = self_handle,
  certificate = cer,
  private_key = key,
  latest_crl = crl,
  next_serial = serial,
  next_crl_number = crl_number,
  last_crl_update = crl.getThisUpdate().to_sql(),
  next_crl_update = crl.getNextUpdate().to_sql())[0]

if os.path.exists(os.path.join(bpki, "resources", "referral.cer")):
  cer = rpki.x509.X509(Auto_file = os.path.join(bpki, "resources", "referral.cer"))
  key = rpki.x509.RSA(Auto_file  = os.path.join(bpki, "resources", "referral.key"))
  rpki.irdb.Referral.objects.get_or_create(
    issuer      = resource_ca,
    certificate = cer,
    private_key = key)

run_rpkid = cfg.getboolean("run_rpkid", section = "myrpki")
run_pubd  = cfg.getboolean("run_pubd",  section = "myrpki")
run_rootd = cfg.getboolean("run_rootd", section = "myrpki")

if run_rpkid or run_pubd:
  cer = rpki.x509.X509(Auto_file = os.path.join(bpki, "servers", "ca.cer"))
  key = rpki.x509.RSA(Auto_file  = os.path.join(bpki, "servers", "ca.key"))
  crl = rpki.x509.CRL(Auto_file  = os.path.join(bpki, "servers", "ca.crl"))
  serial     = read_openssl_serial(os.path.join(bpki, "servers", "serial"))
  crl_number = read_openssl_serial(os.path.join(bpki, "servers", "crl_number"))
  server_ca = rpki.irdb.ServerCA.objects.get_or_create(
    certificate = cer,
    private_key = key,
    latest_crl = crl,
    next_serial = serial,
    next_crl_number = crl_number,
    last_crl_update = crl.getThisUpdate().to_sql(),
    next_crl_update = crl.getNextUpdate().to_sql())[0]
  get_or_create_ServerEE(server_ca, "irbe")

else:
  server_ca = None

if run_rpkid:
  get_or_create_ServerEE(server_ca, "rpkid")
  get_or_create_ServerEE(server_ca, "irdbd")

if run_pubd:
  get_or_create_ServerEE(server_ca, "pubd")

# Certification model  for rootd  has changed.  We  can reuse  the old
# key, but we have to  recertify under a different CA than previously.
# Yes, we're pulling  a key from the servers  BPKI tree and certifying
# it under the resource holder CA, that's part of the change.

if run_rootd:
  rpki.irdb.Rootd.objects.get_or_certify(
    issuer = resource_ca,
    service_uri = "http://localhost:%s/" % cfg.get("rootd_server_port", section = "myrpki"),
    private_key = rpki.x509.RSA(Auto_file = os.path.join(bpki, "servers", "rootd.key")))

# Load BSC certificates and requests.  Yes, this currently wires in
# exactly one BSC handle, "bsc".  So does the old myrpki code.  Ick.

for fn in glob.iglob(os.path.join(bpki, "resources", "bsc.*.cer")):
  rpki.irdb.BSC.objects.get_or_create(
    issuer      = resource_ca,
    handle      = "bsc",
    certificate = rpki.x509.X509(Auto_file = fn),
    pkcs10      = rpki.x509.PKCS10(Auto_file = fn[:-4] + ".req"))

def xcert_hash(cert):
  """
  Generate the filename hash that myrpki would have generated for a
  cross-certification.  This is nasty, don't look.
  """

  cmd1 = ("openssl", "x509", "-noout", "-pubkey", "-subject")
  cmd2 = ("openssl", "dgst", "-md5")

  env = { "PATH" : os.environ["PATH"], "OPENSSL_CONF" : "/dev/null" }
  p1 = subprocess.Popen(cmd1, env = env, stdin = subprocess.PIPE, stdout = subprocess.PIPE)
  p2 = subprocess.Popen(cmd2, env = env, stdin = p1.stdout, stdout = subprocess.PIPE)
  p1.stdin.write(cert.get_PEM())
  p1.stdin.close()
  hash = p2.stdout.read()
  if p1.wait() != 0:
    raise subprocess.CalledProcessError(returncode = p1.returncode, cmd = cmd1)
  if p2.wait() != 0:
    raise subprocess.CalledProcessError(returncode = p2.returncode, cmd = cmd2)

  hash = "".join(hash.split())
  if hash.startswith("(stdin)="):
    hash =  hash[len("(stdin)="):]
  return hash

# Let's try keeping track of all the xcert filenames we use, so we can
# list the ones we didn't.

xcert_filenames = set(glob.iglob(os.path.join(bpki, "*", "xcert.*.cer")))

# Scrape child data out of the entitydb.

for filename in glob.iglob(os.path.join(entitydb, "children", "*.xml")):
  child_handle = os.path.splitext(os.path.split(filename)[1])[0]

  e = read_element_tree(filename, tag_parent)

  ta = rpki.x509.X509(Base64 = e.findtext(tag_bpki_child_ta))
  xcfn = os.path.join(bpki, "resources", "xcert.%s.cer" % xcert_hash(ta))
  xcert_filenames.discard(xcfn)
  xcert = rpki.x509.X509(Auto_file = xcfn)

  cur.execute("""
              SELECT registrant_id, valid_until FROM registrant
              WHERE registry_handle = %s AND registrant_handle = %s
              """, (self_handle, child_handle))
  assert cur.rowcount == 1
  registrant_id, valid_until = cur.fetchone()

  valid_until = rpki.sundial.datetime.fromdatetime(valid_until)
  if valid_until != rpki.sundial.datetime.fromXMLtime(e.get("valid_until")):
    print "WARNING: valid_until dates in XML and SQL do not match for child", child_handle
    print "    SQL:", str(valid_until)
    print "    XML:", str(rpki.sundial.datetime.fromXMLtime(e.get("valid_until")))
    print "Blundering onwards"

  child = rpki.irdb.Child.objects.get_or_create(
    handle = child_handle,
    valid_until = valid_until.to_sql(),
    ta = ta,
    certificate = xcert,
    issuer = resource_ca)[0]

  if copy_csv_data:

    cur.execute("""
                SELECT start_as, end_as FROM registrant_asn WHERE registrant_id = %s
                """, (registrant_id,))
    for start_as, end_as in cur.fetchall():
      rpki.irdb.ChildASN.objects.get_or_create(
        start_as = start_as,
        end_as = end_as,
        child = child)

    cur.execute("""
                SELECT start_ip, end_ip, version FROM registrant_net WHERE registrant_id = %s
                """, (registrant_id,))
    for start_ip, end_ip, version in cur.fetchall():
      rpki.irdb.ChildNet.objects.get_or_create(
        start_ip = start_ip,
        end_ip = end_ip,
        version = version,
        child = child)

# Scrape parent data out of the entitydb.

for filename in glob.iglob(os.path.join(entitydb, "parents", "*.xml")):
  parent_handle = os.path.splitext(os.path.split(filename)[1])[0]

  e = read_element_tree(filename, tag_parent)

  if parent_handle == self_handle:
    assert run_rootd
    assert e.get("service_uri") == "http://localhost:%s/" % cfg.get("rootd_server_port", section = "myrpki")
    continue

  ta = rpki.x509.X509(Base64 = e.findtext(tag_bpki_resource_ta))
  xcfn = os.path.join(bpki, "resources", "xcert.%s.cer" % xcert_hash(ta))
  xcert_filenames.discard(xcfn)
  xcert = rpki.x509.X509(Auto_file = xcfn)

  r = e.find(tag_repository)
  repository_type = r.get("type")
  if repository_type == "referral":
    a = r.find(tag_authorization)
    referrer = a.get("referrer")
    referral_authorization = base64.b64decode(a.text)
  else:
    referrer = None
    referral_authorization = None    

  parent = rpki.irdb.Parent.objects.get_or_create(
    handle = parent_handle,
    parent_handle = e.get("parent_handle"),
    child_handle = e.get("child_handle"),
    ta = ta,
    certificate = xcert,
    service_uri = e.get("service_uri"),
    repository_type = repository_type,
    referrer = referrer,
    referral_authorization = referral_authorization,
    issuer = resource_ca)[0]

  # While we have the parent object in hand, load any Ghostbuster
  # entries specific to this parent.

  if copy_csv_data:
    cur.execute("""
                SELECT vcard FROM ghostbuster_request
                WHERE self_handle = %s AND parent_handle = %s
                """, (self_handle, parent_handle))
    for row in cur.fetchall():
      rpki.irdb.GhostbusterRequest.objects.get_or_create(
        issuer = resource_ca,
        parent = parent,
        vcard = row[0])

# Scrape repository data out of the entitydb.

for filename in glob.iglob(os.path.join(entitydb, "repositories", "*.xml")):
  repository_handle = os.path.splitext(os.path.split(filename)[1])[0]

  e = read_element_tree(filename, tag_repository)

  if e.get("type") != "confirmed":
    continue

  ta = rpki.x509.X509(Base64 = e.findtext(tag_bpki_server_ta))
  xcfn = os.path.join(bpki, "resources", "xcert.%s.cer" % xcert_hash(ta))
  xcert_filenames.discard(xcfn)
  xcert = rpki.x509.X509(Auto_file = xcfn)

  parent_handle = e.get("parent_handle")
  if parent_handle == self_handle:
    turtle = resource_ca.rootd
  else:
    turtle = rpki.irdb.Parent.objects.get(handle = parent_handle, issuer = resource_ca)

  rpki.irdb.Repository.objects.get_or_create(
    handle = repository_handle,
    client_handle = e.get("client_handle"),
    ta = ta,
    certificate = xcert,
    service_uri = e.get("service_uri"),
    sia_base = e.get("sia_base"),
    turtle = turtle,
    issuer = resource_ca)

# Scrape client data out of the entitydb.

for filename in glob.iglob(os.path.join(entitydb, "pubclients", "*.xml")):
  client_handle = os.path.splitext(os.path.split(filename)[1])[0].replace(".", "/")

  e = read_element_tree(filename, tag_repository)

  assert e.get("type") == "confirmed"

  ta = rpki.x509.X509(Base64 = e.findtext(tag_bpki_client_ta))
  xcfn = os.path.join(bpki, "servers", "xcert.%s.cer" % xcert_hash(ta))
  xcert_filenames.discard(xcfn)
  xcert = rpki.x509.X509(Auto_file = xcfn)

  rpki.irdb.Client.objects.get_or_create(
    handle = client_handle,
    ta = ta,
    certificate = xcert,
    issuer = server_ca,
    sia_base = e.get("sia_base"))

if copy_csv_data:

  # Copy over any ROA requests

  cur.execute("""
              SELECT roa_request_id, asn FROM roa_request
              WHERE roa_request_handle = %s
              """, (self_handle,))
  for roa_request_id, asn in cur.fetchall():
    roa_request = rpki.irdb.ROARequest.objects.get_or_create(issuer = resource_ca, asn = asn)[0]
    cur.execute("""
                SELECT prefix, prefixlen, max_prefixlen, version FROM roa_request_prefix
                WHERE roa_request_id = %s
                """, (roa_request_id,))
    for prefix, prefixlen, max_prefixlen, version in cur.fetchall():
      rpki.irdb.ROARequestPrefix.objects.get_or_create(
        roa_request = roa_request,
        version = version,
        prefix = prefix,
        prefixlen = prefixlen,
        max_prefixlen = max_prefixlen)

  # Copy over any non-parent-specific Ghostbuster requests.

  cur.execute("""
              SELECT vcard FROM ghostbuster_request
              WHERE self_handle = %s AND parent_handle IS NULL
              """, (self_handle,))
  for row in cur.fetchall():
    rpki.irdb.GhostbusterRequest.objects.get_or_create(
      issuer = resource_ca,
      parent = None,
      vcard = row[0])

# List cross certifications we didn't use.

if False:
  for filename in sorted(xcert_filenames):
    cer = rpki.x509.X509(Auto_file = filename)
    #print "Unused cross-certificate:", filename, cer.getSubject()
    print "Unused cross-certificate:", filename, cer.get_POW().pprint()

# Done!

cur.close()
db.close()
