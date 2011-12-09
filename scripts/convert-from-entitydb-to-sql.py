"""
Merge XML entitydb and OpenSSL command-line BPKI into SQL IRDB.

This is a work in progress, don't use it unless you really know what
you're doing.

$Id$

Copyright (C) 2011  Internet Systems Consortium ("ISC")

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

import sys, os, time, getopt, glob, subprocess
import rpki.config, rpki.x509, rpki.relaxng
from rpki.mysql_import import MySQLdb
from lxml.etree import ElementTree

if os.getlogin() != "sra":
  sys.exit("I //said// this was a work in progress")

cfg_file = "rpki.conf"
entitydb = "entitydb"
bpki     = "bpki"

opts, argv = getopt.getopt(sys.argv[1:], "c:h?", ["config=", "help"])
for o, a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  if o in ("-c", "--config"):
    cfg_file = a
if argv:
  sys.exit("Unexpected arguments %s" % argv)

cfg = rpki.config.parser(cfg_file)

sql_database = cfg.get("sql-database", section = "irdbd")
sql_username = cfg.get("sql-username", section = "irdbd")
sql_password = cfg.get("sql-password", section = "irdbd")

# Rename the old SQL tables, if they exist

db = MySQLdb.connect(user = sql_username, db = sql_database, passwd = sql_password)
cur = db.cursor()

cur.execute("SHOW TABLES")

tables = [r[0] for r in cur.fetchall()]

for table in tables:
  if "old_" + table not in tables and table in ("registrant",
                                                "registrant_asn",
                                                "registrant_net",
                                                "roa_request",
                                                "roa_request_prefix",
                                                "ghostbuster_request"):
    print "Renaming %s to old_%s" % (table, table)
    cur.execute("ALTER TABLE %s RENAME TO old_%s" % (table, table))

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

e = ElementTree(file = os.path.join(entitydb, "identity.xml")).getroot()
rpki.relaxng.myrpki.assertValid(e)
assert e.tag == tag_identity

handle = e.get("handle")
assert handle == cfg.get("handle", section = "myrpki")

# Create identity if we haven't already

identity = rpki.irdb.Identity.objects.get_or_create(handle = handle)[0]

# Some BPKI utillity routines

def read_openssl_serial(filename):
  f = open(filename, "r")
  text = f.read()
  f.close()
  return int(text.strip(), 16)

def get_or_create_CA(purpose):
  cer = rpki.x509.X509(Auto_file = os.path.join(bpki, purpose, "ca.cer"))
  key = rpki.x509.RSA(Auto_file  = os.path.join(bpki, purpose, "ca.key"))
  crl = rpki.x509.CRL(Auto_file  = os.path.join(bpki, purpose, "ca.crl"))
  serial     = read_openssl_serial(os.path.join(bpki, purpose, "serial"))
  crl_number = read_openssl_serial(os.path.join(bpki, purpose, "crl_number"))

  return rpki.irdb.CA.objects.get_or_create(identity = identity,
                                            purpose = rpki.irdb.CA.purpose_map[purpose],
                                            certificate = cer.get_DER(),
                                            private_key = key.get_DER(),
                                            next_serial = serial,
                                            next_crl_number = crl_number,
                                            last_crl_update = crl.getThisUpdate().to_sql(),
                                            next_crl_update = crl.getNextUpdate().to_sql())[0]

def get_or_create_EECertificate(issuer, purpose):
  cer = rpki.x509.X509(Auto_file = os.path.join(bpki, "servers", purpose + ".cer"))
  key = rpki.x509.RSA(Auto_file  = os.path.join(bpki, "servers", purpose + ".key"))
  rpki.irdb.EECertificate.objects.get_or_create(
    issuer      = issuer,
    purpose     = rpki.irdb.EECertificate.purpose_map[purpose],
    certificate = cer.get_DER(),
    private_key = key.get_DER())

# Load BPKI CA data

resource_ca = get_or_create_CA("resources")

# Load BPKI server EE certificates and keys

run_flags = dict((i, cfg.getboolean(i, section = "myrpki"))
                 for i in ("run_rpkid", "run_pubd", "run_rootd"))

if any(run_flags.itervalues()):
  server_ca = get_or_create_CA("servers")
  get_or_create_EECertificate(server_ca, "irbe")
  if run_flags["run_rpkid"]:
    get_or_create_EECertificate(server_ca, "rpkid")
    get_or_create_EECertificate(server_ca, "irdbd")
  if run_flags["run_pubd"]:
    get_or_create_EECertificate(server_ca, "pubd")
  if run_flags["run_rootd"]:
    get_or_create_EECertificate(server_ca, "rootd")
else:
  server_ca = None

# Load BSC certificates and requests

for fn in glob.iglob(os.path.join(bpki, "resources", "bsc.*.cer")):
  cer = rpki.x509.X509(Auto_file = fn)
  req = rpki.x509.X509(Auto_file = fn[:-4] + ".req")
  rpki.irdb.BSC.objects.get_or_create(
    issuer      = resource_ca,
    certificate = cer.get_DER(),
    pkcs10      = req.get_DER())


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

# Build a table of all the cross-certified BPKI certificates.

xcerts = {}

for filename in glob.iglob(os.path.join("bpki", "*", "xcert.*.cer")):
  h = filename.split(".")[-2]

  if not h in xcerts:
    xcerts[h] = []
  xcerts[h].append(filename)

  # While we're at this, check to make sure that our reproduction of
  # the hash algorithm is working correctly.
  #
  assert xcert_hash(rpki.x509.X509(Auto_file = filename)) == h



# Somewhere around here I'm going to run out of things to do other
# than scraping through the horrible entitydb XML.  Bother.


# Copy over any ROA requests

cur.execute("""
            SELECT roa_request_id, asn FROM old_roa_request
            WHERE roa_request_handle = %s
            """, (handle,))
for roa_request_id, asn in cur.fetchall():
  roa_request = rpki.irdb.ROARequest.objects.get_or_create(identity = identity, asn = asn)[0]
  cur.execute("""
              SELECT prefix, prefixlen, max_prefixlen, version FROM old_roa_request_prefix
              WHERE roa_request_id = %s
              """, (roa_request_id,))
  for prefix, prefixlen, max_prefixlen, version in cur.fetchall():
    rpki.irdb.ROARequestPrefix.objects.get_or_create(
      roa_request = roa_request,
      version = version,
      prefix = prefix,
      prefixlen = prefixlen,
      max_prefixlen = max_prefixlen)

# Copy over any Ghostbuster requests.  This doesn't handle
# Ghostbusters bound to specific parents yet, because I haven't yet
# written the code to copy parent objects from entitydb.

cur.execute("""
            SELECT vcard FROM old_ghostbuster_request
            WHERE self_handle = %s AND parent_handle IS NULL
            """, (handle,))
for row in cur.fetchall():
  rpki.irdb.GhostbusterRequest.objects.get_or_create(identity = identity, parent = None,
                                                     vcard = row[0])

cur.close()
db.close()
