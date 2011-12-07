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

import sys, os, time, getopt
import rpki.config
from rpki.mysql_import import MySQLdb
from lxml.etree import ElementTree

if os.getlogin() != "sra":
  sys.exit("I //said// this was a work in progress")

cfg_file = "rpki.conf"
entitydb = "entitydb"

opts, argv = getopt.getopt(sys.argv[1:], "c:e:h?", ["config=", "entitydb=", "help"])
for o, a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  if o in ("-c", "--config"):
    cfg_file = a
  elif o in ("-e", "--entitydb"):
    entitydb = a
if argv:
  sys.exit("Unexpected arguments %s" % argv)

cfg = rpki.config.parser(cfg_file, "irdbd")

sql_database = cfg.get("sql-database")
sql_username = cfg.get("sql-username")
sql_password = cfg.get("sql-password")

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
    "PORT"     : "" }},
  INSTALLED_APPS = ("rpki.irdb",),
)

import rpki.irdb

# Create the model-based tables if they don't already exist

import django.core.management

django.core.management.call_command("syncdb", verbosity = 4, load_initial_data = False)

# From here down will be an awful lot of messing about with XML and
# X.509 data, extracting stuff from the old database and whacking it
# into the new.  Still working out these bits.

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
assert e.tag == tag_identity

handle = e.get("handle")

# Check handle against what's in rpki.conf?

# Create identity if we haven't already

identity = rpki.irdb.Identity.objects.get_or_create(handle = handle)[0]

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
  rpki.irdb.GhostbusterRequest.objects.get_or_create(identity = identity, vcard = row[0],
                                                     defaults = { "parent" : None })

cur.close()
db.close()
