"""
Convert {parents,children,pubclients}.csv into new XML formats.

$Id$

Copyright (C) 2010  Internet Systems Consortium ("ISC")

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

import subprocess, csv, re, os, getopt, sys, ConfigParser, base64, urlparse
import rpki.sundial, myrpki

from lxml.etree import Element, SubElement, ElementTree

section_regexp  = re.compile("\s*\[\s*(.+?)\s*\]\s*$")
variable_regexp = re.compile("\s*([-a-zA-Z0-9_]+)(\s*=\s*)(.+?)\s*$")

cfg_file = "myrpki.conf"
template_file = os.path.join(os.path.dirname(sys.argv[0]), "examples", "myrpki.conf")
new_cfg_file = None
preserve_valid_until = False

opts, argv = getopt.getopt(sys.argv[1:], "c:hn:pt:?", ["config=", "new_config=", "preserve_valid_until", "template_config=", "help"])
for o, a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  elif o in ("-c", "--config"):
    cfg_file = a
  elif o in ("-n", "--new_config"):
    new_cfg_file = a
  elif o in ("-p", "--preserve_valid_until"):
    preserve_valid_until = True
  elif o in ("-t", "--template_config"):
    template_file = a
if argv:
  raise RuntimeError, "Unexpected arguments %r" % (argv,)
if os.path.samefile(cfg_file, template_file):
  raise RuntimeError, "Old config and template for new config can't be the same file"
if new_cfg_file is None:
  new_cfg_file = cfg_file + ".new"
if os.path.exists(new_cfg_file):
  raise RuntimeError, "%s already exists, NOT overwriting" % new_cfg_file

cfg = ConfigParser.RawConfigParser()
cfg.readfp(open(cfg_file))

# These two have no counterpart in new config file, just read them from old

repository_bpki_certificate = cfg.get("myrpki", "repository_bpki_certificate")
repository_handle           = cfg.get("myrpki", "repository_handle")

# Here we need to construct values for the new config file from the
# old one.  Basic model here is to look at whatever variables need to
# be set in the template (mostly just the [myrpki], I hope), pull
# necessary data from old config file any way we can.  Stuff that
# didn't make the jump from old config file to new we can just ignore,
# stuff that is automated via macro expansions in the new config file
# should be ok without modification.

r = {}

if cfg.has_section("myrpki"):
  for i in ("handle", "roa_csv", "prefix_csv", "asn_csv", "xml_filename"):
    r["myrpki", i] = cfg.get("myrpki", i)
  r["myrpki", "bpki_resources_directory"] = cfg.get("myrpki", "bpki_directory")

if cfg.has_section("myirbe"):
  r["myrpki", "bpki_servers_directory"] = cfg.get("myirbe", "bpki_directory")
  r["myrpki", "run_rpkid"]              = True
  r["myrpki", "run_pubd"]               = cfg.has_option("myirbe", "want_pubd")  and cfg.getboolean("myirbe", "want_pubd")
  r["myrpki", "run_rootd"]              = cfg.has_option("myirbe", "want_rootd") and cfg.getboolean("myirbe", "want_rootd")
else:
  for i in ("run_rpkid", "run_pubd", "run_rootd"):
    r["myrpki", i] = False

if cfg.has_section("rpkid"):
  r["myrpki", "rpkid_server_host"] = cfg.get("rpkid", "server-host")
  r["myrpki", "rpkid_server_port"] = cfg.get("rpkid", "server-port")

if cfg.has_section("irdbd"):
  u = urlparse.urlparse(cfg.get("irdbd", "https-url"))
  r["myrpki", "irdbd_server_host"] = u.hostname or "localhost"
  r["myrpki", "irdbd_server_port"] = u.port or 443

if cfg.has_section("pubd"):
  r["myrpki", "pubd_server_host"] = cfg.get("pubd", "server-host")
  r["myrpki", "pubd_server_port"] = cfg.get("pubd", "server-port")
  r["myrpki", "publication_base_directory"] = cfg.get("pubd", "publication-base")

if cfg.has_section("rootd"):
  r["myrpki", "rootd_server_port"] = cfg.get("rootd", "server-port")
  u = urlparse.urlparse(cfg.get("rootd", "rpki-base-uri"))
  r["myrpki", "publication_rsync_server"] = u.netloc

for i in ("rpkid", "irdbd", "pubd"):
  if cfg.has_section(i):
    for j in ("sql-database", "sql-username", "sql-password"):
      r[i, j] = cfg.get(i, j)

f = open(new_cfg_file, "w")
f.write("# Automatically converted from %s using %s as a template.\n\n" % (cfg_file, template_file))
section = None
for line in open(template_file):
  m = section_regexp.match(line)
  if m:
    section = m.group(1)
  m = variable_regexp.match(line)
  if m:
    option, whitespace = m.group(1, 2)
  else:
    option = None
  if (section, option) in r:
    line = "%s%s%s\n" % (option, whitespace, r[section, option])
  f.write(line)
f.close()
print "Wrote", new_cfg_file

# Get all of these from the new config file; in theory we just set all
# of them, but we want to use values matching new config in any case.

newcfg = ConfigParser.RawConfigParser()
newcfg.readfp(open(new_cfg_file))

handle                      = newcfg.get("myrpki", "handle")
bpki_resources_directory    = newcfg.get("myrpki", "bpki_resources_directory")
bpki_servers_directory      = newcfg.get("myrpki", "bpki_servers_directory")

pubd_server_host            = newcfg.get("myrpki", "pubd_server_host")
pubd_server_port            = newcfg.get("myrpki", "pubd_server_port")
rpkid_server_host           = newcfg.get("myrpki", "rpkid_server_host")
rpkid_server_port           = newcfg.get("myrpki", "rpkid_server_port")

bpki_resources_pemfile      = bpki_resources_directory + "/ca.cer"
bpki_servers_pemfile        = bpki_servers_directory + "/ca.cer"

try:
  entitydb_dir = newcfg.get("myrpki", "entitydb_dir")
except ConfigParser.NoOptionError:
  entitydb_dir = "entitydb"
  
def entitydb(*args):
  return os.path.join(entitydb_dir, *args)

# Now convert the .csv files.  It'd be nice to have XML validation
# enabled for this, so try to turn it on ourselves if the magic
# environment variable hasn't already been set.

rng_file = os.path.join(os.path.dirname(sys.argv[0]), "myrpki.rng")
if not os.getenv("MYRPKI_RNG") and os.path.exists(rng_file):
  os.putenv("MYRPKI_RNG", rng_file)

for d in map(entitydb, ("children", "parents", "repositories", "pubclients")):
  if not os.path.exists(d):
    os.makedirs(d)

one_year_from_now = str(rpki.sundial.now() + rpki.sundial.timedelta(days = 365))

if os.path.exists("children.csv"):
  for child_handle, valid_until, child_resource_pemfile in myrpki.csv_open("children.csv"):

    e = Element("parent",
                valid_until = valid_until if preserve_valid_until else one_year_from_now,
                service_uri = "https://%s:%s/up-down/%s/%s" % (rpkid_server_host, rpkid_server_port, handle, child_handle),
                child_handle = child_handle,
                parent_handle = handle)
    myrpki.PEMElement(e, "bpki_resource_ta", bpki_resources_pemfile)
    myrpki.PEMElement(e, "bpki_server_ta",   bpki_servers_pemfile)
    myrpki.PEMElement(e, "bpki_child_ta",    child_resource_pemfile)
    myrpki.etree_write(e, entitydb("children", "%s.xml" % child_handle))


if os.path.exists("parents.csv"):
  for parent_handle, parent_service_uri, parent_cms_pemfile, parent_https_pemfile, parent_myhandle, parent_sia_base in myrpki.csv_open("parents.csv"):

    e = Element("parent",
                valid_until = one_year_from_now,
                service_uri = parent_service_uri,
                child_handle = parent_myhandle,
                parent_handle = parent_handle)
    myrpki.PEMElement(e, "bpki_resource_ta", parent_cms_pemfile)
    myrpki.PEMElement(e, "bpki_server_ta",   parent_https_pemfile)
    myrpki.PEMElement(e, "bpki_child_ta",    bpki_resources_pemfile)
    myrpki.etree_write(e, entitydb("parents", "%s.xml" % parent_handle))

    client_handle = "/".join(parent_sia_base.rstrip("/").split("/")[3:])
    assert client_handle.startswith(repository_handle)

    e = Element("repository",
                parent_handle = parent_handle,
                client_handle = client_handle,
                service_uri = "https://%s:%s/client/%s" % (pubd_server_host, pubd_server_port, client_handle),
                sia_base = parent_sia_base,
                type = "confirmed")
    myrpki.PEMElement(e, "bpki_server_ta", repository_bpki_certificate)
    myrpki.PEMElement(e, "bpki_client_ta", bpki_resources_pemfile)
    SubElement(e, "contact_info").text = "Automatically generated by convert-csv.py"
    myrpki.etree_write(e, entitydb("repositories", "%s.xml" % parent_handle))

if os.path.exists("pubclients.csv"):
  for client_handle, client_resource_pemfile, client_sia_base in myrpki.csv_open("pubclients.csv"):

    parent_handle = client_handle.split("/")[-1]

    e = Element("repository",
                parent_handle = parent_handle,
                client_handle = client_handle,
                service_uri = "https://%s:%s/client/%s" % (pubd_server_host, pubd_server_port, client_handle),
                sia_base = client_sia_base,
                type = "confirmed")
    myrpki.PEMElement(e, "bpki_server_ta", bpki_servers_pemfile)
    myrpki.PEMElement(e, "bpki_client_ta", client_resource_pemfile)
    SubElement(e, "contact_info").text = "Automatically generated by convert-csv.py"
    myrpki.etree_write(e, entitydb("pubclients", "%s.xml" % client_handle.replace("/", ".")))
