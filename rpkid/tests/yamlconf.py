"""
Test configuration tool, using the same YAML test description format
as smoketest.py and yamltest.py, but doing just the IRDB configuration
for a massive testbed, via direct use of the rpki.irdb library code.

For most purposes, you don't want this, but when building a
configuration for tens or hundreds of thousands of elements, being
able to do the initial configuration stage quickly can help a lot.

$Id$

Copyright (C) 2009--2012  Internet Systems Consortium ("ISC")

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

Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")

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

import subprocess
import re
import os
import getopt
import sys
import yaml
import signal
import time
import cStringIO
import rpki.resource_set
import rpki.sundial
import rpki.config
import rpki.log
import rpki.csv_utils
import rpki.x509

section_regexp = re.compile("\s*\[\s*(.+?)\s*\]\s*$")
variable_regexp = re.compile("\s*([-a-zA-Z0-9_]+)\s*=\s*(.+?)\s*$")

flat_publication = False
config_overrides = {}
only_one_pubd = True
yaml_file = None

def cleanpath(*names):
  return os.path.normpath(os.path.join(*names))

this_dir  = os.getcwd()
test_dir  = cleanpath(this_dir, "yamlconf.dir")
rpki_conf = cleanpath(this_dir, "..", "examples/rpki.conf")

class roa_request(object):
  """
  Representation of a ROA request.
  """

  def __init__(self, asn, ipv4, ipv6):
    self.asn = asn
    self.v4 = rpki.resource_set.roa_prefix_set_ipv4("".join(ipv4.split())) if ipv4 else None
    self.v6 = rpki.resource_set.roa_prefix_set_ipv6("".join(ipv6.split())) if ipv6 else None

  def __eq__(self, other):
    return self.asn == other.asn and self.v4 == other.v4 and self.v6 == other.v6

  def __hash__(self):
    v4 = tuple(self.v4) if self.v4 is not None else None
    v6 = tuple(self.v6) if self.v6 is not None else None
    return self.asn.__hash__() + v4.__hash__() + v6.__hash__()

  def __str__(self):
    if self.v4 and self.v6:
      return "%s: %s,%s" % (self.asn, self.v4, self.v6)
    else:
      return "%s: %s" % (self.asn, self.v4 or self.v6)

  @classmethod
  def parse(cls, y):
    return cls(y.get("asn"), y.get("ipv4"), y.get("ipv6"))
    
class allocation_db(list):
  """
  Allocation database.
  """

  def __init__(self, y):
    list.__init__(self)
    self.root = allocation(y, self)
    assert self.root.is_root
    if self.root.crl_interval is None:
      self.root.crl_interval = 24 * 60 * 60
    if self.root.regen_margin is None:
      self.root.regen_margin = 24 * 60 * 60
    if self.root.base.valid_until is None:
      self.root.base.valid_until = rpki.sundial.now() + rpki.sundial.timedelta(days = 2)
    for a in self:
      if a.sia_base is None:
        if a.runs_pubd:
          base = "rsync://%s/rpki/" % a.hostname
        else:
          base = a.parent.sia_base
        a.sia_base = base + a.name + "/"
      if a.base.valid_until is None:
        a.base.valid_until = a.parent.base.valid_until
      if a.crl_interval is None:
        a.crl_interval = a.parent.crl_interval
      if a.regen_margin is None:
        a.regen_margin = a.parent.regen_margin
    self.root.closure()
    self.map = dict((a.name, a) for a in self)
    for a in self:
      if a.is_hosted:
        a.hosted_by = self.map[a.hosted_by]
        a.hosted_by.hosts.append(a)
        assert not a.is_root and not a.hosted_by.is_hosted

  def dump(self):
    for a in self:
      a.dump()


class allocation(object):
  """
  One entity in our allocation database.  Every entity in the database
  is assumed to hold resources.  Entities that don't have the
  hosted_by property run their own copies of rpkid, irdbd, and pubd.
  """

  base_engine   = -1
  parent        = None
  crl_interval  = None
  regen_margin  = None
  engine        = -1
  rpkid_port    = 4400
  irdbd_port    = 4401
  pubd_port     = 4402
  rootd_port    = 4403

  @classmethod
  def allocate_engine(cls):
    cls.base_engine += 1
    return cls.base_engine

  def __init__(self, y, db, parent = None):
    db.append(self)
    self.name = y["name"]
    self.parent = parent
    self.kids = [allocation(k, db, self) for k in y.get("kids", ())]
    valid_until = None
    if "valid_until" in y:
      valid_until = rpki.sundial.datetime.fromdatetime(y.get("valid_until"))
    if valid_until is None and "valid_for" in y:
      valid_until = rpki.sundial.now() + rpki.sundial.timedelta.parse(y["valid_for"])
    self.base = rpki.resource_set.resource_bag(
      asn = rpki.resource_set.resource_set_as(y.get("asn")),
      v4 = rpki.resource_set.resource_set_ipv4(y.get("ipv4")),
      v6 = rpki.resource_set.resource_set_ipv6(y.get("ipv6")),
      valid_until = valid_until)
    self.sia_base = y.get("sia_base")
    if "crl_interval" in y:
      self.crl_interval = rpki.sundial.timedelta.parse(y["crl_interval"]).convert_to_seconds()
    if "regen_margin" in y:
      self.regen_margin = rpki.sundial.timedelta.parse(y["regen_margin"]).convert_to_seconds()
    self.roa_requests = [roa_request.parse(r) for r in y.get("roa_request", ())]
    for r in self.roa_requests:
      if r.v4:
        self.base.v4 = self.base.v4.union(r.v4.to_resource_set())
      if r.v6:
        self.base.v6 = self.base.v6.union(r.v6.to_resource_set())
    self.hosted_by = y.get("hosted_by")
    self.hosts = []
    if not self.is_hosted:
      self.engine = self.allocate_engine()

  def closure(self):
    resources = self.base
    for kid in self.kids:
      resources = resources.union(kid.closure())
    self.resources = resources
    return resources

  @property
  def hostname(self):
    return self.name + ".emulation-testbed.rpki.net"

  def dump(self):
    print str(self)

  def __str__(self):
    s = self.name + ":\n"
    if self.resources.asn:      s += "  ASNs: %s\n" % self.resources.asn
    if self.resources.v4:       s += "  IPv4: %s\n" % self.resources.v4
    if self.resources.v6:       s += "  IPv6: %s\n" % self.resources.v6
    if self.kids:               s += "  Kids: %s\n" % ", ".join(k.name for k in self.kids)
    if self.parent:             s += "    Up: %s\n" % self.parent.name
    if self.sia_base:           s += "   SIA: %s\n" % self.sia_base
    if self.is_hosted:          s += "  Host: %s\n" % self.hosted_by.name
    if self.hosts:              s += " Hosts: %s\n" % ", ".join(h.name for h in self.hosts)
    for r in self.roa_requests: s += "   ROA: %s\n" % r
    if not self.is_hosted:      s += " IPort: %s\n" % self.irdbd_port
    if self.runs_pubd:          s += " PPort: %s\n" % self.pubd_port
    if not self.is_hosted:      s += " RPort: %s\n" % self.rpkid_port
    if self.is_root:            s += " TPort: %s\n" % self.rootd_port
    return s + " Until: %s\n" % self.resources.valid_until

  @property
  def is_root(self):
    return self.parent is None

  @property
  def is_hosted(self):
    return self.hosted_by is not None

  @property
  def runs_pubd(self):
    return self.is_root or not (self.is_hosted or only_one_pubd)

  def path(self, *names):
    return cleanpath(test_dir, self.host.name, *names)

  def csvout(self, fn):
    path = self.path(fn)
    print "Writing", path
    return rpki.csv_utils.csv_writer(path)

  def up_down_url(self):
    return "http://%s:%d/up-down/%s/%s" % (self.parent.host.hostname,
                                           self.parent.host.rpkid_port,
                                           self.parent.name,
                                           self.name)

  def dump_asns(self, fn):
    f = self.csvout(fn)
    for k in self.kids:    
      f.writerows((k.name, a) for a in k.resources.asn)
    f.close()

  def dump_prefixes(self, fn):
    f = self.csvout(fn)
    for k in self.kids:
      f.writerows((k.name, p) for p in (k.resources.v4 + k.resources.v6))
    f.close()

  def dump_roas(self, fn):
    f = self.csvout(fn)
    for g1, r in enumerate(self.roa_requests):
      f.writerows((p, r.asn, "G%08d%08d" % (g1, g2))
                  for g2, p in enumerate((r.v4 + r.v6 if r.v4 and r.v6 else r.v4 or r.v6 or ())))
    f.close()

  @property
  def pubd(self):
    s = self
    while not s.runs_pubd:
      s = s.parent
    return s

  @property
  def client_handle(self):
    path = []
    s = self
    if not flat_publication:
      while not s.runs_pubd:
        path.append(s)
        s = s.parent
    path.append(s)
    return ".".join(i.name for i in reversed(path))

  @property
  def host(self):
    return self.hosted_by or self

  def dump_conf(self):

    r = { "handle"              : self.name,
          "run_rpkid"           : str(not self.is_hosted),
          "run_pubd"            : str(self.runs_pubd),
          "run_rootd"           : str(self.is_root),
          "irdbd_sql_database"  : self.irdb_name,
          "irdbd_sql_username"  : "irdb",
          "rpkid_sql_database"  : "rpki%d" % self.engine,
          "rpkid_sql_username"  : "rpki",
          "rpkid_server_host"   : self.hostname,
          "rpkid_server_port"   : str(self.rpkid_port),
          "irdbd_server_host"   : self.hostname,
          "irdbd_server_port"   : str(self.irdbd_port),
          "rootd_server_port"   : str(self.rootd_port),
          "pubd_sql_database"   : "pubd%d" % self.engine,
          "pubd_sql_username"   : "pubd",
          "pubd_server_host"    : self.pubd.hostname,
          "pubd_server_port"    : str(self.pubd.pubd_port),
          "publication_rsync_server" : self.pubd.hostname,
          "bpki_servers_directory" : self.path() }
    
    r.update(config_overrides)

    f = open(self.path("rpki.conf"), "w")
    f.write("# Automatically generated, do not edit\n")
    print "Writing", f.name

    section = None
    for line in open(rpki_conf):
      m = section_regexp.match(line)
      if m:
        section = m.group(1)
      m = variable_regexp.match(line)
      option = m.group(1) if m and section == "myrpki" else None
      if option and option in r:
        line = "%s = %s\n" % (option, r[option])
      f.write(line)

    f.close()

  @property
  def irdb_name(self):
    return "irdb%d" % self.host.engine

  @property
  def irdb(self):
    self.host.zoo.reset_identity(self.name)
    return rpki.irdb.database(self.irdb_name)

  def syncdb(self):
    import django.core.management
    assert not self.is_hosted
    django.core.management.call_command("syncdb",
                                        database = self.irdb_name,
                                        load_initial_data = False,
                                        interactive = False,
                                        verbosity = 0)

  def hire_zookeeper(self):
    assert not self.is_hosted
    self.zoo = rpki.irdb.Zookeeper(
      cfg = rpki.config.parser(self.path("rpki.conf")),
      logstream = sys.stdout)

  @property
  def identity(self):
    self._identity.seek(0)
    return self._identity

  @identity.setter
  def identity(self, value):
    self._identity = xmlfile(value)

  @identity.deleter
  def identity(self):
    del self._identity


def xmlfile(s):
  from rpki.irdb.zookeeper import etree_wrapper
  assert isinstance(s, (str, etree_wrapper))
  return cStringIO.StringIO(str(s))

def dump_root(root):

  root_resources = rpki.resource_set.resource_bag(
    asn = rpki.resource_set.resource_set_as("0-4294967295"),
    v4  = rpki.resource_set.resource_set_ipv4("0.0.0.0/0"),
    v6  = rpki.resource_set.resource_set_ipv6("::/0"))

  root_key = rpki.x509.RSA.generate(quiet = True)

  root_uri = "rsync://%s/rpki/" % root.hostname

  root_sia = ((rpki.oids.name2oid["id-ad-caRepository"], ("uri", root_uri)),
              (rpki.oids.name2oid["id-ad-rpkiManifest"], ("uri", root_uri + "root.mft")))

  root_cert = rpki.x509.X509.self_certify(
    keypair     = root_key,
    subject_key = root_key.get_RSApublic(),
    serial      = 1,
    sia         = root_sia,
    notAfter    = rpki.sundial.now() + rpki.sundial.timedelta(days = 365),
    resources   = root_resources)

  f = open(root.path("publication/root.cer"), "wb")
  f.write(root_cert.get_DER())
  f.close()

  f = open(root.path("root.key"), "wb")
  f.write(root_key.get_DER())
  f.close()

  f = open(os.path.join(test_dir, "root.tal"), "w")
  f.write(root_uri + "root.cer\n")
  f.write(root_key.get_RSApublic().get_Base64())
  f.close()


def main():

  global flat_publication
  global config_overrides
  global only_one_pubd
  global yaml_file

  os.environ["TZ"] = "UTC"
  time.tzset()

  cfg_file = None
  profile = None

  opts, argv = getopt.getopt(sys.argv[1:], "c:fh?",
                             ["config=", "flat_publication", "help", "profile="])
  for o, a in opts:
    if o in ("-h", "--help", "-?"):
      print __doc__
      sys.exit(0)
    if o in ("-c", "--config"):
      cfg_file = a
    elif o in ("-f", "--flat_publication"):
      flat_publication = True
    elif o == "--profile":
      profile = a

  if len(argv) > 1:
    raise rpki.exceptions.CommandParseFailure("Unexpected arguments %r" % argv)

  if len(argv) < 1:
    raise rpki.exceptions.CommandParseFailure("Missing YAML file name")

  yaml_file = argv[0]

  rpki.log.use_syslog = False
  rpki.log.init("yamlconf")

  # Allow optional config file for this tool to override default
  # passwords: this is mostly so that I can show a complete working
  # example without publishing my own server's passwords.

  cfg = rpki.config.parser(cfg_file, "yamlconf", allow_missing = True)
  cfg.set_global_flags()

  example_cfg = rpki.config.parser(rpki_conf, "myrpki")

  only_one_pubd = cfg.getboolean("only_one_pubd", True)

  for k in ("rpkid_sql_password", "irdbd_sql_password", "pubd_sql_password",
            "rpkid_sql_username", "irdbd_sql_username", "pubd_sql_username"):
    config_overrides[k] = cfg.get(k) if cfg.has_option(k) else example_cfg.get(k)

  if profile:
    import cProfile
    prof = cProfile.Profile()
    try:
      prof.runcall(body)
    finally:
      prof.dump_stats(profile)
      print
      print "Dumped profile data to %s" % profile
  else:
    body()

def body():

  global rpki

  for root, dirs, files in os.walk(test_dir, topdown = False):
    for file in files:
      os.unlink(os.path.join(root, file))
    for dir in dirs:
      os.rmdir(os.path.join(root, dir))

  print
  print "Reading YAML", yaml_file

  db = allocation_db(yaml.safe_load_all(open(yaml_file)).next())

  # Show what we loaded

  #db.dump()

  # Fun with multiple databases in Django!

  # https://docs.djangoproject.com/en/1.4/topics/db/multi-db/
  # https://docs.djangoproject.com/en/1.4/topics/db/sql/

  database_template = {
    "ENGINE"   : "django.db.backends.mysql",
    "USER"     : config_overrides["irdbd_sql_username"],
    "PASSWORD" : config_overrides["irdbd_sql_password"],
    "HOST"     : "",
    "PORT"     : "",
    "OPTIONS"  : { "init_command": "SET storage_engine=INNODB" }}

  databases = dict((d.irdb_name,
                    dict(database_template, NAME = d.irdb_name))
                   for d in db if not d.is_hosted)

  # Django seems really desperate for a default database, even though
  # we have no intention of using it.  Eventually, we may just let it
  # have, eg, a default entry pointing to the root IRDB to satisfy
  # this, but for now, we just waste an engine number so we can be
  # sure anything written to the other databases was done on purpose.

  if False:
    databases["default"] = dict(database_template,
                                NAME = "thisdatabasedoesnotexist",
                                USER = "thisusernamedoesnotexist",
                                PASSWORD = "thispasswordisinvalid")

  elif False:
    databases["default"] = dict(database_template,
                                NAME = "irdb%d" % allocation.allocate_engine())

  else:
    databases["default"] = databases[db.root.irdb_name]

  # Perhaps we want to do something with plain old MySQLdb as MySQL
  # root to create databases before dragging Django code into this?

  from django.conf import settings

  settings.configure(
    DATABASES = databases,
    DATABASE_ROUTERS = ["rpki.irdb.router.DBContextRouter"],
    INSTALLED_APPS = ("rpki.irdb",))

  import rpki.irdb

  print
  print "Creating directories, .conf and .csv files"
  print

  for d in db:
    if not d.is_hosted:
      os.makedirs(d.path())
      if d.is_root or d.runs_pubd:
        os.makedirs(d.path("publication"))
      d.dump_conf()
      d.dump_asns("%s.asns.csv" % d.name)
      d.dump_prefixes("%s.prefixes.csv" % d.name)
      d.dump_roas("%s.roas.csv" % d.name)
      print

  print "Initializing object models and zookeepers"

  for d in db:
    if not d.is_hosted:
      print " ", d.name
      d.syncdb()
      d.hire_zookeeper()

  print
  print "Creating rootd RPKI root certificate and TAL"

  dump_root(db.root)

  print

  for d in db:
    print "Creating identity", d.name
    with d.irdb:
      d.identity = d.host.zoo.initialize()

  for d in db:
    print
    print "Configuring", d.name

    if d.is_root:
      with d.irdb:
        assert not d.is_hosted
        x = d.zoo.configure_rootd()
        x = d.zoo.configure_publication_client(xmlfile(x), flat = flat_publication)[0]
        d.zoo.configure_repository(xmlfile(x))

    else:
      with d.parent.irdb:
        x = d.parent.zoo.configure_child(d.identity)[0]
      with d.irdb:
        x = d.zoo.configure_parent(xmlfile(x))[0]
      with d.pubd.irdb:
        x = d.pubd.zoo.configure_publication_client(xmlfile(x), flat = flat_publication)[0]
      with d.irdb:
        d.zoo.configure_repository(xmlfile(x))

if __name__ == "__main__":
  main()

