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
import sys
import yaml
import signal
import time
import argparse
import rpki.resource_set
import rpki.sundial
import rpki.config
import rpki.log
import rpki.csv_utils
import rpki.x509
import rpki.sql_schemas

from rpki.mysql_import import MySQLdb

section_regexp = re.compile("\s*\[\s*(.+?)\s*\]\s*$")
variable_regexp = re.compile("\s*([-a-zA-Z0-9_]+)\s*=\s*(.+?)\s*$")

flat_publication = False
only_one_pubd = True
yaml_file = None
loopback = False
quiet = False
dns_suffix = None
mysql_rootuser = None
mysql_rootpass = None
publication_base = None
publication_root = None

# The SQL username mismatch between rpkid/examples/rpki.conf and
# rpkid/tests/smoketest.setup.sql is completely stupid and really
# should be cleaned up at some point...but not today, at least not as
# part of writing this program.  These default values are wired into
# yamltest to match smoketest.setup.sql, so wire them in here too but
# in a more obvious way.

config_overrides = {
  "irdbd_sql_username" : "irdb", "irdbd_sql_password" : "fnord",
  "rpkid_sql_username" : "rpki", "rpkid_sql_password" : "fnord",
  "pubd_sql_username"  : "pubd", "pubd_sql_password"  : "fnord" }

def cleanpath(*names):
  return os.path.normpath(os.path.join(*names))

this_dir  = os.getcwd()
test_dir  = None
rpki_conf = None

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

  base_port     = 4400
  base_engine   = -1
  parent        = None
  crl_interval  = None
  regen_margin  = None
  engine        = -1
  rpkid_port    = 4404
  irdbd_port    = 4403
  pubd_port     = 4402
  rootd_port    = 4401
  rsync_port    = 873

  @classmethod
  def allocate_port(cls):
    cls.base_port += 1
    return cls.base_port

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
    if "crl_interval" in y:
      self.crl_interval = rpki.sundial.timedelta.parse(y["crl_interval"]).convert_to_seconds()
    if "regen_margin" in y:
      self.regen_margin = rpki.sundial.timedelta.parse(y["regen_margin"]).convert_to_seconds()
    self.roa_requests = [roa_request.parse(r) for r in y.get("roa_request", ())]
    for r in self.roa_requests:
      if r.v4:
        self.base.v4 |= r.v4.to_resource_set()
      if r.v6:
        self.base.v6 |= r.v6.to_resource_set()
    self.hosted_by = y.get("hosted_by")
    self.hosts = []
    if not self.is_hosted:
      self.engine = self.allocate_engine()
    if loopback and not self.is_hosted:
      self.rpkid_port = self.allocate_port()
      self.irdbd_port = self.allocate_port()
    if loopback and self.runs_pubd:
      self.pubd_port  = self.allocate_port()
      self.rsync_port = self.allocate_port()
    if loopback and self.is_root:
      self.rootd_port = self.allocate_port()

  def closure(self):
    resources = self.base
    for kid in self.kids:
      resources |= kid.closure()
    self.resources = resources
    return resources

  @property
  def hostname(self):
    if loopback:
      return "localhost"
    elif dns_suffix:
      return self.name + "." + dns_suffix.lstrip(".")
    else:
      return self.name

  @property
  def rsync_server(self):
    if loopback:
      return "%s:%s" % (self.pubd.hostname, self.pubd.rsync_port)
    else:
      return self.pubd.hostname

  def dump(self):
    if not quiet:
      print str(self)

  def __str__(self):
    s = self.name + ":\n"
    if self.resources.asn:      s += "  ASNs: %s\n" % self.resources.asn
    if self.resources.v4:       s += "  IPv4: %s\n" % self.resources.v4
    if self.resources.v6:       s += "  IPv6: %s\n" % self.resources.v6
    if self.kids:               s += "  Kids: %s\n" % ", ".join(k.name for k in self.kids)
    if self.parent:             s += "    Up: %s\n" % self.parent.name
    if self.is_hosted:          s += "  Host: %s\n" % self.hosted_by.name
    if self.hosts:              s += " Hosts: %s\n" % ", ".join(h.name for h in self.hosts)
    for r in self.roa_requests: s += "   ROA: %s\n" % r
    if not self.is_hosted:      s += " IPort: %s\n" % self.irdbd_port
    if self.runs_pubd:          s += " PPort: %s\n" % self.pubd_port
    if not self.is_hosted:      s += " RPort: %s\n" % self.rpkid_port
    if self.runs_pubd:          s += " SPort: %s\n" % self.rsync_port
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
    if not quiet:
      print "Writing", path
    return rpki.csv_utils.csv_writer(path)

  def up_down_url(self):
    return "http://%s:%d/up-down/%s/%s" % (self.parent.host.hostname,
                                           self.parent.host.rpkid_port,
                                           self.parent.name,
                                           self.name)

  def dump_asns(self, fn):
    with self.csvout(fn) as f:
      for k in self.kids:    
        f.writerows((k.name, a) for a in k.resources.asn)

  def dump_prefixes(self, fn):
    with self.csvout(fn) as f:
      for k in self.kids:
        f.writerows((k.name, p) for p in (k.resources.v4 + k.resources.v6))

  def dump_roas(self, fn):
    with self.csvout(fn) as f:
      for g1, r in enumerate(self.roa_requests):
        f.writerows((p, r.asn, "G%08d%08d" % (g1, g2))
                    for g2, p in enumerate((r.v4 + r.v6 if r.v4 and r.v6 else r.v4 or r.v6 or ())))

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

  @property
  def publication_base_directory(self):
    if not loopback and publication_base is not None:
      return publication_base
    else:
      return self.path("publication")

  @property
  def publication_root_directory(self):
    if not loopback and publication_root is not None:
      return publication_root
    else:
      return self.path("publication.root")

  def dump_conf(self):

    r = dict(
      handle                    = self.name,
      run_rpkid                 = str(not self.is_hosted),
      run_pubd                  = str(self.runs_pubd),
      run_rootd                 = str(self.is_root),
      irdbd_sql_username        = "irdb",
      rpkid_sql_username        = "rpki",
      rpkid_server_host         = self.hostname,
      rpkid_server_port         = str(self.rpkid_port),
      irdbd_server_host         = "localhost",
      irdbd_server_port         = str(self.irdbd_port),
      rootd_server_port         = str(self.rootd_port),
      pubd_sql_username         = "pubd",
      pubd_server_host          = self.pubd.hostname,
      pubd_server_port          = str(self.pubd.pubd_port),
      publication_rsync_server  = self.rsync_server)
    
    if loopback:
      r.update(
        irdbd_sql_database      = self.irdb_name,
        rpkid_sql_database      = "rpki%d" % self.engine,
        pubd_sql_database       = "pubd%d" % self.engine,
        bpki_servers_directory  = self.path(),
        publication_base_directory = self.publication_base_directory)

    r.update(config_overrides)

    with open(self.path("rpki.conf"), "w") as f:
      f.write("# Automatically generated, do not edit\n")
      if not quiet:
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

  def dump_rsyncd(self):
    lines = []
    if self.runs_pubd:
      lines.extend((
        "# Automatically generated, do not edit",
        "port         = %d"           % self.rsync_port,
        "address      = %s"           % self.hostname,
        "log file     = rsyncd.log",
        "read only    = yes",
        "use chroot   = no",
        "[rpki]",
        "path         = %s"           % self.publication_base_directory,
        "comment      = RPKI test"))
    if self.is_root:
      assert self.runs_pubd
      lines.extend((
        "[root]",
        "path         = %s"           % self.publication_root_directory,
        "comment      = RPKI test root"))
    if lines:
      with open(self.path("rsyncd.conf"), "w") as f:
        if not quiet:
          print "Writing", f.name
        f.writelines(line + "\n" for line in lines)

  @property
  def irdb_name(self):
    return "irdb%d" % self.host.engine

  @property
  def irdb(self):
    prior_name = self.zoo.handle
    return rpki.irdb.database(
      self.irdb_name,
      on_entry = lambda: self.zoo.reset_identity(self.name),
      on_exit  = lambda: self.zoo.reset_identity(prior_name))

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
    self._zoo = rpki.irdb.Zookeeper(
      cfg = rpki.config.parser(self.path("rpki.conf")),
      logstream = None if quiet else sys.stdout)

  @property
  def zoo(self):
    return self.host._zoo

  def dump_root(self):

    assert self.is_root and not self.is_hosted

    root_resources = rpki.resource_set.resource_bag(
      asn = rpki.resource_set.resource_set_as("0-4294967295"),
      v4  = rpki.resource_set.resource_set_ipv4("0.0.0.0/0"),
      v6  = rpki.resource_set.resource_set_ipv6("::/0"))

    root_key = rpki.x509.RSA.generate(quiet = True)

    root_uri = "rsync://%s/rpki/" % self.rsync_server

    root_sia = (root_uri, root_uri + "root.mft", None)

    root_cert = rpki.x509.X509.self_certify(
      keypair     = root_key,
      subject_key = root_key.get_RSApublic(),
      serial      = 1,
      sia         = root_sia,
      notAfter    = rpki.sundial.now() + rpki.sundial.timedelta(days = 365),
      resources   = root_resources)

    with open(self.path("publication.root", "root.cer"), "wb") as f:
      f.write(root_cert.get_DER())

    with open(self.path("root.key"), "wb") as f:
      f.write(root_key.get_DER())

    with open(cleanpath(test_dir, "root.tal"), "w") as f:
      f.write("rsync://%s/root/root.cer\n\n%s" % (
        self.rsync_server, root_key.get_RSApublic().get_Base64()))

  def mkdir(self, *path):
    path = self.path(*path)
    if not quiet:
      print "Creating directory", path
    os.makedirs(path)

  def dump_sql(self):
    if not self.is_hosted:
      with open(self.path("rpkid.sql"), "w") as f:
        if not quiet:
          print "Writing", f.name
        f.write(rpki.sql_schemas.rpkid)
    if self.runs_pubd:
      with open(self.path("pubd.sql"), "w") as f:
        if not quiet:
          print "Writing", f.name
        f.write(rpki.sql_schemas.pubd)
    if not self.is_hosted:
      username = config_overrides["irdbd_sql_username"]
      password = config_overrides["irdbd_sql_password"]
      cmd = ("mysqldump", "-u", username, "-p" + password, self.irdb_name)
      with open(self.path("irdbd.sql"), "w") as f:
        if not quiet:
          print "Writing", f.name
        subprocess.check_call(cmd, stdout = f)


def pre_django_sql_setup(needed):

  username = config_overrides["irdbd_sql_username"]
  password = config_overrides["irdbd_sql_password"]

  # If we have the MySQL root password, just blow away and recreate
  # the required databases.  Otherwise, check for missing databases,
  # then blow away all tables in the required databases.  In either
  # case, we assume that the Django syncdb code will populate
  # databases as necessary, all we need to do here is provide empty
  # databases for the Django code to fill in.

  if mysql_rootpass is not None:
    if mysql_rootpass:
      db = MySQLdb.connect(user = mysql_rootuser, passwd = mysql_rootpass)
    else:
      db = MySQLdb.connect(user = mysql_rootuser)  
    cur = db.cursor()
    for database in needed:
      try:
        cur.execute("DROP DATABASE IF EXISTS %s" % database)
      except:
        pass
      cur.execute("CREATE DATABASE %s" % database)
      cur.execute("GRANT ALL ON %s.* TO %s@localhost IDENTIFIED BY %%s" % (
        database, username), (password,))

  else:
    db = MySQLdb.connect(user = username, passwd = password)
    cur = db.cursor()
    cur.execute("SHOW DATABASES")
    existing = set(r[0] for r in cur.fetchall())
    if needed - existing:
      sys.stderr.write("The following databases are missing:\n")
      for database in sorted(needed - existing):
        sys.stderr.write("  %s\n" % database)
      sys.stderr.write("Please create them manually or put MySQL root password in my config file\n")
      sys.exit("Missing databases and MySQL root password not known, can't continue")
    for database in needed:
      db.select_db(database)
      cur.execute("SHOW TABLES")
      tables = [r[0] for r in cur.fetchall()]
      cur.execute("SET foreign_key_checks = 0")
      for table in tables:
        cur.execute("DROP TABLE %s" % table)
      cur.execute("SET foreign_key_checks = 1")  

  cur.close()
  db.commit()
  db.close()

class timestamp(object):

  def __init__(self, *args):
    self.count = 0
    self.start = self.tick = rpki.sundial.now()

  def __call__(self, *args):
    now = rpki.sundial.now()
    if not quiet:
      print "[Count %s last %s total %s now %s]" % (
        self.count, now - self.tick, now - self.start, now)
    self.tick = now
    self.count += 1


def main():

  global flat_publication
  global config_overrides
  global only_one_pubd
  global loopback
  global dns_suffix
  global mysql_rootuser
  global mysql_rootpass
  global yaml_file
  global test_dir
  global rpki_conf
  global publication_base
  global publication_root
  global quiet

  os.environ["TZ"] = "UTC"
  time.tzset()

  parser = argparse.ArgumentParser(description = "yamlconf")
  parser.add_argument("-c", "--config", help = "configuration file")
  parser.add_argument("--dns_suffix",
                      help = "DNS suffix to add to hostnames")
  parser.add_argument("-l", "--loopback", action = "store_true",
                      help = "Configure for use with yamltest on localhost")
  parser.add_argument("-f", "--flat_publication", action = "store_true",
                      help = "Use flat publication model")
  parser.add_argument("-q", "--quiet", action = "store_true",
                      help = "Work more quietly")
  parser.add_argument("--profile",
                      help = "Filename for profile output")
  parser.add_argument("yaml_file", type = argparse.FileType("r"),
                      help = "YAML file describing network to build")
  args = parser.parse_args()

  dns_suffix = args.dns_suffix
  loopback = args.loopback
  flat_publication = args.flat_publication
  quiet = args.quiet
  yaml_file = args.yaml_file

  rpki.log.use_syslog = False
  rpki.log.init("yamlconf")

  # Allow optional config file for this tool to override default
  # passwords: this is mostly so that I can show a complete working
  # example without publishing my own server's passwords.

  cfg = rpki.config.parser(args.config, "yamlconf", allow_missing = True)
  try:
    cfg.set_global_flags()
  except:
    pass

  # Use of "yamltest.dir" is deliberate: intent is for what we write to
  # be usable with "yamltest --skip_config".

  only_one_pubd = cfg.getboolean("only_one_pubd", True)
  test_dir = cfg.get("test_directory", cleanpath(this_dir, "yamltest.dir"))
  rpki_conf = cfg.get("rpki_conf", cleanpath(this_dir, "..", "examples/rpki.conf"))
  mysql_rootuser = cfg.get("mysql_rootuser", "root")

  try:
    mysql_rootpass = cfg.get("mysql_rootpass")
  except:
    pass

  try:
    publication_base = cfg.get("publication_base")
  except:
    pass

  try:
    publication_root = cfg.get("publication_root")
  except:
    pass

  for k in ("rpkid_sql_password", "irdbd_sql_password", "pubd_sql_password",
            "rpkid_sql_username", "irdbd_sql_username", "pubd_sql_username"):
    if cfg.has_option(k):
      config_overrides[k] = cfg.get(k) 

  if args.profile:
    import cProfile
    prof = cProfile.Profile()
    try:
      prof.runcall(body)
    finally:
      prof.dump_stats(args.profile)
      if not quiet:
        print
        print "Dumped profile data to %s" % args.profile
  else:
    body()

def body():

  global rpki

  ts = timestamp()

  for root, dirs, files in os.walk(test_dir, topdown = False):
    for file in files:
      os.unlink(os.path.join(root, file))
    for dir in dirs:
      os.rmdir(os.path.join(root, dir))

  if not quiet:
    print
    print "Reading YAML", yaml_file.name

  db = allocation_db(yaml.safe_load_all(yaml_file).next())

  # Show what we loaded

  #db.dump()

  # Do pre-Django SQL setup

  pre_django_sql_setup(set(d.irdb_name for d in db if not d.is_hosted))

  # Now ready for fun with multiple databases in Django!

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

  databases["default"] = databases[db.root.irdb_name]

  from django.conf import settings

  settings.configure(
    DATABASES = databases,
    DATABASE_ROUTERS = ["rpki.irdb.router.DBContextRouter"],
    INSTALLED_APPS = ("rpki.irdb",))

  import rpki.irdb

  rpki.irdb.models.ca_certificate_lifetime = rpki.sundial.timedelta(days = 3652 * 2)
  rpki.irdb.models.ee_certificate_lifetime = rpki.sundial.timedelta(days = 3652)

  ts()

  for d in db:
    if not quiet:
      print
      print "Configuring", d.name

    if not d.is_hosted:
      d.mkdir()
    if d.runs_pubd:
      d.mkdir("publication")
    if d.is_root:
      d.mkdir("publication.root")

    if not d.is_hosted:
      d.dump_conf()
      d.dump_rsyncd()

    d.dump_asns("%s.asns.csv" % d.name)
    d.dump_prefixes("%s.prefixes.csv" % d.name)
    d.dump_roas("%s.roas.csv" % d.name)

    if not d.is_hosted:
      if not quiet:
        print "Initializing SQL"
      d.syncdb()
      if not quiet:
        print "Hiring zookeeper"
      d.hire_zookeeper()

    with d.irdb:
      if not quiet:
        print "Creating identity"
      x = d.zoo.initialize()

      if d.is_root:
        if not quiet:
          print "Creating RPKI root certificate and TAL"
        d.dump_root()
        x = d.zoo.configure_rootd()

      else:
        with d.parent.irdb:
          x = d.parent.zoo.configure_child(x.file)[0]
        x = d.zoo.configure_parent(x.file)[0]

      with d.pubd.irdb:
        x = d.pubd.zoo.configure_publication_client(x.file, flat = flat_publication)[0]
      d.zoo.configure_repository(x.file)

    if loopback and not d.is_hosted:
      with d.irdb:
        d.zoo.write_bpki_files()

    ts()

  if not loopback:
    if not quiet:
      print
    for d in db:
      d.dump_sql()

if __name__ == "__main__":
  main()
