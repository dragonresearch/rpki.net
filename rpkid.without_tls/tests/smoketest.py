"""
Test framework to configure and drive a collection of rpkid.py and
irdbd.py instances under control of a master script.

Usage: python smoketest.py [ { -c | --config } config_file ]
                           [ { -h | --help } ]
                           [ { -p | --profile } ]
                           [ { -y | --yaml }   yaml_script ]

Default config_file is smoketest.conf, override with --config option.

Default yaml_script is smoketest.yaml, override with -yaml option.

yaml_script is a YAML file describing the tests to be run, and is
intended to be implementation agnostic.

config_file contains settings for various implementation-specific
things that don't belong in yaml_script.

$Id$

Copyright (C) 2009--2010  Internet Systems Consortium ("ISC")

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

from __future__ import with_statement

import os, yaml, warnings, subprocess, signal, time, getopt, sys
import rpki.resource_set, rpki.sundial, rpki.x509, rpki.http
import rpki.log, rpki.left_right, rpki.config, rpki.publication, rpki.async

# Silence warning while loading MySQLdb in Python 2.6, sigh
if hasattr(warnings, "catch_warnings"):
  with warnings.catch_warnings():
    warnings.simplefilter("ignore", DeprecationWarning)
    import MySQLdb
else:
  import MySQLdb

os.environ["TZ"] = "UTC"
time.tzset()

cfg_file = "smoketest.conf"

yaml_script = None
profile = False

opts, argv = getopt.getopt(sys.argv[1:], "c:hpy:?", ["config=", "help", "profile", "yaml="])
for o, a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  elif o in ("-c", "--config"):
    cfg_file = a
  elif o in ("-p", "--profile"):
    profile = True
  elif o in ("-y", "--yaml"):
    yaml_script = a
if argv:
  print __doc__
  raise rpki.exceptions.CommandParseFailure, "Unexpected arguments %s" % argv

cfg = rpki.config.parser(cfg_file, "smoketest", allow_missing = True)

# Load the YAML script early, so we can report errors ASAP

if yaml_script is None:
  yaml_script  = cfg.get("yaml_script", "smoketest.yaml")
try:
  yaml_script = [y for y in yaml.safe_load_all(open(yaml_script))]
except:
  print __doc__
  raise

# Define port allocator early, so we can use it while reading config

def allocate_port():
  """
  Allocate a TCP port number.
  """
  global base_port
  p = base_port
  base_port += 1
  return p

# Most filenames in the following are relative to the working directory.

smoketest_name = cfg.get("smoketest_name", "smoketest")
smoketest_dir  = cfg.get("smoketest_dir",  smoketest_name + ".dir")

irdb_db_pass   = cfg.get("irdb_db_pass",   "fnord")
rpki_db_pass   = cfg.get("rpki_db_pass",   "fnord")
pubd_db_pass   = cfg.get("pubd_db_pass",   "fnord")
pubd_db_name   = cfg.get("pubd_db_name",   "pubd0")
pubd_db_user   = cfg.get("pubd_db_user",   "pubd")

base_port      = int(cfg.get("base_port",  "4400"))

rsyncd_port    = allocate_port()
rootd_port     = allocate_port()
pubd_port      = allocate_port()

rsyncd_module  = cfg.get("rsyncd_module",  smoketest_name)
rootd_sia      = cfg.get("rootd_sia",      "rsync://localhost:%d/%s/" % (rsyncd_port, rsyncd_module))

rootd_name     = cfg.get("rootd_name",     "rootd")
rsyncd_name    = cfg.get("rsyncd_name",    "rsyncd")
rcynic_name    = cfg.get("rcynic_name",    "rcynic")
pubd_name      = cfg.get("pubd_name",      "pubd")

prog_python    = cfg.get("prog_python",    "python")
prog_rpkid     = cfg.get("prog_rpkid",     "../../rpkid.py")
prog_irdbd     = cfg.get("prog_irdbd",     "../../irdbd.py")
prog_poke      = cfg.get("prog_poke",      "../../testpoke.py")
prog_rootd     = cfg.get("prog_rootd",     "../../rootd.py")
prog_pubd      = cfg.get("prog_pubd",      "../../pubd.py")
prog_openssl   = cfg.get("prog_openssl",   "../../../openssl/openssl/apps/openssl")
prog_rsyncd    = cfg.get("prog_rsyncd",    "rsync")
prog_rcynic    = cfg.get("prog_rcynic",    "../../../rcynic/rcynic")

rcynic_stats   = cfg.get("rcynic_stats",   "echo ; ../../../rcynic/show.sh %s.xml ; echo" % rcynic_name)

rpki_sql_file  = cfg.get("rpki_sql_file",  "../rpkid.sql")
irdb_sql_file  = cfg.get("irdb_sql_file",  "../irdbd.sql")
pub_sql_file   = cfg.get("pub_sql_file",   "../pubd.sql")

startup_delay  = int(cfg.get("startup_delay", "10"))

rsyncd_dir     = None
pubd_ta        = None
pubd_irbe_key  = None
pubd_irbe_cert = None
pubd_pubd_cert = None

def main():
  """
  Main program.
  """

  rpki.log.use_syslog = False
  rpki.log.init(smoketest_name)
  rpki.log.info("Starting")

  pubd_process = None
  rootd_process = None
  rsyncd_process = None

  rpki_sql = mangle_sql(rpki_sql_file)
  irdb_sql = mangle_sql(irdb_sql_file)
  pubd_sql = mangle_sql(pub_sql_file)

  rpki.log.info("Initializing test directory")

  # Connect to test directory, creating it if necessary
  try:
    os.chdir(smoketest_dir)
  except OSError:
    os.makedirs(smoketest_dir)
    os.chdir(smoketest_dir)

  # Discard everything but keys, which take a while to generate
  for root, dirs, files in os.walk(".", topdown = False):
    for file in files:
      if not file.endswith(".key"):
        os.remove(os.path.join(root, file))
    for dir in dirs:
      os.rmdir(os.path.join(root, dir))

  rpki.log.info("Reading master YAML configuration")
  y = yaml_script.pop(0)

  rpki.log.info("Constructing internal allocation database")
  db = allocation_db(y)

  rpki.log.info("Constructing BPKI keys and certs for rootd")
  setup_bpki_cert_chain(rootd_name, ee = ("RPKI",))

  rpki.log.info("Constructing BPKI keys and certs for pubd")
  setup_bpki_cert_chain(pubd_name, ee = ("PUBD", "IRBE"))

  for a in db:
    a.setup_bpki_certs()

  setup_publication(pubd_sql)
  setup_rootd(db.root, y.get("rootd", {}))
  setup_rsyncd()
  setup_rcynic()

  for a in db.engines:
    a.setup_conf_file()
    a.setup_sql(rpki_sql, irdb_sql)
    a.sync_sql()

  try:

    rpki.log.info("Starting rootd")
    rootd_process = subprocess.Popen((prog_python, prog_rootd, "-d", "-c", rootd_name + ".conf"))

    rpki.log.info("Starting pubd")
    pubd_process = subprocess.Popen((prog_python, prog_pubd, "-d", "-c", pubd_name + ".conf") + (("-p", pubd_name + ".prof") if profile else ()))

    rpki.log.info("Starting rsyncd")
    rsyncd_process = subprocess.Popen((prog_rsyncd, "--daemon", "--no-detach", "--config", rsyncd_name + ".conf"))

    # Start rpkid and irdbd instances
    for a in db.engines:
      a.run_daemons()

    # From this point on we'll be running event-driven, so the rest of
    # the code until final exit is all closures.

    def start():
      rpki.async.iterator(db.engines, create_rpki_objects, created_rpki_objects)

    def create_rpki_objects(iterator, a):
      a.create_rpki_objects(iterator)

    def created_rpki_objects():

      # Setup keys and certs and write YAML files for leaves
      for a in db.leaves:
        a.setup_yaml_leaf()

      # Set pubd's BPKI CRL
      set_pubd_crl(yaml_loop)

    def yaml_loop():

      # This is probably where we should be updating expired BPKI
      # objects, particular CRLs

      rpki.log.info("Running cron for all RPKI engines")
      rpki.async.iterator(db.engines, run_cron, run_yaml)

    def run_cron(iterator, a):
      a.run_cron(iterator)

    def run_yaml():

      # Run all YAML clients
      for a in db.leaves:
        a.run_yaml()

      # Run rcynic to check results
      run_rcynic()

      # Apply next delta if we have one; otherwise, we're done.
      if yaml_script:
        rpki.log.info("Applying deltas")
        db.apply_delta(yaml_script.pop(0), apply_delta_done)
      else:
        rpki.log.info("No more deltas to apply, done")
        rpki.async.exit_event_loop()

    def apply_delta_done():

      # Resync IRDBs
      for a in db.engines:
        a.sync_sql()

      # Loop until we run out of control YAML
      yaml_loop()

    rpki.log.info("Sleeping %d seconds while daemons start up" % startup_delay)
    rpki.async.timer(start).set(rpki.sundial.timedelta(seconds = startup_delay))
    rpki.async.event_loop()

    # At this point we have gone into event-driven code.

    rpki.log.info("Event loop exited normally")

  except Exception, e:

    rpki.log.info("Event loop exited with an exception: %r" % e)
    rpki.log.traceback()

  finally:

    rpki.log.info("Cleaning up")
    for a in db.engines:
      a.kill_daemons()
    for proc, name in ((rootd_process,  "rootd"),
                       (pubd_process,   "pubd"),
                       (rsyncd_process, "rsyncd")):
      if proc is not None:
        rpki.log.info("Killing %s, pid %s" % (name, proc.pid))
        try:
          os.kill(proc.pid, signal.SIGTERM)
        except OSError:
          pass
        proc.wait()

def cmd_sleep(cb, interval):
  """
  Set an alarm, then wait for it to go off.
  """
  howlong = rpki.sundial.timedelta.parse(interval)
  rpki.log.info("Sleeping %r" % howlong)
  rpki.async.timer(cb).set(howlong)

def cmd_shell(cb, *cmd):
  """
  Run a shell command.
  """
  cmd = " ".join(cmd)
  status = subprocess.call(cmd, shell = True)
  rpki.log.info("Shell command returned status %d" % status)
  cb()

def cmd_echo(cb, *words):
  """Echo some text to the log."""
  rpki.log.note(" ".join(words))
  cb()

## @var cmds
# Dispatch table for commands embedded in delta sections

cmds = { "sleep" : cmd_sleep,
         "shell" : cmd_shell,
         "echo"  : cmd_echo }

class roa_request(object):
  """
  Representation for a roa_request object.
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
    if self.v4 and self.v6: s = str(self.v4) + "," + str(self.v6)
    elif self.v4:           s = str(self.v4)
    else:                   s = str(self.v6)
    return "%s: %s" % (self.asn, s)

  @classmethod
  def parse(cls, yaml):
    return cls(yaml.get("asn"), yaml.get("ipv4"), yaml.get("ipv6"))
    
class allocation_db(list):
  """
  Representation of all the entities and allocations in the test
  system.  Almost everything is generated out of this database.
  """

  def __init__(self, yaml):
    """
    Initialize database from the (first) YAML document.
    """

    list.__init__(self)
    self.root = allocation(yaml, self)
    assert self.root.is_root()
    if self.root.crl_interval is None:
      self.root.crl_interval = rpki.sundial.timedelta.parse(cfg.get("crl_interval", "1d")).convert_to_seconds()
    if self.root.regen_margin is None:
      self.root.regen_margin = rpki.sundial.timedelta.parse(cfg.get("regen_margin", "1d")).convert_to_seconds()
    for a in self:
      if a.sia_base is None:
        a.sia_base = (rootd_sia if a.is_root() else a.parent.sia_base) + a.name + "/"
      if a.base.valid_until is None:
        a.base.valid_until = a.parent.base.valid_until
      if a.crl_interval is None:
        a.crl_interval = a.parent.crl_interval
      if a.regen_margin is None:
        a.regen_margin = a.parent.regen_margin
      i = 0
      for j in xrange(4):
        i = a.sia_base.index("/", i) + 1
      a.client_handle = a.sia_base[i:].rstrip("/")
    self.root.closure()
    self.map = dict((a.name, a) for a in self)
    self.engines = [a for a in self if a.is_engine()]
    self.leaves = [a for a in self if a.is_leaf()]
    for i, a in enumerate(self.engines):
      a.set_engine_number(i)
    for a in self:
      if a.is_hosted():
        a.hosted_by = self.map[a.hosted_by]
        a.hosted_by.hosts.append(a)
        assert a.is_twig(), "%s is not twig" % a.name
        assert not a.hosted_by.is_hosted(), "%s is hosted by a hosted entity" % a.name

  def apply_delta(self, delta, cb):
    """
    Apply a delta or run a command.
    """

    def loop(iterator, d):
      if isinstance(d, str):
        c = d.split()
        cmds[c[0]](iterator, *c[1:])
      else:
        self.map[d["name"]].apply_delta(d, iterator)

    def done():
      self.root.closure()
      cb()

    if delta is None:
      cb()
    else:
      rpki.async.iterator(delta, loop, done)

  def dump(self):
    """
    Print content of the database.
    """
    for a in self:
      print a

class allocation(object):

  parent       = None
  irdb_db_name = None
  irdb_port    = None
  rpki_db_name = None
  rpki_port    = None
  crl_interval = None
  regen_margin = None

  def __init__(self, yaml, db, parent = None):
    """
    Initialize one entity and insert it into the database.
    """
    db.append(self)
    self.name = yaml["name"]
    self.parent = parent
    self.kids = [allocation(k, db, self) for k in yaml.get("kids", ())]
    valid_until = None
    if "valid_until" in yaml:
      valid_until = rpki.sundial.datetime.fromdatetime(yaml.get("valid_until"))
    if valid_until is None and "valid_for" in yaml:
      valid_until = rpki.sundial.now() + rpki.sundial.timedelta.parse(yaml["valid_for"])
    self.base = rpki.resource_set.resource_bag(
      asn = rpki.resource_set.resource_set_as(yaml.get("asn")),
      v4 = rpki.resource_set.resource_set_ipv4(yaml.get("ipv4")),
      v6 = rpki.resource_set.resource_set_ipv6(yaml.get("ipv6")),
      valid_until = valid_until)
    self.sia_base = yaml.get("sia_base")
    if "crl_interval" in yaml:
      self.crl_interval = rpki.sundial.timedelta.parse(yaml["crl_interval"]).convert_to_seconds()
    if "regen_margin" in yaml:
      self.regen_margin = rpki.sundial.timedelta.parse(yaml["regen_margin"]).convert_to_seconds()
    self.roa_requests = [roa_request.parse(y) for y in yaml.get("roa_request", yaml.get("route_origin", ()))]
    for r in self.roa_requests:
      if r.v4:
        self.base.v4 = self.base.v4.union(r.v4.to_resource_set())
      if r.v6:
        self.base.v6 = self.base.v6.union(r.v6.to_resource_set())
    self.hosted_by = yaml.get("hosted_by")
    self.extra_conf = yaml.get("extra_conf", [])
    self.hosts = []

  def closure(self):
    """
    Compute the transitive resource closure.
    """
    resources = self.base
    for kid in self.kids:
      resources = resources.union(kid.closure())
    self.resources = resources
    return resources

  def apply_delta(self, yaml, cb):
    """
    Apply deltas to this entity.
    """

    rpki.log.info("Applying delta: %s" % yaml)

    def loop(iterator, kv):
      if kv[0] == "name":
        iterator()
      else:
        getattr(self, "apply_" + kv[0])(kv[1], iterator)

    rpki.async.iterator(yaml.items(), loop, cb)

  def apply_add_as(self, text, cb):
    self.base.asn = self.base.asn.union(rpki.resource_set.resource_set_as(text))
    cb()

  def apply_add_v4(self, text, cb):
    self.base.v4 = self.base.v4.union(rpki.resource_set.resource_set_ipv4(text))
    cb()

  def apply_add_v6(self, text, cb):
    self.base.v6 = self.base.v6.union(rpki.resource_set.resource_set_ipv6(text))
    cb()

  def apply_sub_as(self, text, cb):
    self.base.asn = self.base.asn.difference(rpki.resource_set.resource_set_as(text))
    cb()

  def apply_sub_v4(self, text, cb):
    self.base.v4 = self.base.v4.difference(rpki.resource_set.resource_set_ipv4(text))
    cb()

  def apply_sub_v6(self, text, cb):
    self.base.v6 = self.base.v6.difference(rpki.resource_set.resource_set_ipv6(text))
    cb()

  def apply_valid_until(self, stamp, cb):
    self.base.valid_until = rpki.sundial.datetime.fromdatetime(stamp)
    cb()

  def apply_valid_for(self, text, cb):
    self.base.valid_until = rpki.sundial.now() + rpki.sundial.timedelta.parse(text)
    cb()

  def apply_valid_add(self, text, cb):
    self.base.valid_until += rpki.sundial.timedelta.parse(text)
    cb()

  def apply_valid_sub(self, text, cb):
    self.base.valid_until -= rpki.sundial.timedelta.parse(text)
    cb()

  def apply_roa_request_add(self, yaml, cb):
    for y in yaml:
      r = roa_request.parse(y)
      if r not in self.roa_requests:
        self.roa_requests.append(r)
    cb()

  def apply_roa_request_del(self, yaml, cb):
    for y in yaml:
      r = roa_request.parse(y)
      if r in self.roa_requests:
        self.roa_requests.remove(r)
    cb()

  def apply_rekey(self, target, cb):

    def done(e):
      if isinstance(e, Exception):
        rpki.log.traceback()
        raise e
      cb()

    if self.is_leaf():
      raise RuntimeError, "Can't rekey YAML leaf %s, sorry" % self.name
    elif target is None:
      rpki.log.info("Rekeying <self/> %s" % self.name)
      self.call_rpkid([rpki.left_right.self_elt.make_pdu(action = "set", self_handle = self.name, rekey = "yes")], cb = done)
    else:
      rpki.log.info("Rekeying <parent/> %s %s" % (self.name, target))
      self.call_rpkid([rpki.left_right.parent_elt.make_pdu(action = "set", self_handle = self.name, parent_handle = target, rekey = "yes")], cb = done)

  def apply_revoke(self, target, cb):

    def done(e):
      if isinstance(e, Exception):
        rpki.log.traceback()
        raise e
      cb()

    if self.is_leaf():
      rpki.log.info("Attempting to revoke YAML leaf %s" % self.name)
      subprocess.check_call((prog_python, prog_poke, "-y", self.name + ".yaml", "-r", "revoke"))
      cb()
    elif target is None:
      rpki.log.info("Revoking <self/> %s" % self.name)
      self.call_rpkid([rpki.left_right.self_elt.make_pdu(action = "set", self_handle = self.name, revoke = "yes")], cb = done)
    else:
      rpki.log.info("Revoking <parent/> %s %s" % (self.name, target))
      self.call_rpkid([rpki.left_right.parent_elt.make_pdu(action = "set", self_handle = self.name, parent_handle = target, revoke = "yes")], cb = done)

  def __str__(self):
    s = self.name + "\n"
    if self.resources.asn:      s += "  ASN: %s\n" % self.resources.asn
    if self.resources.v4:       s += " IPv4: %s\n" % self.resources.v4
    if self.resources.v6:       s += " IPv6: %s\n" % self.resources.v6
    if self.kids:               s += " Kids: %s\n" % ", ".join(k.name for k in self.kids)
    if self.parent:             s += "   Up: %s\n" % self.parent.name
    if self.sia_base:           s += "  SIA: %s\n" % self.sia_base
    return s + "Until: %s\n" % self.resources.valid_until

  def is_leaf(self):
    #return not self.kids and not self.roa_requests
    return False

  def is_root(self):
    return self.parent is None

  def is_twig(self):
    return not self.is_leaf() and not self.is_root()

  def is_hosted(self):
    return self.hosted_by is not None

  def is_engine(self):
    return not self.is_leaf() and not self.is_hosted()

  def set_engine_number(self, n):
    """
    Set the engine number for this entity.
    """
    self.irdb_db_name = "irdb%d" % n
    self.irdb_port    = allocate_port()
    self.rpki_db_name = "rpki%d" % n
    self.rpki_port    = allocate_port()

  def get_rpki_port(self):
    """
    Get rpki port to use for this entity.
    """
    if self.is_hosted():
      assert self.hosted_by.rpki_port is not None
      return self.hosted_by.rpki_port
    else:
      assert self.rpki_port is not None
      return self.rpki_port

  def setup_bpki_certs(self):
    """
    Create BPKI certificates for this entity.
    """
    rpki.log.info("Constructing BPKI keys and certs for %s" % self.name)
    if self.is_leaf():
      setup_bpki_cert_chain(self.name, ee = ("RPKI",))
    else:
      setup_bpki_cert_chain(name = self.name,
                            ee = ("RPKI", "IRDB", "IRBE"),
                            ca = ("SELF",))
      self.rpkid_ta   = rpki.x509.X509(PEM_file = self.name + "-TA.cer")
      self.irbe_key   = rpki.x509.RSA( PEM_file = self.name + "-IRBE.key")
      self.irbe_cert  = rpki.x509.X509(PEM_file = self.name + "-IRBE.cer")
      self.rpkid_cert = rpki.x509.X509(PEM_file = self.name + "-RPKI.cer")

  def setup_conf_file(self):
    """
    Write config files for this entity.
    """
    rpki.log.info("Writing config files for %s" % self.name)
    assert self.rpki_port is not None
    d = { "my_name"      : self.name,
          "irdb_db_name" : self.irdb_db_name,
          "irdb_db_pass" : irdb_db_pass,
          "irdb_port"    : self.irdb_port,
          "rpki_db_name" : self.rpki_db_name,
          "rpki_db_pass" : rpki_db_pass,
          "rpki_port"    : self.rpki_port }
    f = open(self.name + ".conf", "w")
    f.write(conf_fmt_1 % d)
    for line in self.extra_conf:
      f.write(line + "\n")
    f.close()

  def setup_sql(self, rpki_sql, irdb_sql):
    """
    Set up this entity's IRDB.
    """
    rpki.log.info("Setting up MySQL for %s" % self.name)
    db = MySQLdb.connect(user = "rpki", db = self.rpki_db_name, passwd = rpki_db_pass)
    cur = db.cursor()
    db.autocommit(True)
    for sql in rpki_sql:
      cur.execute(sql)
    db.close()
    db = MySQLdb.connect(user = "irdb", db = self.irdb_db_name, passwd = irdb_db_pass)
    cur = db.cursor()
    db.autocommit(True)
    for sql in irdb_sql:
      cur.execute(sql)
    for s in [self] + self.hosts:
      for kid in s.kids:
        cur.execute("INSERT registrant (registrant_handle, registry_handle, valid_until) VALUES (%s, %s, %s)",
                    (kid.name, s.name, kid.resources.valid_until.to_sql()))
    db.close()

  def sync_sql(self):
    """
    Whack this entity's IRDB to match our master database.  We do this
    once during setup, then do it again every time we apply a delta to
    this entity.
    """
    rpki.log.info("Updating MySQL data for IRDB %s" % self.name)
    db = MySQLdb.connect(user = "irdb", db = self.irdb_db_name, passwd = irdb_db_pass)
    cur = db.cursor()
    db.autocommit(True)
    cur.execute("DELETE FROM registrant_asn")
    cur.execute("DELETE FROM registrant_net")
    cur.execute("DELETE FROM roa_request_prefix")
    cur.execute("DELETE FROM roa_request")
    for s in [self] + self.hosts:
      for kid in s.kids:
        cur.execute("SELECT registrant_id FROM registrant WHERE registrant_handle = %s AND registry_handle = %s", (kid.name, s.name))
        registrant_id = cur.fetchone()[0]
        for as_range in kid.resources.asn:
          cur.execute("INSERT registrant_asn (start_as, end_as, registrant_id) VALUES (%s, %s, %s)", (as_range.min, as_range.max, registrant_id))
        for v4_range in kid.resources.v4:
          cur.execute("INSERT registrant_net (start_ip, end_ip, version, registrant_id) VALUES (%s, %s, 4, %s)", (v4_range.min, v4_range.max, registrant_id))
        for v6_range in kid.resources.v6:
          cur.execute("INSERT registrant_net (start_ip, end_ip, version, registrant_id) VALUES (%s, %s, 6, %s)", (v6_range.min, v6_range.max, registrant_id))
        cur.execute("UPDATE registrant SET valid_until = %s WHERE registrant_id = %s", (kid.resources.valid_until.to_sql(), registrant_id))
      for r in s.roa_requests:
        cur.execute("INSERT roa_request (roa_request_handle, asn) VALUES (%s, %s)", (s.name, r.asn))
        roa_request_id = cur.lastrowid
        for version, prefix_set in ((4, r.v4), (6, r.v6)):
          if prefix_set:
            cur.executemany("INSERT roa_request_prefix (roa_request_id, prefix, prefixlen, max_prefixlen, version) VALUES (%s, %s, %s, %s, %s)",
                            ((roa_request_id, x.prefix, x.prefixlen, x.max_prefixlen, version) for x in prefix_set))
    db.close()

  def run_daemons(self):
    """
    Run daemons for this entity.
    """
    rpki.log.info("Running daemons for %s" % self.name)
    self.rpkid_process = subprocess.Popen((prog_python, prog_rpkid, "-d", "-c", self.name + ".conf") + (("-p", self.name + ".prof") if profile else ()))
    self.irdbd_process = subprocess.Popen((prog_python, prog_irdbd, "-d", "-c", self.name + ".conf"))

  def kill_daemons(self):
    """
    Kill daemons for this entity.
    """
    rpki.log.info("Killing daemons for %s" % self.name)
    try:
      for proc in (self.rpkid_process, self.irdbd_process):
        try:
          rpki.log.info("Killing pid %d" % proc.pid)
          os.kill(proc.pid, signal.SIGTERM)
        except OSError:
          pass
        proc.wait()
    except AttributeError:
      pass

  def call_rpkid(self, pdus, cb):
    """
    Send a left-right message to this entity's RPKI daemon and return
    the response.

    If this entity is hosted (does not run its own RPKI daemon), all
    of this happens with the hosting RPKI daemon.
    """

    rpki.log.info("Calling rpkid for %s" % self.name)

    if self.is_hosted():
      rpki.log.info("rpkid %s is hosted by rpkid %s, switching" % (self.name, self.hosted_by.name))
      self = self.hosted_by
      assert not self.is_hosted()

    assert isinstance(pdus, (list, tuple))
    assert self.rpki_port is not None

    q_msg = rpki.left_right.msg.query(*pdus)
    q_cms = rpki.left_right.cms_msg()
    q_der = q_cms.wrap(q_msg, self.irbe_key, self.irbe_cert)
    q_url = "http://localhost:%d/left-right" % self.rpki_port

    rpki.log.debug(q_cms.pretty_print_content())

    def done(r_der):
      rpki.log.info("Callback from rpkid %s" % self.name)
      r_cms = rpki.left_right.cms_msg(DER = r_der)
      r_msg = r_cms.unwrap((self.rpkid_ta, self.rpkid_cert))
      rpki.log.debug(r_cms.pretty_print_content())
      assert r_msg.is_reply()
      for r_pdu in r_msg:
        assert not isinstance(r_pdu, rpki.left_right.report_error_elt)
      cb(r_msg)

    def lose(e):
      raise

    rpki.http.client(
      url          = q_url,
      msg          = q_der,
      callback     = done,
      errback      = lose)

  def cross_certify(self, certificant, reverse = False):
    """
    Cross-certify and return the resulting certificate.
    """

    if reverse:
      certifier = certificant
      certificant = self.name + "-SELF"
    elif self.is_leaf():
      certifier = self.name + "-TA"
    else:
      certifier = self.name + "-SELF"
    certfile = certifier + "-" + certificant + ".cer"

    rpki.log.info("Cross certifying %s into %s's BPKI (%s)" % (certificant, certifier, certfile))

    child = rpki.x509.X509(Auto_file = certificant + ".cer")
    parent = rpki.x509.X509(Auto_file = certifier + ".cer")
    keypair = rpki.x509.RSA(Auto_file = certifier + ".key")
    serial_file = certifier + ".srl"

    now = rpki.sundial.now()
    notAfter = now + rpki.sundial.timedelta(days = 30)

    try:
      f = open(serial_file, "r")
      serial = f.read()
      f.close()
      serial = int(serial.splitlines()[0], 16)
    except IOError:
      serial = 1

    x = parent.cross_certify(keypair, child, serial, notAfter, now)

    f = open(serial_file, "w")
    f.write("%02x\n" % (serial + 1))
    f.close()

    f = open(certfile, "w")
    f.write(x.get_PEM())
    f.close()

    rpki.log.debug("Cross certified (%s) issuer %s [%s] subject %s [%s]" % (certfile, x.getIssuer(), x.hAKI(), x.getSubject(), x.hSKI()))
    return x

  def create_rpki_objects(self, cb):
    """
    Create RPKI engine objects for this engine.

    Root node of the engine tree is special, it too has a parent but
    that one is the magic self-signed micro engine.

    The rest of this is straightforward.  There are a lot of objects
    to create, but we can do batch them all into one honking PDU, then
    issue one more PDU to set BSC EE certificates based on the PKCS
    #10 requests we get back when we tell rpkid to generate BSC keys.
    """

    assert not self.is_hosted() and not self.is_leaf()

    selves = [self] + self.hosts

    for i, s in enumerate(selves):
      rpki.log.info("Creating RPKI objects for [%d] %s" % (i, s.name))

    rpkid_pdus = []
    pubd_pdus = []

    for s in selves:

      rpkid_pdus.append(rpki.left_right.self_elt.make_pdu(
        action = "create",
        self_handle = s.name,
        crl_interval = s.crl_interval,
        regen_margin = s.regen_margin,
        bpki_cert = (s.cross_certify(s.hosted_by.name + "-TA", reverse = True)
                     if s.is_hosted() else
                     rpki.x509.X509(Auto_file = s.name + "-SELF.cer"))))

      rpkid_pdus.append(rpki.left_right.bsc_elt.make_pdu(
        action = "create",
        self_handle = s.name,
        bsc_handle = "b",
        generate_keypair = True))

      pubd_pdus.append(rpki.publication.client_elt.make_pdu(
        action = "create",
        client_handle = s.client_handle,
        base_uri = s.sia_base,
        bpki_cert = s.cross_certify(pubd_name + "-TA", reverse = True)))

      rpkid_pdus.append(rpki.left_right.repository_elt.make_pdu(
        action = "create",
        self_handle = s.name,
        bsc_handle = "b",
        repository_handle = "r",
        bpki_cert = s.cross_certify(pubd_name + "-TA"),
        peer_contact_uri = "http://localhost:%d/client/%s" % (pubd_port, s.client_handle)))

      for k in s.kids:
        rpkid_pdus.append(rpki.left_right.child_elt.make_pdu(
          action = "create",
          self_handle = s.name,
          child_handle = k.name,
          bsc_handle = "b",
          bpki_cert = s.cross_certify(k.name + ("-TA" if k.is_leaf() else "-SELF"))))

      if s.is_root():
        rootd_cert = s.cross_certify(rootd_name + "-TA")
        rpkid_pdus.append(rpki.left_right.parent_elt.make_pdu(
            action = "create",
            self_handle = s.name,
            parent_handle = "rootd",
            bsc_handle = "b",
            repository_handle = "r",
            sia_base = s.sia_base,
            bpki_cms_cert = rootd_cert,
            sender_name = s.name,
            recipient_name = "rootd",
            peer_contact_uri = "http://localhost:%s/" % rootd_port))
      else:
        rpkid_pdus.append(rpki.left_right.parent_elt.make_pdu(
          action = "create",
          self_handle = s.name,
          parent_handle = s.parent.name,
          bsc_handle = "b",
          repository_handle = "r",
          sia_base = s.sia_base,
          bpki_cms_cert = s.cross_certify(s.parent.name + "-SELF"),
          sender_name = s.name,
          recipient_name = s.parent.name,
          peer_contact_uri = "http://localhost:%s/up-down/%s/%s" % (s.parent.get_rpki_port(), s.parent.name, s.name)))

    def one():
      call_pubd(pubd_pdus, cb = two)

    def two(vals):
      self.call_rpkid(rpkid_pdus, cb = three)

    def three(vals):

      bsc_dict = dict((b.self_handle, b) for b in vals if isinstance(b, rpki.left_right.bsc_elt))

      bsc_pdus = []

      for s in selves:
        b = bsc_dict[s.name]

        rpki.log.info("Issuing BSC EE cert for %s" % s.name)
        cmd = (prog_openssl, "x509", "-req", "-sha256", "-extfile", s.name + "-RPKI.conf", "-extensions", "req_x509_ext", "-days", "30",
               "-CA", s.name + "-SELF.cer", "-CAkey",    s.name + "-SELF.key", "-CAcreateserial", "-text")
        signer = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
        signed = signer.communicate(input = b.pkcs10_request.get_PEM())
        if not signed[0]:
          rpki.log.warn(signed[1])
          raise RuntimeError, "Couldn't issue BSC EE certificate"
        s.bsc_ee = rpki.x509.X509(PEM = signed[0])
        s.bsc_crl = rpki.x509.CRL(PEM_file = s.name + "-SELF.crl")
        rpki.log.info("BSC EE cert for %s SKI %s" % (s.name, s.bsc_ee.hSKI()))

        bsc_pdus.append(rpki.left_right.bsc_elt.make_pdu(
          action = "set",
          self_handle = s.name,
          bsc_handle = "b",
          signing_cert = s.bsc_ee,
          signing_cert_crl = s.bsc_crl))

      self.call_rpkid(bsc_pdus, cb = four)

    def four(vals):
      cb()

    one()

  def setup_yaml_leaf(self):
    """
    Generate certificates and write YAML scripts for leaf nodes.

    We're cheating a bit here: properly speaking, we can't generate
    issue or revoke requests without knowing the class, which is
    generated on the fly, but at the moment the test case is
    simplistic enough that the class will always be "1", so we just
    wire in that value for now.

    Well, ok, we just broke that assumption.  Now we do something even
    nastier, just to eke a bit more life out of this kludge.  This
    really needs to be rewritten, but it may require a different tool
    than testpoke.
    """

    if not os.path.exists(self.name + ".key"):
      rpki.log.info("Generating RPKI key for %s" % self.name)
      subprocess.check_call((prog_openssl, "genrsa", "-out", self.name + ".key", "2048" ),
                            stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
    ski = rpki.x509.RSA(PEM_file = self.name + ".key").gSKI()

    if self.parent.is_hosted():
      parent_host = self.parent.hosted_by.name
    else:
      parent_host = self.parent.name

    self.cross_certify(self.parent.name + "-SELF")
    self.cross_certify(parent_host + "-TA")

    rpki.log.info("Writing leaf YAML for %s" % self.name)
    f = open(self.name + ".yaml", "w")
    f.write(yaml_fmt_1 % {
      "parent_name"  : self.parent.name,
      "parent_host"  : parent_host,
      "my_name"      : self.name,
      "http_port"    : self.parent.get_rpki_port(),
      "class_name"   : 2 if self.parent.is_hosted() else 1,
      "sia"          : self.sia_base,
      "ski"          : ski })
    f.close()

  def run_cron(self, cb):
    """
    Trigger cron run for this engine.
    """

    rpki.log.info("Running cron for %s" % self.name)

    assert self.rpki_port is not None

    def done(result):
      assert result == "OK", 'Expected "OK" result from cronjob, got %r' % result
      cb()

    rpki.http.client(
      url      = "http://localhost:%d/cronjob" % self.rpki_port,
      msg      = "Run cron now, please",
      callback = done,
      errback  = done)

  def run_yaml(self):
    """
    Run YAML scripts for this leaf entity.  Since we're not bothering
    to check the class list returned by the list command, the issue
    command may fail, so we treat failure of the list command as an
    error, but only issue a warning when issue fails.
    """

    rpki.log.info("Running YAML for %s" % self.name)
    subprocess.check_call((prog_python, prog_poke, "-y", self.name + ".yaml", "-r", "list"))
    if subprocess.call((prog_python, prog_poke, "-y", self.name + ".yaml", "-r", "issue")) != 0:
      rpki.log.warn("YAML issue command failed for %s, continuing" % self.name)

def setup_bpki_cert_chain(name, ee = (), ca = ()):
  """
  Build a set of BPKI certificates.
  """
  s = "exec >/dev/null 2>&1\n"
  #s = "set -x\n"
  for kind in ("TA",) + ee + ca:
    d = { "name"    : name,
          "kind"    : kind,
          "ca"      : "false" if kind in ee else "true",
          "openssl" : prog_openssl }
    f = open("%(name)s-%(kind)s.conf" % d, "w")
    f.write(bpki_cert_fmt_1 % d)
    f.close()
    if not os.path.exists("%(name)s-%(kind)s.key" % d):
      s += bpki_cert_fmt_2 % d
    s += bpki_cert_fmt_3 % d
  d = { "name" : name, "openssl" : prog_openssl }
  s += bpki_cert_fmt_4 % d
  for kind in ee + ca:
    d["kind"] =  kind
    s += bpki_cert_fmt_5 % d
  for kind in ("TA",) + ca:
    d["kind"] =  kind
    s += bpki_cert_fmt_6 % d
  subprocess.check_call(s, shell = True)

def setup_rootd(rpkid, rootd_yaml):
  """
  Write the config files for rootd.
  """
  rpkid.cross_certify(rootd_name + "-TA", reverse = True)
  rpki.log.info("Writing config files for %s" % rootd_name)
  d = { "rootd_name" : rootd_name,
        "rootd_port" : rootd_port,
        "rpkid_name" : rpkid.name,
        "rootd_sia"  : rootd_sia,
        "rsyncd_dir" : rsyncd_dir,
        "openssl"    : prog_openssl,
        "lifetime"   : rootd_yaml.get("lifetime", "30d") }
  f = open(rootd_name + ".conf", "w")
  f.write(rootd_fmt_1 % d)
  f.close()
  s = "exec >/dev/null 2>&1\n"
  #s = "set -x\n"
  if not os.path.exists(rootd_name + ".key"):
    s += rootd_fmt_2 % d
  s += rootd_fmt_3 % d
  subprocess.check_call(s, shell = True)

def setup_rcynic():
  """
  Write the config file for rcynic.
  """
  rpki.log.info("Config file for rcynic")
  d = { "rcynic_name" : rcynic_name,
        "rootd_name"  : rootd_name,
        "rootd_sia"   : rootd_sia }
  f = open(rcynic_name + ".conf", "w")
  f.write(rcynic_fmt_1 % d)
  f.close()

def setup_rsyncd():
  """
  Write the config file for rsyncd.
  """
  rpki.log.info("Config file for rsyncd")
  d = { "rsyncd_name"   : rsyncd_name,
        "rsyncd_port"   : rsyncd_port,
        "rsyncd_module" : rsyncd_module,
        "rsyncd_dir"    : rsyncd_dir }
  f = open(rsyncd_name + ".conf", "w")
  f.write(rsyncd_fmt_1 % d)
  f.close()

def setup_publication(pubd_sql):
  """
  Set up publication daemon.
  """
  rpki.log.info("Configure publication daemon")
  pubd_dir = os.getcwd() + "/publication/"
  assert rootd_sia.startswith("rsync://")
  i = 0
  for j in xrange(4):
    i = rootd_sia.index("/", i + 1)
  global rsyncd_dir
  rsyncd_dir = pubd_dir.rstrip("/") + rootd_sia[i:]
  os.makedirs(rsyncd_dir)
  db = MySQLdb.connect(db = pubd_db_name, user = pubd_db_user, passwd = pubd_db_pass)
  cur = db.cursor()
  db.autocommit(True)
  for sql in pubd_sql:
    cur.execute(sql)
  db.close()
  d = { "pubd_name"    : pubd_name,
        "pubd_port"    : pubd_port,
        "pubd_db_name" : pubd_db_name,
        "pubd_db_user" : pubd_db_user,
        "pubd_db_pass" : pubd_db_pass,
        "pubd_dir"     : pubd_dir }
  f = open(pubd_name + ".conf", "w")
  f.write(pubd_fmt_1 % d)
  f.close()
  global pubd_ta
  global pubd_irbe_key
  global pubd_irbe_cert
  global pubd_pubd_cert
  pubd_ta        = rpki.x509.X509(Auto_file = pubd_name + "-TA.cer")
  pubd_irbe_key  = rpki.x509.RSA( Auto_file = pubd_name + "-IRBE.key")
  pubd_irbe_cert = rpki.x509.X509(Auto_file = pubd_name + "-IRBE.cer")
  pubd_pubd_cert = rpki.x509.X509(Auto_file = pubd_name + "-PUBD.cer")

def call_pubd(pdus, cb):
  """
  Send a publication message to publication daemon and return the
  response.
  """
  rpki.log.info("Calling pubd")
  q_msg = rpki.publication.msg.query(*pdus)
  q_cms = rpki.publication.cms_msg()
  q_der = q_cms.wrap(q_msg, pubd_irbe_key, pubd_irbe_cert)
  q_url = "http://localhost:%d/control" % pubd_port

  rpki.log.debug(q_cms.pretty_print_content())

  def call_pubd_cb(r_der):
    r_cms = rpki.publication.cms_msg(DER = r_der)
    r_msg = r_cms.unwrap((pubd_ta, pubd_pubd_cert))
    rpki.log.debug(r_cms.pretty_print_content())
    assert r_msg.is_reply()
    for r_pdu in r_msg:
      assert not isinstance(r_pdu, rpki.publication.report_error_elt)
    cb(r_msg)

  def call_pubd_eb(e):
    rpki.log.warn("Problem calling pubd: %s" % e)
    rpki.log.traceback()

  rpki.http.client(
    url          = q_url,
    msg          = q_der,
    callback     = call_pubd_cb,
    errback      = call_pubd_eb)

def set_pubd_crl(cb):
  """
  Whack publication daemon's bpki_crl.  This must be configured before
  publication daemon starts talking to its clients, and must be
  updated whenever we update the CRL.
  """
  rpki.log.info("Setting pubd's BPKI CRL")
  call_pubd([rpki.publication.config_elt.make_pdu(action = "set", bpki_crl = rpki.x509.CRL(Auto_file = pubd_name + "-TA.crl"))],
            cb = lambda ignored: cb())

def run_rcynic():
  """
  Run rcynic to see whether what was published makes sense.
  """
  rpki.log.info("Running rcynic")
  env = os.environ.copy()
  env["TZ"] = ""
  subprocess.check_call((prog_rcynic, "-c", rcynic_name + ".conf"), env = env)
  subprocess.call(rcynic_stats, shell = True, env = env)

def mangle_sql(filename):
  """
  Mangle an SQL file into a sequence of SQL statements.
  """
  
  # There is no pretty way to do this.  Just shut your eyes, it'll be
  # over soon.
  
  f = open(filename)
  statements = " ".join(" ".join(word for word in line.expandtabs().split(" ") if word)
                        for line in [line.strip(" \t\n") for line in f.readlines()]
                        if line and not line.startswith("--")).rstrip(";").split(";")
  f.close()
  return [stmt.strip() for stmt in statements]

bpki_cert_fmt_1 = '''\
[ req ]
distinguished_name      = req_dn
x509_extensions         = req_x509_ext
prompt                  = no
default_md              = sha256

[ req_dn ]
CN                      = Test Certificate %(name)s %(kind)s

[ req_x509_ext ]
basicConstraints        = critical,CA:%(ca)s
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always


[ ca ]
default_ca = ca_default

[ ca_default ]

certificate             = %(name)s-%(kind)s.cer
serial                  = %(name)s-%(kind)s.srl
private_key             = %(name)s-%(kind)s.key
database                = %(name)s-%(kind)s.idx
crlnumber               = %(name)s-%(kind)s.cnm
default_crl_days        = 30
default_md              = sha256
'''

bpki_cert_fmt_2 = '''\
%(openssl)s genrsa -out %(name)s-%(kind)s.key 2048 &&
'''

bpki_cert_fmt_3 = '''\
%(openssl)s req -new -sha256 -key %(name)s-%(kind)s.key -out %(name)s-%(kind)s.req -config %(name)s-%(kind)s.conf &&
touch %(name)s-%(kind)s.idx &&
echo >%(name)s-%(kind)s.cnm 01 &&
'''

bpki_cert_fmt_4 = '''\
%(openssl)s x509 -req -sha256 -in %(name)s-TA.req -out %(name)s-TA.cer -extfile %(name)s-TA.conf -extensions req_x509_ext -signkey %(name)s-TA.key -days 60 -text \
'''

bpki_cert_fmt_5 = ''' && \
%(openssl)s x509 -req -sha256 -in %(name)s-%(kind)s.req -out %(name)s-%(kind)s.cer -extfile %(name)s-%(kind)s.conf -extensions req_x509_ext -days 30 -text \
                     -CA %(name)s-TA.cer -CAkey %(name)s-TA.key -CAcreateserial \
'''

bpki_cert_fmt_6 = ''' && \
%(openssl)s ca -batch -gencrl -out %(name)s-%(kind)s.crl -config %(name)s-%(kind)s.conf \
'''

yaml_fmt_1 = '''---
version:                1
posturl:                http://localhost:%(http_port)s/up-down/%(parent_name)s/%(my_name)s
recipient-id:           "%(parent_name)s"
sender-id:              "%(my_name)s"

cms-cert-file:          %(my_name)s-RPKI.cer
cms-key-file:           %(my_name)s-RPKI.key
cms-ca-cert-file:       %(my_name)s-TA.cer
cms-crl-file:           %(my_name)s-TA.crl
cms-ca-certs-file:
  -                     %(my_name)s-TA-%(parent_name)s-SELF.cer

ssl-cert-file:          %(my_name)s-RPKI.cer
ssl-key-file:           %(my_name)s-RPKI.key
ssl-ca-cert-file:       %(my_name)s-TA.cer
ssl-ca-certs-file:
  -                     %(my_name)s-TA-%(parent_host)s-TA.cer

# We're cheating here by hardwiring the class name

requests:
  list:
    type:                       list
  issue:
    type:                       issue
    class:                      %(class_name)s
    sia:
      -                         %(sia)s
    cert-request-key-file:      %(my_name)s.key
  revoke:
    type:                       revoke
    class:                      %(class_name)s
    ski:                        %(ski)s
'''

conf_fmt_1 = '''\

[irdbd]

startup-message = This is %(my_name)s irdbd

sql-database    = %(irdb_db_name)s
sql-username    = irdb
sql-password    = %(irdb_db_pass)s
bpki-ta         = %(my_name)s-TA.cer
rpkid-cert      = %(my_name)s-RPKI.cer
irdbd-cert      = %(my_name)s-IRDB.cer
irdbd-key       = %(my_name)s-IRDB.key
http-url       = http://localhost:%(irdb_port)d/

[irbe_cli]

rpkid-bpki-ta   = %(my_name)s-TA.cer
rpkid-cert      = %(my_name)s-RPKI.cer
rpkid-irbe-cert = %(my_name)s-IRBE.cer
rpkid-irbe-key  = %(my_name)s-IRBE.key
rpkid-url       = http://localhost:%(rpki_port)d/left-right

[rpkid]

startup-message = This is %(my_name)s rpkid

sql-database    = %(rpki_db_name)s
sql-username    = rpki
sql-password    = %(rpki_db_pass)s

bpki-ta         = %(my_name)s-TA.cer
rpkid-key       = %(my_name)s-RPKI.key
rpkid-cert      = %(my_name)s-RPKI.cer
irdb-cert       = %(my_name)s-IRDB.cer
irbe-cert       = %(my_name)s-IRBE.cer

irdb-url        = http://localhost:%(irdb_port)d/

server-host     = localhost
server-port     = %(rpki_port)d

use-internal-cron = false
'''

rootd_fmt_1 = '''\

[rootd]

bpki-ta                 = %(rootd_name)s-TA.cer
rootd-bpki-cert         = %(rootd_name)s-RPKI.cer
rootd-bpki-key          = %(rootd_name)s-RPKI.key
rootd-bpki-crl          = %(rootd_name)s-TA.crl
child-bpki-cert         = %(rootd_name)s-TA-%(rpkid_name)s-SELF.cer

server-port             = %(rootd_port)s

rpki-root-dir           = %(rsyncd_dir)s
rpki-base-uri           = %(rootd_sia)s
rpki-root-cert-uri      = %(rootd_sia)s%(rootd_name)s.cer

rpki-root-key           = %(rootd_name)s.key
rpki-root-cert          = %(rootd_name)s.cer

rpki-subject-pkcs10     = %(rootd_name)s.subject.pkcs10
rpki-subject-lifetime   = %(lifetime)s

rpki-root-crl           = Bandicoot.crl
rpki-root-manifest      = Bandicoot.mnf

rpki-class-name         = Wombat
rpki-subject-cert       = Wombat.cer

[req]
default_bits            = 2048
encrypt_key             = no
distinguished_name      = req_dn
#req_extensions          = req_x509_ext
prompt                  = no
default_md              = sha256
default_days            = 60

[req_dn]
CN                      = Completely Bogus Test Root (NOT FOR PRODUCTION USE)

[req_x509_ext]
basicConstraints        = critical,CA:true
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always

[req_x509_rpki_ext]
basicConstraints        = critical,CA:true
subjectKeyIdentifier    = hash
keyUsage                = critical,keyCertSign,cRLSign
subjectInfoAccess       = 1.3.6.1.5.5.7.48.5;URI:%(rootd_sia)s,1.3.6.1.5.5.7.48.10;URI:%(rootd_sia)sBandicoot.mnf
sbgp-autonomousSysNum   = critical,AS:0-4294967295
sbgp-ipAddrBlock        = critical,IPv4:0.0.0.0/0,IPv6:0::/0
certificatePolicies     = critical, @rpki_certificate_policy

[rpki_certificate_policy]

policyIdentifier = 1.3.6.1.5.5.7.14.2
'''

rootd_fmt_2 = '''\
%(openssl)s genrsa -out %(rootd_name)s.key 2048 &&
'''

rootd_fmt_3 = '''\
%(openssl)s rsa -pubout -outform DER -in %(rootd_name)s.key -out %(rootd_name)s.pkey  &&
%(openssl)s req -new -sha256 -key %(rootd_name)s.key -out %(rootd_name)s.req -config %(rootd_name)s.conf -text -extensions req_x509_rpki_ext &&
%(openssl)s x509 -req -sha256 -in %(rootd_name)s.req -out %(rootd_name)s.cer -outform DER -extfile %(rootd_name)s.conf -extensions req_x509_rpki_ext \
                      -signkey %(rootd_name)s.key &&
ln -f %(rootd_name)s.cer  %(rsyncd_dir)s
'''

rcynic_fmt_1 = '''\
[rcynic]
xml-summary             = %(rcynic_name)s.xml
jitter                  = 0
use-links               = yes
use-syslog              = no
use-stderr              = yes
log-level               = log_debug
#trust-anchor            = %(rootd_name)s.cer
trust-anchor-uri-with-key = %(rootd_sia)s%(rootd_name)s.cer %(rootd_name)s.pkey
'''

rsyncd_fmt_1 = '''\
port                    = %(rsyncd_port)d
address                 = localhost

[%(rsyncd_module)s]
read only               = yes
transfer logging        = yes
use chroot              = no
path                    = %(rsyncd_dir)s
comment                 = RPKI test
'''

pubd_fmt_1 = '''\
[pubd]

sql-database            = %(pubd_db_name)s
sql-username            = %(pubd_db_user)s
sql-password            = %(pubd_db_pass)s
bpki-ta                 = %(pubd_name)s-TA.cer
pubd-cert               = %(pubd_name)s-PUBD.cer
pubd-key                = %(pubd_name)s-PUBD.key
irbe-cert               = %(pubd_name)s-IRBE.cer
server-host             = localhost
server-port             = %(pubd_port)d
publication-base        = %(pubd_dir)s
'''

main()
