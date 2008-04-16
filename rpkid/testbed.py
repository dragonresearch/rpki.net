# $Id$

# Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
Test framework to configure and drive a collection of rpkid.py and
irdbd.py instances under control of a master script.

Usage: python rpkid.py [ { -c | --config } config_file ]
                       [ { -h | --help } ]
                       [ { -y | --yaml }   yaml_script ]

Default config_file is testbed.conf, override with --config option.

Default yaml_script is testbed.yaml, override with -yaml option.

yaml_script is a YAML file describing the tests to be run, and is
intended to be implementation agnostic.

config_file contains settings for various implementation-specific
things that don't belong in yaml_script.
"""

import os, yaml, MySQLdb, subprocess, signal, time, datetime, re, getopt, sys, lxml
import rpki.resource_set, rpki.sundial, rpki.x509, rpki.https, rpki.log, rpki.left_right, rpki.config

os.environ["TZ"] = "UTC"
time.tzset()

cfg_file = "testbed.conf"

yaml_script = None

opts,argv = getopt.getopt(sys.argv[1:], "c:hy:?", ["config=", "help", "yaml="])
for o,a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  elif o in ("-c", "--config"):
    cfg_file = a
  elif o in ("-y", "--yaml"):
    yaml_script = a
if argv:
  print __doc__
  raise RuntimeError, "Unexpected arguments %s" % argv

cfg = rpki.config.parser(cfg_file, "testbed")

# Load the YAML script early, so we can report errors ASAP

if yaml_script is None:
  yaml_script  = cfg.get("yaml_script", "testbed.yaml")
try:
  yaml_script = [y for y in yaml.safe_load_all(open(yaml_script))]
except:
  print __doc__
  raise

# Define port allocator early, so we can use it while reading config

def allocate_port():
  """Allocate a TCP port number."""
  global base_port
  p = base_port
  base_port += 1
  return p

# Most filenames in the following are relative to the working directory.

testbed_name   = cfg.get("testbed_name",   "testbed")
testbed_dir    = cfg.get("testbed_dir",    testbed_name + ".dir")

irdb_db_pass   = cfg.get("irdb_db_pass",   "fnord")
rpki_db_pass   = cfg.get("rpki_db_pass",   "fnord")

base_port      = int(cfg.get("base_port",  "4400"))

rsyncd_port    = allocate_port()
rootd_port     = allocate_port()

rsyncd_module  = cfg.get("rsyncd_module",  testbed_name)
rootd_sia      = cfg.get("rootd_sia",      "rsync://localhost:%d/%s/" % (rsyncd_port, rsyncd_module))

rootd_name     = cfg.get("rootd_name",     "rootd")
rsyncd_name    = cfg.get("rcynic_name",    "rsyncd")
rcynic_name    = cfg.get("rcynic_name",    "rcynic")

prog_python    = cfg.get("prog_python",    "python")
prog_rpkid     = cfg.get("prog_rpkid",     "../rpkid.py")
prog_irdbd     = cfg.get("prog_irdbd",     "../irdbd.py")
prog_poke      = cfg.get("prog_poke",      "../testpoke.py")
prog_rootd     = cfg.get("prog_rootd",     "../rootd.py")
prog_openssl   = cfg.get("prog_openssl",   "../../openssl/openssl/apps/openssl")
prog_rsyncd    = cfg.get("prog_rsyncd",    "rsync")
prog_rcynic    = cfg.get("prog_rcynic",    "../../rcynic/rcynic")

rcynic_stats   = cfg.get("rcynic_stats",   "xsltproc --param refresh 0 ../../rcynic/rcynic.xsl %s.xml | w3m -T text/html -dump" % rcynic_name)

rpki_sql_file  = cfg.get("rpki_sql_file",  "../docs/rpki-db-schema.sql")
irdb_sql_file  = cfg.get("irdb_sql_file",  "../docs/sample-irdb.sql")

testbed_key    = None
testbed_certs  = None
rootd_ta       = None

startup_delay  = int(cfg.get("startup_delay", "10"))

def main():
  """Main program, up front to make control logic more obvious."""

  rpki.log.init(testbed_name)
  rpki.log.info("Starting")

  signal.signal(signal.SIGALRM, wakeup)

  rootd_process = None
  rsyncd_process = None

  rpki_sql = mangle_sql(rpki_sql_file)
  irdb_sql = mangle_sql(irdb_sql_file)

  try:
    os.chdir(testbed_dir)
  except:
    os.makedirs(testbed_dir)
    os.chdir(testbed_dir)

  rpki.log.info("Cleaning up old state")
  subprocess.check_call(("rm", "-rf", "publication", "rcynic-data", "rootd.subject.pkcs10", "rootd.req"))

  rpki.log.info("Reading master YAML configuration")
  db = allocation_db(yaml_script.pop(0))

  rpki.log.info("Constructing biz keys and certs for control script")
  setup_biz_cert_chain(testbed_name)
  global testbed_key, testbed_certs
  testbed_key = rpki.x509.RSA(PEM_file = testbed_name + "-EE.key")
  testbed_certs = rpki.x509.X509_chain(PEM_files = (testbed_name + "-EE.cer", testbed_name + "-CA.cer"))

  rpki.log.info("Constructing biz keys and certs for rootd")
  setup_biz_cert_chain(rootd_name)
  global rootd_ta
  rootd_ta = rpki.x509.X509(PEM_file = rootd_name + "-TA.cer")

  for a in db:
    a.setup_biz_certs()

  setup_publication()
  setup_rootd(db.root.name)
  setup_rsyncd()
  setup_rcynic()

  for a in db.engines:
    a.setup_conf_file()
    a.setup_sql(rpki_sql, irdb_sql)
    a.sync_sql()

  try:

    rpki.log.info("Starting rootd")
    rootd_process = subprocess.Popen((prog_python, prog_rootd, "-c", rootd_name + ".conf"))

    rpki.log.info("Starting rsyncd")
    rsyncd_process = subprocess.Popen((prog_rsyncd, "--daemon", "--no-detach", "--config", rsyncd_name + ".conf"))

    # Start rpkid and irdbd instances
    for a in db.engines:
      a.run_daemons()

    rpki.log.info("Sleeping %d seconds while daemons start up" % startup_delay)
    time.sleep(startup_delay)

    # Create objects in RPKI engines
    for a in db.engines:
      a.create_rpki_objects()

    # Write YAML files for leaves
    for a in db.leaves:
      a.write_leaf_yaml()

    # Loop until we run out of control YAML
    while True:

      # Run cron in all RPKI instances
      for a in db.engines:
        a.run_cron()

      # Run all YAML clients
      for a in db.leaves:
        a.run_yaml()

      # Run rcynic to check results
      run_rcynic()

      # If we've run out of deltas to apply, we're done
      if not yaml_script:
        rpki.log.info("No more deltas to apply, done")
        break

      rpki.log.info("Applying deltas")
      db.apply_delta(yaml_script.pop(0))

      # Resync IRDBs
      for a in db.engines:
        a.sync_sql()

  # Clean up

  finally:

    try:
      rpki.log.info("Shutting down")
      for a in db.engines:
        a.kill_daemons()
      for p,n in ((rootd_process, "rootd"), (rsyncd_process, "rsyncd")):
        if p is not None:
          rpki.log.info("Killing %s" % n)
          os.kill(p.pid, signal.SIGTERM)
    except Exception, data:
      rpki.log.warn("Couldn't clean up daemons (%s), continuing" % data)

# Define time delta parser early, so we can use it while reading config

class timedelta(datetime.timedelta):
  """Timedelta with text parsing.  This accepts two input formats:

  - A simple integer, indicating a number of seconds.

  - A string of the form "wD xH yM zS" where w, x, y, and z are integers
    and D, H, M, and S indicate days, hours, minutes, and seconds.
    All of the fields are optional, but at least one must be specified.
    Eg, "3D4H" means "three days plus four hours".
  """

  ## @var regexp
  # Hideously ugly regular expression to parse the complex text form.
  # Tags are intended for use with re.MatchObject.groupdict() and map
  # directly to the keywords expected by the timedelta constructor.

  regexp = re.compile("\\s*(?:(?P<days>\\d+)D)?" +
                      "\\s*(?:(?P<hours>\\d+)H)?" +
                      "\\s*(?:(?P<minutes>\\d+)M)?" +
                      "\\s*(?:(?P<seconds>\\d+)S)?\\s*", re.I)

  @classmethod
  def parse(cls, arg):
    """Parse text into a timedelta object."""
    if not isinstance(arg, str):
      return cls(seconds = arg)
    elif arg.isdigit():
      return cls(seconds = int(arg))
    else:
      return cls(**dict((k, int(v)) for (k, v) in cls.regexp.match(arg).groupdict().items() if v is not None))

  def convert_to_seconds(self):
    """Convert a timedelta interval to seconds."""
    return self.days * 24 * 60 * 60 + self.seconds

def wakeup(signum, frame):
  """Handler called when we receive a SIGALRM signal."""
  rpki.log.info("Wakeup call received, continuing")

def cmd_sleep(interval = None):
  """Set an alarm, then wait for it to go off."""
  if interval is None:
    rpki.log.info("Pausing indefinitely, send a SIGALRM to wake me up")
  else:
    seconds = timedelta.parse(interval).convert_to_seconds()
    rpki.log.info("Sleeping %s seconds" % seconds)
    signal.alarm(seconds)
  signal.pause()

def cmd_shell(*cmd):
  """Run a shell command."""
  cmd = " ".join(cmd)
  status = subprocess.call(cmd, shell = True)
  rpki.log.info("Shell command returned status %d" % status)

def cmd_echo(*words):
  """Echo some text to the log."""
  rpki.log.note(" ".join(words))

## @var cmds
# Dispatch table for commands embedded in delta sections

cmds = { "sleep" : cmd_sleep,
         "shell" : cmd_shell,
         "echo"  : cmd_echo }

class route_origin(object):
  """Representation for a route_origin object."""

  def __init__(self, asn, ipv4, ipv6, exact_match):
    self.asn = asn
    self.v4 = rpki.resource_set.resource_set_ipv4("".join(ipv4.split())) if ipv4 else None
    self.v6 = rpki.resource_set.resource_set_ipv6("".join(ipv6.split())) if ipv6 else None
    self.exact_match = exact_match

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
    return cls(yaml.get("asn"), yaml.get("ipv4"), yaml.get("ipv6"), yaml.get("exact_match", False))
    
class allocation_db(list):
  """Representation of all the entities and allocations in the test system.
  Almost everything is generated out of this database.
  """

  def __init__(self, yaml):
    """Initialize database from the (first) YAML document."""
    self.root = allocation(yaml, self)
    assert self.root.is_root()
    if self.root.crl_interval is None:
      self.root.crl_interval = timedelta.parse(cfg.get("crl_interval", "1d")).convert_to_seconds()
    if self.root.regen_margin is None:
      self.root.regen_margin = timedelta.parse(cfg.get("regen_margin", "1d")).convert_to_seconds()
    for a in self:
      if a.sia_base is None:
        a.sia_base = (rootd_sia if a.is_root() else a.parent.sia_base) + a.name + "/"
      if a.base.valid_until is None:
        a.base.valid_until = a.parent.base.valid_until
      if a.crl_interval is None:
        a.crl_interval = a.parent.crl_interval
      if a.regen_margin is None:
        a.regen_margin = a.parent.regen_margin
    self.root.closure()
    self.map = dict((a.name, a) for a in self)
    self.engines = [a for a in self if not a.is_leaf()]
    self.leaves = [a for a in self if a.is_leaf()]
    for i, a in zip(range(len(self.engines)), self.engines):
      a.set_engine_number(i)

  def apply_delta(self, delta):
    """Apply a delta or run a command."""
    for d in delta:
      if isinstance(d, str):
        c = d.split()
        cmds[c[0]](*c[1:])
      else:
        self.map[d["name"]].apply_delta(d)
    self.root.closure()

  def dump(self):
    """Print content of the database."""
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
    """Initialize one entity and insert it into the database."""
    db.append(self)
    self.name = yaml["name"]
    self.parent = parent
    self.kids = [allocation(k, db, self) for k in yaml.get("kids", ())]
    valid_until = yaml.get("valid_until")
    if valid_until is None and "valid_for" in yaml:
      valid_until = datetime.datetime.utcnow() + timedelta.parse(yaml["valid_for"])
    self.base = rpki.resource_set.resource_bag(
      as = rpki.resource_set.resource_set_as(yaml.get("asn")),
      v4 = rpki.resource_set.resource_set_ipv4(yaml.get("ipv4")),
      v6 = rpki.resource_set.resource_set_ipv6(yaml.get("ipv6")),
      valid_until = valid_until)
    self.sia_base = yaml.get("sia_base")
    if "crl_interval" in yaml:
      self.crl_interval = timedelta.parse(yaml["crl_interval"]).convert_to_seconds()
    if "regen_margin" in yaml:
      self.regen_margin = timedelta.parse(yaml["regen_margin"]).convert_to_seconds()
    self.route_origins = set()
    if "route_origin" in yaml:
      for y in yaml.get("route_origin"):
        self.route_origins.add(route_origin.parse(y))
    self.extra_conf = yaml.get("extra_conf", [])

  def closure(self):
    """Compute the transitive resource closure."""
    resources = self.base
    for kid in self.kids:
      resources = resources.union(kid.closure())
    self.resources = resources
    return resources

  def apply_delta(self, yaml):
    """Apply deltas to this entity."""
    rpki.log.info("Applying delta: %s" % yaml)
    for k,v in yaml.items():
      if k != "name":
        getattr(self, "apply_" + k)(v)

  def apply_add_as(self, text): self.base.as = self.base.as.union(rpki.resource_set.resource_set_as(text))
  def apply_add_v4(self, text): self.base.v4 = self.base.v4.union(rpki.resource_set.resource_set_ipv4(text))
  def apply_add_v6(self, text): self.base.v6 = self.base.v6.union(rpki.resource_set.resource_set_ipv6(text))
  def apply_sub_as(self, text): self.base.as = self.base.as.difference(rpki.resource_set.resource_set_as(text))
  def apply_sub_v4(self, text): self.base.v4 = self.base.v4.difference(rpki.resource_set.resource_set_ipv4(text))
  def apply_sub_v6(self, text): self.base.v6 = self.base.v6.difference(rpki.resource_set.resource_set_ipv6(text))

  def apply_valid_until(self, stamp): self.base.valid_until = stamp
  def apply_valid_for(self, text):    self.base.valid_until = datetime.datetime.utcnow() + timedelta.parse(text)
  def apply_valid_add(self, text):    self.base.valid_until += timedelta.parse(text)
  def apply_valid_sub(self, text):    self.base.valid_until -= timedelta.parse(text)

  def apply_route_origin_add(self, yaml):
    for y in yaml:
      self.route_origins.add(route_origin.parse(y))

  def apply_route_origin_del(self, yaml):
    for y in yaml:
      self.route_origins.remove(route_origin.parse(y))

  def apply_rekey(self, target):
    if self.is_leaf():
      raise RuntimeError, "Can't rekey YAML leaf %s, sorry" % self.name
    elif target is None:
      rpki.log.info("Rekeying <self/> %s" % self.name)
      self.call_rpkid(rpki.left_right.self_elt.make_pdu(action = "set", self_id = self.self_id, rekey = "yes"))
    else:
      rpki.log.info("Rekeying <parent/> %s %s" % (self.name, target))
      self.call_rpkid(rpki.left_right.parent_elt.make_pdu(action = "set", self_id = self.self_id, parent_id = target, rekey = "yes"))

  def apply_revoke(self, target):
    if self.is_leaf():
      rpki.log.info("Attempting to revoke YAML leaf %s" % self.name)
      subprocess.check_call((prog_python, prog_poke, "-y", self.name + ".yaml", "-r", "revoke", "-d"))
    elif target is None:
      rpki.log.info("Revoking <self/> %s" % self.name)
      self.call_rpkid(rpki.left_right.self_elt.make_pdu(action = "set", self_id = self.self_id, revoke = "yes"))
    else:
      rpki.log.info("Revoking <parent/> %s %s" % (self.name, target))
      self.call_rpkid(rpki.left_right.parent_elt.make_pdu(action = "set", self_id = self.self_id, parent_id = target, revoke = "yes"))

  def __str__(self):
    s = self.name + "\n"
    if self.resources.as:       s += "  ASN: %s\n" % self.resources.as
    if self.resources.v4:       s += " IPv4: %s\n" % self.resources.v4
    if self.resources.v6:       s += " IPv6: %s\n" % self.resources.v6
    if self.kids:               s += " Kids: %s\n" % ", ".join(k.name for k in self.kids)
    if self.parent:             s += "   Up: %s\n" % self.parent.name
    if self.sia_base:           s += "  SIA: %s\n" % self.sia_base
    return s + "Until: %s\n" % self.resources.valid_until.strftime("%Y-%m-%dT%H:%M:%SZ")

  def is_leaf(self): return not self.kids and not self.route_origins
  def is_root(self): return self.parent is None
  def is_twig(self): return not self.is_leaf() and not self.is_root()

  def set_engine_number(self, n):
    """Set the engine number for this entity."""
    self.irdb_db_name = "irdb%d" % n
    self.irdb_port    = allocate_port()
    self.rpki_db_name = "rpki%d" % n
    self.rpki_port    = allocate_port()

  def setup_biz_certs(self):
    """Create business certs for this entity."""
    rpki.log.info("Constructing biz keys and certs for %s" % self.name)
    for tag in ("RPKI", "IRDB"):
      setup_biz_cert_chain(self.name + "-" + tag)
    self.rpkid_ta = rpki.x509.X509(PEM_file = self.name + "-RPKI-TA.cer")

  def setup_conf_file(self):
    """Write config files for this entity."""
    rpki.log.info("Writing config files for %s" % self.name)
    d = { "my_name"      : self.name,
          "testbed_name" : testbed_name,
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
    """Set up this entity's IRDB."""
    rpki.log.info("Setting up MySQL for %s" % self.name)
    db = MySQLdb.connect(user = "rpki", db = self.rpki_db_name, passwd = rpki_db_pass)
    cur = db.cursor()
    for sql in rpki_sql:
      cur.execute(sql)
    db.close()
    db = MySQLdb.connect(user = "irdb", db = self.irdb_db_name, passwd = irdb_db_pass)
    cur = db.cursor()
    for sql in irdb_sql:
      cur.execute(sql)
    for kid in self.kids:
      cur.execute("INSERT registrant (IRBE_mapped_id, subject_name, valid_until) VALUES (%s, %s, %s)", (kid.name, kid.name, kid.resources.valid_until))
    db.close()

  def sync_sql(self):
    """Whack this entity's IRDB to match our master database.  We do
    this once during setup, then do it again every time we apply a
    delta to this entity.
    """
    rpki.log.info("Updating MySQL data for IRDB %s" % self.name)
    db = MySQLdb.connect(user = "irdb", db = self.irdb_db_name, passwd = irdb_db_pass)
    cur = db.cursor()
    cur.execute("DELETE FROM asn")
    cur.execute("DELETE FROM net")
    for kid in self.kids:
      cur.execute("SELECT registrant_id FROM registrant WHERE IRBE_mapped_id = %s", (kid.name,))
      registrant_id = cur.fetchone()[0]
      for as_range in kid.resources.as:
        cur.execute("INSERT asn (start_as, end_as, registrant_id) VALUES (%s, %s, %s)", (as_range.min, as_range.max, registrant_id))
      for v4_range in kid.resources.v4:
        cur.execute("INSERT net (start_ip, end_ip, version, registrant_id) VALUES (%s, %s, 4, %s)", (v4_range.min, v4_range.max, registrant_id))
      for v6_range in kid.resources.v6:
        cur.execute("INSERT net (start_ip, end_ip, version, registrant_id) VALUES (%s, %s, 6, %s)", (v6_range.min, v6_range.max, registrant_id))
      cur.execute("UPDATE registrant SET valid_until = %s WHERE registrant_id = %s", (kid.resources.valid_until, registrant_id))
    db.close()

  def run_daemons(self):
    """Run daemons for this entity."""
    rpki.log.info("Running daemons for %s" % self.name)
    self.rpkid_process = subprocess.Popen((prog_python, prog_rpkid, "-c", self.name + ".conf"))
    self.irdbd_process = subprocess.Popen((prog_python, prog_irdbd, "-c", self.name + ".conf"))

  def kill_daemons(self):
    """Kill daemons for this entity."""
    rpki.log.info("Killing daemons for %s" % self.name)
    for proc in (self.rpkid_process, self.irdbd_process):
      try:
        os.kill(proc.pid, signal.SIGTERM)
      except:
        pass
      proc.wait()

  def call_rpkid(self, pdu):
    """Send a left-right message to this entity's RPKI daemon and
    return the response.
    """
    rpki.log.info("Calling rpkid for %s" % self.name)
    pdu.type = "query"
    elt = rpki.left_right.msg((pdu,)).toXML()
    rpki.log.debug(lxml.etree.tostring(elt, pretty_print = True, encoding = "us-ascii"))
    rpki.relaxng.left_right.assertValid(elt)
    cms = rpki.cms.xml_sign(
      elt           = elt,
      key           = testbed_key,
      certs         = testbed_certs)
    url = "https://localhost:%d/left-right" % self.rpki_port
    rpki.log.debug("Attempting to connect to %s" % url)
    cms = rpki.https.client(
      client_key   = testbed_key,
      client_certs = testbed_certs,
      server_ta    = rpki.x509.X509_chain(self.rpkid_ta),
      url          = url,
      msg          = cms)
    elt = rpki.cms.xml_verify(der = cms, ta = self.rpkid_ta)
    rpki.log.debug(lxml.etree.tostring(elt, pretty_print = True, encoding = "us-ascii"))
    rpki.relaxng.left_right.assertValid(elt)
    pdu = rpki.left_right.sax_handler.saxify(elt)[0]
    assert pdu.type == "reply" and not isinstance(pdu, rpki.left_right.report_error_elt)
    return pdu

  def create_rpki_objects(self):
    """Create RPKI engine objects for this engine.

    Parent and child objects are tricky:

    - Parent object needs to know child_id by which parent refers to
      this engine in order to set the contact URI correctly.

    - Child object needs to record the child_id by which this engine
      refers to the child.

    This all just works so long as we walk the set of engines in the
    right order (parents before their children).

    Root node of the engine tree is special, it too has a parent but
    that one is the magic self-signed micro engine.
    """

    rpki.log.info("Creating rpkid self object for %s" % self.name)
    self.self_id = self.call_rpkid(rpki.left_right.self_elt.make_pdu(
      action = "create", crl_interval = self.crl_interval, regen_margin = self.regen_margin)).self_id

    rpki.log.info("Creating rpkid BSC object for %s" % self.name)
    pdu = self.call_rpkid(rpki.left_right.bsc_elt.make_pdu(action = "create", self_id = self.self_id, generate_keypair = True))
    self.bsc_id = pdu.bsc_id

    rpki.log.info("Issuing BSC EE cert for %s" % self.name)
    cmd = (prog_openssl, "x509", "-req", "-CA", self.name + "-RPKI-CA.cer", "-CAkey", self.name + "-RPKI-CA.key", "-CAserial", self.name + "-RPKI-CA.srl")
    signer = subprocess.Popen(cmd, stdin = subprocess.PIPE, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    bsc_ee = rpki.x509.X509(PEM = signer.communicate(input = pdu.pkcs10_request.get_PEM())[0])

    rpki.log.info("Installing BSC EE cert for %s" % self.name)
    self.call_rpkid(rpki.left_right.bsc_elt.make_pdu(action = "set", self_id = self.self_id, bsc_id = self.bsc_id,
                                                     signing_cert = [bsc_ee, rpki.x509.X509(PEM_file = self.name + "-RPKI-CA.cer")]))

    rpki.log.info("Creating rpkid repository object for %s" % self.name)
    self.repository_id = self.call_rpkid(rpki.left_right.repository_elt.make_pdu(action = "create", self_id = self.self_id, bsc_id = self.bsc_id)).repository_id

    rpki.log.info("Creating rpkid parent object for %s" % self.name)
    if self.is_root():
      self.parent_id = self.call_rpkid(rpki.left_right.parent_elt.make_pdu(
        action = "create", self_id = self.self_id, bsc_id = self.bsc_id, repository_id = self.repository_id, sia_base = self.sia_base,
        peer_biz_cert = rootd_ta, peer_biz_glue = rootd_ta, sender_name = self.name, recipient_name = "Walrus",
        peer_contact_uri = "https://localhost:%s/" % rootd_port)).parent_id
    else:
      self.parent_id = self.call_rpkid(rpki.left_right.parent_elt.make_pdu(
        action = "create", self_id = self.self_id, bsc_id = self.bsc_id, repository_id = self.repository_id, sia_base = self.sia_base,
        peer_biz_cert = self.parent.rpkid_ta, peer_biz_glue = self.parent.rpkid_ta, sender_name = self.name, recipient_name = self.parent.name,
        peer_contact_uri = "https://localhost:%s/up-down/%s" % (self.parent.rpki_port, self.child_id))).parent_id

    rpki.log.info("Creating rpkid child objects for %s" % self.name)
    db = MySQLdb.connect(user = "irdb", db = self.irdb_db_name, passwd = irdb_db_pass)
    cur = db.cursor()
    for kid in self.kids:
      kid.child_id = self.call_rpkid(rpki.left_right.child_elt.make_pdu(
        action = "create", self_id = self.self_id, bsc_id = self.bsc_id, peer_biz_cert = kid.rpkid_ta)).child_id
      cur.execute("UPDATE registrant SET rpki_self_id = %s, rpki_child_id = %s WHERE IRBE_mapped_id = %s", (self.self_id, kid.child_id, kid.name))
    db.close()

    rpki.log.info("Creating rpkid route_origin objects for %s" % self.name)
    for ro in self.route_origins:
      ro.route_origin_id = self.call_rpkid(rpki.left_right.route_origin_elt.make_pdu(
        action = "create", self_id = self.self_id, as_number = ro.asn,
        exact_match = ro.exact_match, ipv4 = ro.v4, ipv6 = ro.v6)).route_origin_id

#       exact_match = 1 if ro.exact_match else 0

  def write_leaf_yaml(self):
    """Write YAML scripts for leaf nodes.  Only supports list requests
    at the moment: issue requests would require class and SIA values,
    revoke requests would require class and SKI values.

    ...Except that we can cheat and assume class 1 because we just
    know that rpkid will assign that with the current setup.  So we
    also support issue, kludge though this is.
    """

    rpki.log.info("Writing leaf YAML for %s" % self.name)
    f = open(self.name + ".yaml", "w")
    f.write(yaml_fmt_1 % {
      "child_id"    : self.child_id,
      "parent_name" : self.parent.name,
      "my_name"     : self.name,
      "https_port"  : self.parent.rpki_port,
      "sia"         : self.sia_base })
    f.close()

  def run_cron(self):
    """Trigger cron run for this engine."""

    rpki.log.info("Running cron for %s" % self.name)
    rpki.https.client(client_key   = testbed_key,
                      client_certs = testbed_certs,
                      server_ta    = rpki.x509.X509_chain(self.rpkid_ta),
                      url          = "https://localhost:%d/cronjob" % self.rpki_port,
                      msg          = "Run cron now, please")

  def run_yaml(self):
    """Run YAML scripts for this leaf entity."""
    rpki.log.info("Running YAML for %s" % self.name)
    subprocess.check_call((prog_python, prog_poke, "-y", self.name + ".yaml", "-r", "list", "-d"))
    subprocess.check_call((prog_python, prog_poke, "-y", self.name + ".yaml", "-r", "issue", "-d"))

def setup_biz_cert_chain(name):
  """Build a set of business certs."""
  s = "exec >/dev/null 2>&1\n"
  for kind in ("EE", "CA", "TA"):
    d = { "name"    : name,
          "kind"    : kind,
          "ca"      : "true" if kind in ("CA", "TA") else "false",
          "openssl" : prog_openssl }
    f = open("%(name)s-%(kind)s.cnf" % d, "w")
    f.write(biz_cert_fmt_1 % d)
    f.close()
    if not os.path.exists("%(name)s-%(kind)s.key" % d):
      s += biz_cert_fmt_2 % d
    s += biz_cert_fmt_3 % d
  s += (biz_cert_fmt_4 % { "name" : name, "openssl" : prog_openssl })
  subprocess.check_call(s, shell = True)

def setup_rootd(rpkid_name):
  """Write the config files for rootd."""
  rpki.log.info("Writing config files for %s" % rootd_name)
  d = { "rootd_name" : rootd_name,
        "rootd_port" : rootd_port,
        "rpkid_name" : rpkid_name,
        "rootd_sia"  : rootd_sia,
        "rsyncd_dir" : rsyncd_dir,
        "openssl"    : prog_openssl }
  f = open(rootd_name + ".conf", "w")
  f.write(rootd_fmt_1 % d)
  f.close()
  s = "exec >/dev/null 2>&1\n"
  if not os.path.exists(rootd_name + ".key"):
    s += rootd_fmt_2 % d
  s += rootd_fmt_3 % d
  subprocess.check_call(s, shell = True)

def setup_rcynic():
  """Write the config file for rcynic."""
  rpki.log.info("Config file for rcynic")
  d = { "rcynic_name" : rcynic_name,
        "rootd_name"  : rootd_name }
  f = open(rcynic_name + ".conf", "w")
  f.write(rcynic_fmt_1 % d)
  f.close()

def setup_rsyncd():
  """Write the config file for rsyncd."""
  rpki.log.info("Config file for rsyncd")
  d = { "rsyncd_name"   : rsyncd_name,
        "rsyncd_port"   : rsyncd_port,
        "rsyncd_module" : rsyncd_module,
        "rsyncd_dir"    : rsyncd_dir }
  f = open(rsyncd_name + ".conf", "w")
  f.write(rsyncd_fmt_1 % d)
  f.close()

def setup_publication():
  """Set up (pseudo) publication directory."""
  rpki.log.info("Creating (pseudo) publication directory")
  assert rootd_sia.startswith("rsync://")
  global rsyncd_dir
  rsyncd_dir = os.getcwd() + "/publication/" + rootd_sia[len("rsync://"):]
  os.makedirs(rsyncd_dir)

def run_rcynic():
  """Run rcynic to see whether what was published makes sense."""
  rpki.log.info("Running rcynic")
  env = os.environ.copy()
  env["TZ"] = ""
  subprocess.check_call((prog_rcynic, "-c", rcynic_name + ".conf"), env = env)
  subprocess.call(rcynic_stats, shell = True, env = env)

def mangle_sql(filename):
  """Mangle an SQL file into a sequence of SQL statements."""
  #
  # There is no pretty way to do this.  Just shut your eyes, it'll be over soon.
  #
  f = open(filename)
  statements = " ".join(" ".join(word for word in line.expandtabs().split(" ") if word)
                        for line in [line.strip(" \t\n") for line in f.readlines()]
                        if line and not line.startswith("--")).rstrip(";").split(";")
  f.close()
  return [stmt.strip() for stmt in statements]

biz_cert_fmt_1 = '''\
[ req ]
distinguished_name	= req_dn
x509_extensions		= req_x509_ext
prompt			= no
default_md		= sha256

[ req_dn ]
CN			= Test Certificate %(name)s %(kind)s

[ req_x509_ext ]
basicConstraints	= CA:%(ca)s
subjectKeyIdentifier	= hash
authorityKeyIdentifier	= keyid:always
'''

biz_cert_fmt_2 = '''\
%(openssl)s genrsa -out %(name)s-%(kind)s.key 2048 &&
'''

biz_cert_fmt_3 = '''\
%(openssl)s req -new -key %(name)s-%(kind)s.key -out %(name)s-%(kind)s.req -config %(name)s-%(kind)s.cnf &&
'''

biz_cert_fmt_4 = '''\
%(openssl)s x509 -req -in %(name)s-TA.req -out %(name)s-TA.cer -extfile %(name)s-TA.cnf -extensions req_x509_ext -signkey %(name)s-TA.key -days 60 &&
%(openssl)s x509 -req -in %(name)s-CA.req -out %(name)s-CA.cer -extfile %(name)s-CA.cnf -extensions req_x509_ext -CA %(name)s-TA.cer -CAkey %(name)s-TA.key -CAcreateserial &&
%(openssl)s x509 -req -in %(name)s-EE.req -out %(name)s-EE.cer -extfile %(name)s-EE.cnf -extensions req_x509_ext -CA %(name)s-CA.cer -CAkey %(name)s-CA.key -CAcreateserial
'''

yaml_fmt_1 = '''---
version:                1
posturl:                https://localhost:%(https_port)s/up-down/%(child_id)s
recipient-id:           "%(parent_name)s"
sender-id:              "%(my_name)s"

cms-cert-file:          %(my_name)s-RPKI-EE.cer
cms-key-file:           %(my_name)s-RPKI-EE.key
cms-ca-cert-file:       %(parent_name)s-RPKI-TA.cer
cms-cert-chain-file:    [ %(my_name)s-RPKI-CA.cer ]

ssl-cert-file:          %(my_name)s-RPKI-EE.cer
ssl-key-file:           %(my_name)s-RPKI-EE.key
ssl-ca-cert-file:       %(parent_name)s-RPKI-TA.cer
ssl-cert-chain-file:    [ %(my_name)s-RPKI-CA.cer ]

requests:
  list:
    type:               list
  issue:
    type:               issue
    #
    # This is cheating, we know a priori that the class will be "1"
    #
    class:              1
    sia:
      -                 %(sia)s
'''

conf_fmt_1 = '''\

[irdbd]

startup-message = This is %(my_name)s irdbd

sql-database	= %(irdb_db_name)s
sql-username	= irdb
sql-password	= %(irdb_db_pass)s

cms-key		= %(my_name)s-IRDB-EE.key
cms-cert.0	= %(my_name)s-IRDB-EE.cer
cms-cert.1	= %(my_name)s-IRDB-CA.cer
cms-ta		= %(my_name)s-RPKI-TA.cer

https-key	= %(my_name)s-IRDB-EE.key
https-cert.0	= %(my_name)s-IRDB-EE.cer
https-cert.1	= %(my_name)s-IRDB-CA.cer
https-ta	= %(my_name)s-RPKI-TA.cer

https-url	= https://localhost:%(irdb_port)d/

[irbe-cli]

cms-key		= %(testbed_name)s-EE.key
cms-cert.0	= %(testbed_name)s-EE.cer
cms-cert.1	= %(testbed_name)s-CA.cer
cms-ta		= %(my_name)s-RPKI-TA.cer

https-key	= %(testbed_name)s-EE.key
https-cert.0	= %(testbed_name)s-EE.cer
https-cert.1	= %(testbed_name)s-CA.cer
https-ta	= %(my_name)s-RPKI-TA.cer

https-url	= https://localhost:%(rpki_port)d/left-right

[rpkid]

startup-message = This is %(my_name)s rpkid

sql-database	= %(rpki_db_name)s
sql-username	= rpki
sql-password	= %(rpki_db_pass)s

cms-key		= %(my_name)s-RPKI-EE.key
cms-cert.0	= %(my_name)s-RPKI-EE.cer
cms-cert.1	= %(my_name)s-RPKI-CA.cer

cms-ta-irdb	= %(my_name)s-IRDB-TA.cer
cms-ta-irbe	= %(testbed_name)s-TA.cer

https-key	= %(my_name)s-RPKI-EE.key
https-cert.0	= %(my_name)s-RPKI-EE.cer
https-cert.1	= %(my_name)s-RPKI-CA.cer

https-ta-irdb	= %(my_name)s-IRDB-TA.cer
https-ta-irbe	= %(testbed_name)s-TA.cer

irdb-url	= https://localhost:%(irdb_port)d/

server-host     = localhost
server-port     = %(rpki_port)d
'''

rootd_fmt_1 = '''\

[rootd]

cms-key			= %(rootd_name)s-EE.key
cms-cert.0		= %(rootd_name)s-EE.cer
cms-cert.1		= %(rootd_name)s-CA.cer
cms-ta			= %(rpkid_name)s-RPKI-TA.cer

https-key		= %(rootd_name)s-EE.key
https-cert.0		= %(rootd_name)s-EE.cer
https-cert.1		= %(rootd_name)s-CA.cer
https-ta		= %(rpkid_name)s-RPKI-TA.cer

server-port		= %(rootd_port)s

rootd_base              = %(rootd_sia)s
rootd_cert              = %(rootd_sia)sWOMBAT.cer

rpki-subject-filename	= %(rsyncd_dir)sWOMBAT.cer

rpki-key		= %(rootd_name)s.key
rpki-issuer		= %(rootd_name)s.cer
rpki-pkcs10-filename	= %(rootd_name)s.subject.pkcs10

[req]
default_bits		= 2048
encrypt_key		= no
distinguished_name	= req_dn
req_extensions		= req_x509_ext
prompt			= no

[req_dn]
CN			= Completely Bogus Test Root (NOT FOR PRODUCTION USE)

[req_x509_ext]
basicConstraints	= critical,CA:true
subjectKeyIdentifier	= hash
keyUsage		= critical,keyCertSign,cRLSign
subjectInfoAccess	= 1.3.6.1.5.5.7.48.5;URI:%(rootd_sia)s
sbgp-autonomousSysNum	= critical,AS:0-4294967295
sbgp-ipAddrBlock	= critical,IPv4:0.0.0.0/0,IPv6:0::/0
'''

rootd_fmt_2 = '''\
%(openssl)s genrsa -out %(rootd_name)s.key 2048 &&
'''

rootd_fmt_3 = '''\
%(openssl)s req -new -key %(rootd_name)s.key -out %(rootd_name)s.req -config %(rootd_name)s.conf -text &&
%(openssl)s x509 -req -in %(rootd_name)s.req -out %(rootd_name)s.cer -outform DER -extfile %(rootd_name)s.conf -extensions req_x509_ext -signkey %(rootd_name)s.key -sha256
'''

rcynic_fmt_1 = '''\
[rcynic]
xml-summary             = %(rcynic_name)s.xml
jitter                  = 0
use-links               = yes
use-syslog              = no
use-stderr              = yes
log-level               = log_debug
trust-anchor            = %(rootd_name)s.cer
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

main()
