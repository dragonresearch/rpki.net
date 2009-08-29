"""
Test framework, using the same YAML test description format as
testbed.py, but using the myrpki.py and myirbe.py tools to do all the
back-end work.  Reads YAML file, generates .csv and .conf files, runs
daemons and waits for one of them to exit.

Much of the YAML handling code lifted from testbed.py.

Still to do:

- Implement testebd.py-style delta actions, that is, modify the
  allocation database under control of the YAML file, dump out new
  .csv files, and run myrpki.py and myirbe.py again to feed resulting
  changes into running daemons.

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

import subprocess, csv, re, os, getopt, sys, base64, yaml, signal, errno, time
import rpki.resource_set, rpki.sundial, rpki.config, myrpki

# Nasty regular expressions for parsing config files.  Sadly, while
# the Python ConfigParser supports writing config files, it does so in
# such a limited way that it's easier just to hack this ourselves.

section_regexp = re.compile("\s*\[\s*(.+?)\s*\]\s*$")
variable_regexp = re.compile("\s*([-a-zA-Z0-9_]+)\s*=\s*(.+?)\s*$")

def cleanpath(*names):
  """
  Construct normalized pathnames.
  """
  return os.path.normpath(os.path.join(*names))

# Pathnames for various things we need

this_dir  = os.getcwd()
test_dir  = cleanpath(this_dir, "test")
rpkid_dir = cleanpath(this_dir, "../rpkid")

prog_myirbe = cleanpath(this_dir, "myirbe.py")
prog_myrpki = cleanpath(this_dir, "myrpki.py")
prog_rpkid  = cleanpath(rpkid_dir, "rpkid.py")
prog_irdbd  = cleanpath(rpkid_dir, "irdbd.py")
prog_pubd   = cleanpath(rpkid_dir, "pubd.py")
prog_rootd  = cleanpath(rpkid_dir, "rootd.py")

prog_openssl = cleanpath(this_dir, "../openssl/openssl/apps/openssl")

only_one_pubd = True

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
  def parse(cls, yaml):
    """
    Parse a ROA request from YAML format.
    """
    return cls(yaml.get("asn"), yaml.get("ipv4"), yaml.get("ipv6"))
    
class allocation_db(list):
  """
  Our allocation database.
  """

  def __init__(self, yaml):
    list.__init__(self)
    self.root = allocation(yaml, self)
    assert self.root.is_root()
    if self.root.crl_interval is None:
      self.root.crl_interval = 24 * 60 * 60
    if self.root.regen_margin is None:
      self.root.regen_margin = 24 * 60 * 60
    for a in self:
      if a.sia_base is None:
        if a.runs_pubd():
          base = "rsync://localhost:%d/" % a.rsync_port
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
      if a.is_hosted():
        a.hosted_by = self.map[a.hosted_by]
        a.hosted_by.hosts.append(a)
        assert not a.is_root() and not a.hosted_by.is_hosted()

  def dump(self):
    """
    Show contents of allocation database.
    """
    for a in self:
      a.dump()

  def make_rootd_openssl(self):
    """
    Factory for a function to run the OpenSSL comand line tool on the
    root node of our allocation database.  Could easily be generalized
    if there were a need, but as it happens we only ever need to do
    this for the root node.
    """
    env = { "PATH"           : os.environ["PATH"],
            "BPKI_DIRECTORY" : self.root.path("bpki.myirbe"),
            "RANDFILE"       : ".OpenSSL.whines.unless.I.set.this" }
    cwd = self.root.path()
    return lambda *args: subprocess.check_call((prog_openssl,) + args, cwd = cwd, env = env)

class allocation(object):
  """
  One entity in our allocation database.  Every entity in the database
  is assumed to hold resources, so needs at least myrpki services.
  Entities that don't have the hosted_by property run their own copies
  of rpkid, irdbd, and pubd, so they also need myirbe services.
  """

  parent       = None
  crl_interval = None
  regen_margin = None

  base_port = 4400

  @classmethod
  def allocate_port(cls):
    """
    Allocate a TCP port.
    """
    cls.base_port += 1
    return cls.base_port

  base_engine = -1

  @classmethod
  def allocate_engine(cls):
    """
    Allocate an engine number, mostly used to construct MySQL database
    names.
    """
    cls.base_engine += 1
    return cls.base_engine

  def __init__(self, yaml, db, parent = None):
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
    self.hosts = []
    if not self.is_hosted():
      self.engine = self.allocate_engine()
      self.rpkid_port = self.allocate_port()
      self.irdbd_port = self.allocate_port()
    if self.runs_pubd():
      self.pubd_port  = self.allocate_port()
      self.rsync_port = self.allocate_port()
    if self.is_root():
      self.rootd_port = self.allocate_port()

  def closure(self):
    """
    Compute resource closure of this node and its children, to avoid a
    lot of tedious (and error-prone) duplication in the YAML file.
    """
    resources = self.base
    for kid in self.kids:
      resources = resources.union(kid.closure())
    self.resources = resources
    return resources

  def dump(self):
    """
    Show content of this allocation node.
    """
    print str(self)

  def __str__(self):
    s = self.name + ":\n"
    if self.resources.asn:      s += "  ASNs: %s\n" % self.resources.asn
    if self.resources.v4:       s += "  IPv4: %s\n" % self.resources.v4
    if self.resources.v6:       s += "  IPv6: %s\n" % self.resources.v6
    if self.kids:               s += "  Kids: %s\n" % ", ".join(k.name for k in self.kids)
    if self.parent:             s += "    Up: %s\n" % self.parent.name
    if self.sia_base:           s += "   SIA: %s\n" % self.sia_base
    if self.is_hosted():        s += "  Host: %s\n" % self.hosted_by.name
    if self.hosts:              s += " Hosts: %s\n" % ", ".join(h.name for h in self.hosts)
    for r in self.roa_requests: s += "   ROA: %s\n" % r
    if not self.is_hosted():    s += " IPort: %s\n" % self.irdbd_port
    if self.runs_pubd():        s += " PPort: %s\n" % self.pubd_port
    if not self.is_hosted():    s += " RPort: %s\n" % self.rpkid_port
    if self.runs_pubd():        s += " SPort: %s\n" % self.rsync_port
    if self.is_root():          s += " TPort: %s\n" % self.rootd_port
    return s + " Until: %s\n" % self.resources.valid_until

  def is_root(self):
    """
    Is this the root node?
    """
    return self.parent is None

  def is_hosted(self):
    """
    Is this entity hosted?
    """
    return self.hosted_by is not None

  def runs_pubd(self):
    """
    Does this entity run a pubd?
    """
    return self.is_root() or not (self.is_hosted() or only_one_pubd)

  def path(self, *names):
    """
    Construct pathnames in this entity's test directory.
    """
    return cleanpath(test_dir, self.name, *names)

  def csvout(self, fn):
    """
    Open and log a CSV output file.  We use delimiter and dialect
    settings imported from the myrpki module, so that we automatically
    write CSV files in the right format.
    """
    path = self.path(fn)
    print "Writing", path
    return csv.writer(open(path, "w"), dialect = myrpki.csv_dialect)

  def up_down_url(self):
    """
    Construct service URL for this node's parent.
    """
    parent_port = self.parent.hosted_by.rpkid_port if self.parent.is_hosted() else self.parent.rpkid_port
    return "https://localhost:%d/up-down/%s/%s" % (parent_port, self.parent.name, self.name)

  def dump_asns(self, fn):
    """
    Write Autonomous System Numbers CSV file.
    """
    f = self.csvout(fn)
    for k in self.kids:    
      f.writerows((k.name, a) for a in k.resources.asn)

  def dump_children(self, fn):
    """
    Write children CSV file.
    """
    self.csvout(fn).writerows((k.name, k.resources.valid_until, k.path("bpki.myrpki/ca.cer"))
                              for k in self.kids)

  def dump_parents(self, fn):
    """
    Write parents CSV file.
    """
    if self.is_root():
      self.csvout(fn).writerow(("rootd",
                                "https://localhost:%d/" % self.rootd_port,
                                self.path("bpki.myirbe/ca.cer"),
                                self.path("bpki.myirbe/ca.cer"),
                                self.name,
                                self.sia_base))
    else:
      parent_host = self.parent.hosted_by if self.parent.is_hosted() else self.parent
      self.csvout(fn).writerow((self.parent.name,
                                self.up_down_url(),
                                self.parent.path("bpki.myrpki/ca.cer"),
                                parent_host.path("bpki.myirbe/ca.cer"),
                                self.name,
                                self.sia_base))

  def dump_prefixes(self, fn):
    """
    Write prefixes CSV file.
    """
    f = self.csvout(fn)
    for k in self.kids:
      f.writerows((k.name, p) for p in (k.resources.v4 + k.resources.v6))

  def dump_roas(self, fn):
    """
    Write ROA CSV file.
    """
    f = self.csvout(fn)
    for r in self.roa_requests:
      f.writerows((p, r.asn) for p in (r.v4 + r.v6 if r.v4 and r.v6 else r.v4 or r.v6 or ()))

  def dump_clients(self, fn, db):
    """
    Write pubclients CSV file.
    """
    if self.runs_pubd():
      f = self.csvout(fn)
      f.writerows((s.name, s.path("bpki.myrpki/ca.cer"), s.sia_base)
                  for s in (db if only_one_pubd else [self] + self.kids))

  def dump_conf(self, fn):
    """
    Write configuration file for OpenSSL and RPKI tools.
    """

    host = self.hosted_by if self.is_hosted() else self

    r = { ("myrpki", "handle"): self.name }

    if not self.is_hosted():
      r["irdbd",  "https-url"]     = "https://localhost:%d/" % self.irdbd_port
      r["irdbd",  "sql-database"]  = "irdb%d" % self.engine
      r["myirbe", "irdbd_conf"]    = "myrpki.conf"
      r["myirbe", "rpkid_base"]    = "https://localhost:%d/" % self.rpkid_port
      r["rpkid",  "irdb-url"]      = "https://localhost:%d/" % self.irdbd_port
      r["rpkid",  "server-port"]   = "%d" % self.rpkid_port
      r["rpkid",  "sql-database"]  = "rpki%d" % self.engine
      r["myirbe", "want_pubd"]     = "true" if self.runs_pubd() else "false"
      r["myirbe", "want_rootd"]    = "true" if self.is_root() else "false"

    if self.is_root():
      root_path = "localhost:%d/%s" % (self.rsync_port, self.name)
      r["rootd",  "rpki-root-dir"] = "publication/"
      r["rootd",  "rpki-base-uri"] = "rsync://%s/" % root_path
      r["rootd",  "rpki-root-cert"] = "publication/root.cer"
      r["rootd",  "rpki-root-cert-uri"] = "rsync://%s/root.cer" % root_path
      r["rootd",  "rpki-subject-cert"] = "%s.cer" % self.name
      r["rpki_x509_extensions", "subjectInfoAccess"] = "1.3.6.1.5.5.7.48.5;URI:rsync://%s/,1.3.6.1.5.5.7.48.10;URI:rsync://%s/root.mnf" % (root_path, root_path)

    if self.runs_pubd():
      r["pubd", "server-port"]  = "%d" % self.pubd_port
      r["pubd", "sql-database"] = "pubd%d" % self.engine

    s = self
    while not s.runs_pubd():
      s = s.parent
    r["myirbe", "pubd_base"]  = "https://localhost:%d/" % s.pubd_port
    r["myirbe", "rsync_base"] = "rsync://localhost:%d/" % s.rsync_port
    r["myrpki", "repository_bpki_certificate"] = s.path("bpki.myirbe/ca.cer")

    if self.is_root():
      r["rootd", "server-port"] = "%d" % self.rootd_port

    if rpkid_password:
      r["rpkid", "sql-password"] = rpkid_password

    if irdbd_password:
      r["irdbd", "sql-password"] = irdbd_password

    if pubd_password:
      r["pubd", "sql-password"]  = pubd_password

    f = open(self.path(fn), "w")
    f.write("# Automatically generated, do not edit\n")
    print "Writing", f.name

    section = None
    for line in open("myrpki.conf"):
      m = section_regexp.match(line)
      if m:
        section = m.group(1)
      if section is None or (self.is_hosted() and section in ("myirbe", "rpkid", "irdbd", "pubd", "rootd")):
        continue
      m = variable_regexp.match(line) if m is None else None
      variable = m.group(1) if m else None
      if (section, variable) in r:
        line = variable + " = " +  r[section, variable] + "\n"
      f.write(line)

    f.close()

  def dump_rsyncd(self, fn):
    """
    Write rsyncd configuration file.
    """

    if self.runs_pubd():
      f = open(self.path(fn), "w")
      print "Writing", f.name
      f.writelines(s + "\n" for s in
                   ("# Automatically generated, do not edit",
                    "port         = %d"           % self.rsync_port,
                    "address      = localhost",
                    "[%s]"                        % self.name,
                    "log file     = rsyncd.log",
                    "read only    = yes",
                    "use chroot   = no",
                    "path         = %s"           % self.path("publication"),
                    "comment      = RPKI test"))
      f.close()

  def run_myirbe(self):
    """
    Run myirbe.py if this entity is not hosted by another engine.
    """
    if not self.is_hosted():
      print "Running myirbe.py for", self.name
      cmd = ["python", prog_myirbe]
      cmd.extend(h.path("myrpki.xml") for h in self.hosts)
      subprocess.check_call(cmd, cwd = self.path())

  def run_myrpki(self):
    """
    Run myrpki.py for this entity.
    """
    print "Running myrpki.py for", self.name
    subprocess.check_call(("python", prog_myrpki), cwd = self.path())

  def run_python_daemon(self, prog):
    """
    Start a Python daemon and return a subprocess.Popen object
    representing the running daemon.
    """
    basename = os.path.basename(prog)
    p = subprocess.Popen(("python", prog, "-c", self.path("myrpki.conf")),
                         cwd = self.path(),
                         stdout = open(self.path(os.path.splitext(basename)[0] + ".log"), "w"),
                         stderr = subprocess.STDOUT)
    print "Running %s for %s: pid %d process %r" % (basename, self.name, p.pid, p)
    return p
  
  def run_rpkid(self):
    """
    Run rpkid.
    """
    return self.run_python_daemon(prog_rpkid)

  def run_irdbd(self):
    """
    Run irdbd.
    """
    return self.run_python_daemon(prog_irdbd)

  def run_pubd(self):
    """
    Run pubd.
    """
    return self.run_python_daemon(prog_pubd)

  def run_rootd(self):
    """
    Run rootd.
    """
    return self.run_python_daemon(prog_rootd)

  def run_rsyncd(self):
    """
    Run rsyncd.
    """
    p = subprocess.Popen(("rsync", "--daemon", "--no-detach", "--config", "rsyncd.conf"),
                         cwd = self.path())
    print "Running rsyncd for %s: pid %d process %r" % (self.name, p.pid, p)
    return p

os.environ["TZ"] = "UTC"
time.tzset()

cfg_file = "yamltest.conf"

opts, argv = getopt.getopt(sys.argv[1:], "c:h?", ["config=", "help"])
for o, a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  if o in ("-c", "--config"):
    cfg_file = a

# We can't usefully process more than one YAMl file at a time, so
# whine if there's more than one argument left.

if len(argv) > 1:
  raise RuntimeError, "Unexpected arguments %r" % argv

yaml_file = argv[0] if argv else "../rpkid/testbed.1.yaml"

# Allow optional config file for this tool to override default
# passwords: this is mostly so that I can show a complete working
# example without publishing my own server's passwords.

try:
  cfg = rpki.config.parser(cfg_file, "yamltest")
  rpkid_password = cfg.get("rpkid_db_pass")
  irdbd_password = cfg.get("irdbd_db_pass")
  pubd_password  = cfg.get("pubd_db_pass")
except:
  rpkid_password = None
  irdbd_password = None
  pubd_password  = None

# Start clean

for root, dirs, files in os.walk(test_dir, topdown = False):
  for file in files:
    os.unlink(os.path.join(root, file))
  for dir in dirs:
    os.rmdir(os.path.join(root, dir))

# Read first YAML doc in file and process as compact description of
# test layout and resource allocations.  Ignore subsequent YAML docs,
# they're for testbed.py, not this script.

db = allocation_db(yaml.safe_load_all(open(yaml_file)).next())

# Show what we loaded

db.dump()

# Set up each entity in our test

for d in db:
  os.makedirs(d.path())
  d.dump_asns("asns.csv")
  d.dump_children("children.csv")
  d.dump_parents("parents.csv")
  d.dump_prefixes("prefixes.csv")
  d.dump_roas("roas.csv")
  d.dump_conf("myrpki.conf")
  d.dump_clients("pubclients.csv", db)
  d.dump_rsyncd("rsyncd.conf")

# Do initial myirbe.py run for each hosting entity to set up BPKI

for d in db:
  d.run_myirbe()

# Run myrpki.py several times for each entity.  First pass misses
# stuff that isn't generated until later in first pass.  Second pass
# should pick up everything and reach a stable state.  If anything
# changes during third pass, that's a bug.

for i in xrange(3):
  for d in db:
    d.run_myrpki()

# Set up a few things for rootd

rootd_openssl = db.make_rootd_openssl()

print "Creating rootd BPKI cross-certificate for its child"
rootd_openssl("ca", "-notext", "-batch",
              "-config",  "myrpki.conf",
              "-ss_cert", "bpki.myrpki/ca.cer",
              "-out",     "bpki.myirbe/child.cer",
              "-extensions", "ca_x509_ext_xcert0")

os.makedirs(db.root.path("publication"))

print "Creating rootd RPKI root certificate"
rootd_openssl("x509", "-req", "-sha256", "-outform", "DER",
              "-signkey", "bpki.myirbe/ca.key",
              "-in",      "bpki.myirbe/ca.req",
              "-out",     "publication/root.cer",
              "-extfile", "myrpki.conf",
              "-extensions", "rpki_x509_extensions")

# At this point we need to start a whole lotta daemons.

progs = []

def all_daemons_running():
  for p in progs:
    if p.poll() is not None:
      return False
  return True

try:
  print "Running daemons"
  progs.append(db.root.run_rootd())
  progs.extend(d.run_irdbd()  for d in db if not d.is_hosted())
  progs.extend(d.run_pubd()   for d in db if d.runs_pubd())
  progs.extend(d.run_rsyncd() for d in db if d.runs_pubd())
  progs.extend(d.run_rpkid()  for d in db if not d.is_hosted())

  print "Giving daemons time to start up"
  time.sleep(20)

  assert all_daemons_running()

  # Run myirbe again for each host, to set up IRDB and RPKI objects.
  # Need to run a second time to push BSC certs out to rpkid.  Nothing
  # should happen on the third pass.  Oops, when hosting we need to
  # run myrpki between myirbe passes, since only the hosted entity can
  # issue the BSC, etc.

  for i in xrange(3):
    for d in db:
      d.run_myrpki()
    for d in db:
      d.run_myirbe()

  print "Done initializing daemons"

  # Wait until something terminates.

  signal.signal(signal.SIGCHLD, lambda *dont_care: None)
  if all_daemons_running():
    signal.pause()

finally:

  # Shut everything down.

  signal.signal(signal.SIGCHLD, signal.SIG_DFL)
  for p in progs:
    if p.poll() is None:
      os.kill(p.pid, signal.SIGTERM)
    print "Program pid %d %r returned %d" % (p.pid, p, p.wait())
