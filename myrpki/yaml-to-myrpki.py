"""
Convert testbed.py YAML configuration format to myrpki .conf and .csv
format.  Much of the YAML handling code lifted from testbed.py.

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

import subprocess, csv, re, os, getopt, sys, ConfigParser, base64, yaml, signal
import rpki.resource_set, rpki.sundial, myrpki

section_regexp = re.compile("\s*\[\s*(.+?)\s*\]\s*$")
variable_regexp = re.compile("\s*(\w+)\s*=\s*(.+?)\s*$")

def cleanpath(*names):
  return os.path.normpath(os.path.join(*names))

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

base_port = 4400

def allocate_port():
  global base_port
  p = base_port
  base_port += 1
  return p

rootd_port = allocate_port()

class roa_request(object):

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
    return cls(yaml.get("asn"), yaml.get("ipv4"), yaml.get("ipv6"))
    
class allocation_db(list):

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
        a.sia_base = ("rsync://rpki.example/" if a.is_root() else a.parent.sia_base) + a.name + "/"
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
    for a in self:
      print a

class allocation(object):

  parent       = None
  crl_interval = None
  regen_margin = None

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
      self.rsync_port = allocate_port()
      self.rpkid_port = allocate_port()
      self.pubd_port  = allocate_port()

  def closure(self):
    resources = self.base
    for kid in self.kids:
      resources = resources.union(kid.closure())
    self.resources = resources
    return resources

  def __str__(self):
    s = self.name + ":\n"
    if self.resources.asn:      s += "  ASNs: %s\n" % self.resources.asn
    if self.resources.v4:       s += "  IPv4: %s\n" % self.resources.v4
    if self.resources.v6:       s += "  IPv6: %s\n" % self.resources.v6
    if self.kids:               s += "  Kids: %s\n" % ", ".join(k.name for k in self.kids)
    if self.parent:             s += "    Up: %s\n" % self.parent.name
    #if self.sia_base:          s += "   SIA: %s\n" % self.sia_base
    if self.is_hosted():        s += "  Host: %s\n" % self.hosted_by.name
    if self.hosts:              s += " Hosts: %s\n" % ", ".join(h.name for h in self.hosts)
    for r in self.roa_requests: s += "   ROA: %s\n" % r
    return s + " Until: %s\n" % self.resources.valid_until

  def is_root(self):
    return self.parent is None

  def is_hosted(self):
    return self.hosted_by is not None

  def path(self, *names):
    return cleanpath(test_dir, self.name, *names)

  def outfile(self, filename):
    path = self.path(filename)
    print "Writing", path
    return open(path, "w")

  def up_down_url(self):
    if self.is_root():
      return "https://localhost:%d/" % rootd_port
    else:
      parent_port = self.parent.hosted_by.rpkid_port if self.parent.is_hosted() else self.parent.rpkid_port
      return "https://localhost:%d/up-down/%s/%s" % (parent_port, self.parent.name, self.name)

  def dump_asns(self, fn):
    f = self.outfile(fn)
    for k in self.kids:
      for a in k.resources.asn:
        f.write("%s\t%s\n" % (k.name, a))
    f.close()

  def dump_children(self, fn):
    f = self.outfile(fn)
    for k in self.kids:
      f.write("%s\t%s\t%s\n" % (k.name, k.resources.valid_until, k.path("bpki.myrpki", "ca.cer")))
    f.close()

  def dump_parents(self, fn):
    f = self.outfile(fn)
    if not self.is_root():
      f.write("%s\t%s\t%s\n" % (self.parent.name, self.up_down_url(), self.parent.path("bpki.myrpki", "ca.cer")))
    f.close()

  def dump_prefixes(self, fn):
    f = self.outfile(fn)
    for k in self.kids:
      for p in k.resources.v4 + k.resources.v6:
        f.write("%s\t%s\n" % (k.name, p))
    f.close()

  def dump_roas(self, fn):
    f = self.outfile(fn)
    for r in self.roa_requests:
      for p in r.v4 + r.v6 if r.v4 and r.v6 else r.v4 or r.v6 or ():
        f.write("%s\t%s\n" % (p, r.asn))
    f.close()

  def dump_conf(self, fn):

    replacements = { ("myrpki", "handle") : self.name }

    if not self.is_hosted():
      replacements.update({
        ("myirbe", "rsync_base") : "rsync://localhost:%d/" % self.rsync_port,
        ("myirbe", "pubd_base")  : "https://localhost:%d/" % self.pubd_port,
        ("myirbe", "rpkid_base") : "https://localhost:%d/" % self.rpkid_port })

    f = self.outfile(fn)
    f.write("# Automatically generated, do not edit\n")

    for conf in ("myrpki.conf", "rpkid.conf", "irdbd.conf", "pubd.conf", "rootd.conf"):
      section = None
      for line in open(conf):
        m = section_regexp.match(line)
        if m:
          section = m.group(1)
        if section is None or (self.is_hosted() and section in ("myirbe", "rpkid", "irdbd", "pubd", "rootd")):
          continue
        m = variable_regexp.match(line) if m is None else None
        variable = m.group(1) if m else None
        if (section, variable) in replacements:
          line = variable + " = " +  replacements[(section, variable)] + "\n"
        f.write(line)

    f.close()

  def run_myirbe(self):
    if not self.is_hosted():
      print "Running myirbe.py for", self.name
      subprocess.check_call(("python", prog_myirbe), cwd = self.path())

  def run_myrpki(self):
    print "Running myrpki.py for", self.name
    subprocess.check_call(("python", prog_myrpki), cwd = self.path())

  def run_python_daemon(self, prog):
    basename = os.path.basename(prog)
    p = subprocess.Popen(("python", prog, "-c", "myrpki.conf"),
                         cwd = self.path(),
                         stdout = open(self.path(os.path.splitext(basename)[0] + ".log"), "w"),
                         stderr = subprocess.STDOUT)
    print "Running %s for %s: pid %d process %r" % (basename, self.name, p.pid, p)
    return p
  
  def run_rpkid(self):
    return self.run_python_daemon(prog_rpkid)

  def run_irdbd(self):
    return self.run_python_daemon(prog_irdbd)

  def run_pubd(self):
    return self.run_python_daemon(prog_pubd)

  def run_rootd(self):
    return self.run_python_daemon(prog_rootd)

# Start clean, but keep key files because they take a while to generate

for root, dirs, files in os.walk(test_dir, topdown = False):
  for file in files:
    if not file.endswith(".key"):
      os.remove(os.path.join(root, file))
  for dir in dirs:
    os.rmdir(os.path.join(root, dir))

# Select input file

yaml_file = sys.argv[1] if len(sys.argv) > 1 else "../rpkid/testbed.1.yaml"

# Read first YAML doc in file and process as compact description of
# test layout and resource allocations.  Ignore subsequent YAML docs,
# they're for testbed.py, not this script.

db = allocation_db(yaml.safe_load_all(open(yaml_file)).next())

# Set up each entity in our test

for d in db:
  os.makedirs(d.path())
  d.dump_asns("asns.csv")
  d.dump_children("children.csv")
  d.dump_parents("parents.csv")
  d.dump_prefixes("prefixes.csv")
  d.dump_roas("roas.csv")
  d.dump_conf("myrpki.conf")

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

# Set up rootd's BPKI cross-certificate for its one and only child.

if not os.path.exists(db.root.path("bpki.rootd/child.cer")):
  subprocess.check_call((prog_openssl, "ca", "-notext", "-batch",
                         "-config",  db.root.path("myrpki.conf"),
                         "-ss_cert", db.root.path("bpki.rpkid/ca.cer"),
                         "-out",     db.root.path("bpki.rootd/child.cer"),
                         "-extensions", "ca_x509_ext_xcert0"),
                         cwd = db.root.path(),
                        env = { "PATH"           : os.environ["PATH"],
                                "BPKI_DIRECTORY" : db.root.path("bpki.rootd"),
                                "RANDFILE"       : ".OpenSSL.whines.unless.I.set.this" } )

# Set up rootd's RPKI root certificate.

if not os.path.exists(db.root.path("bpki.rootd/rpkiroot.cer")):
  subprocess.check_call((prog_openssl, "x509", "-req", "-sha256", "-outform", "DER",
                         "-in",      db.root.path("bpki.rootd/ca.req"),
                         "-signkey", db.root.path("bpki.rootd/ca.key"),
                         "-out",     db.root.path("bpki.rootd/rpkiroot.cer"),
                         "-extfile", db.root.path("myrpki.conf"),
                         "-extensions", "rpki_x509_extensions"),
                         cwd = db.root.path(),
                        env = { "PATH"           : os.environ["PATH"],
                                "BPKI_DIRECTORY" : db.root.path("bpki.rootd"),
                                "RANDFILE"       : ".OpenSSL.whines.unless.I.set.this" } )

# At this point we need to start a whole lotta daemons.

progs = [db.root.run_rootd()]
progs.extend(d.run_irdbd() for d in db if not d.is_hosted())
progs.extend(d.run_pubd()  for d in db if not d.is_hosted())
progs.extend(d.run_rpkid() for d in db if not d.is_hosted())

signal.signal(signal.SIGCHLD, lambda *dont_care: None)
want_pause = True
for p in progs:
  want_pause &= p.poll() is None
if want_pause:
  signal.pause()
signal.signal(signal.SIGCHLD, signal.SIG_DFL)

for p in progs:
  if p.poll() is None:
    os.kill(p.pid, signal.SIGINT)
  print "Program pid %d %r returned %d" % (p.pid, p, p.wait())
