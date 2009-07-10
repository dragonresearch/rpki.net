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

import subprocess, csv, re, os, getopt, sys, ConfigParser, base64, yaml
import rpki.resource_set, rpki.sundial

base_port = 4400

def allocate_port():
  global base_port
  p = base_port
  base_port += 1
  return p

def copy_conf(input_file, output_file, replacement_dict = {}):
  cfg = ConfigParser.RawConfigParser()
  cfg.read(input_file)
  cfg.remove_section("myirbe")
  for opt in cfg.items("myrpki"):
    cfg.remove_option("myrpki", opt[0])
  for k, v in replacement_dict.iteritems():
    cfg.set("myrpki", k, v)
  f = open(output_file, "w")
  f.write("# Automatically generated from %s, do not edit\n" % input_file)
  cfg.write(f)
  f.close()

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

  def path(self, filename):
    return os.path.join("test", self.name, filename)

  def dump_asns(self, f):
    for k in self.kids:
      for a in k.resources.asn:
        f.write("%s\t%s\n" % (k.name, a))

  def dump_children(self, f):
    for k in self.kids:
      f.write("%s\t%s\t%s\n" % (k.name, k.resources.valid_until, k.path("ca.cer")))

  def dump_parents(self, f):
    if not self.is_root():
      f.write("%s\t%s\t%s\n" % (self.parent.name, "https://some.where.example/", self.parent.path("ca.cer")))

  def dump_prefixes(self, f):
    for k in self.kids:
      for p in k.resources.v4 + k.resources.v6:
        f.write("%s\t%s\n" % (k.name, p))

  def dump_roas(self, f):
    for r in self.roa_requests:
      for p in r.v4 + r.v6 if r.v4 and r.v6 else r.v4 or r.v6 or ():
        f.write("%s\t%s\n" % (p, r.asn))

  def dump_conf(self, input_file, f):
    cfg = ConfigParser.RawConfigParser()
    cfg.read(input_file)
    cfg.set("myrpki", "handle", self.name)
    if self.is_hosted():
      cfg.remove_section("myirbe")
    else:
      cfg.set("myirbe", "rsync_base", "rsync://localhost:%d/" % self.rsync_port)
      cfg.set("myirbe", "pubd_base",  "https://localhost:%d"  % self.pubd_port)
      cfg.set("myirbe", "rpkid_base", "https://localhost:%d"  % self.rpkid_port)
    f.write("# Automatically generated from %s, do not edit\n" % input_file)
    cfg.write(f)

#copy_conf("myrpki.conf", "/dev/stdout")

if False:
  yaml_file = sys.argv[1]
elif False:
  yaml_file = "../rpkid/testbed.6.yaml"
else:
  yaml_file = "test.yaml"

# Can't use yaml.safe_load() because it objects to subsequent
# documents in the same file.  Can't subscript result of
# yaml.safe_load_all() because it's a generator.  So we call .next(),
# per the generator protocol, to get the first document.

yaml_doc = yaml.safe_load_all(open(yaml_file)).next()

db = allocation_db(yaml_doc)

#db.dump()

for d in db:
  os.makedirs(d.path(""))
  d.dump_asns(open(d.path("asns.csv"), "w"))
  d.dump_children(open(d.path("children.csv"), "w"))
  d.dump_parents(open(d.path("parents.csv"), "w"))
  d.dump_prefixes(open(d.path("prefixes.csv"), "w"))
  d.dump_roas(open(d.path("roas.csv"), "w"))
  d.dump_conf("myrpki.conf", open(d.path("myrpki.conf"), "w"))
