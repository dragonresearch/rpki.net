# $Id$

import rpki.resource_set, os, yaml

class allocation_db(list):

  def __init__(self, yaml):
    self.root = allocation(yaml, self)
    assert self.root.is_root()
    self.root.closure()
    self.map = dict((a.name, a) for a in self)
    for i, a in zip(range(len(self)), self):
      a.number = i

  def get(self, name, default = None):
    return self.map.get(name, default)

  def apply_delta(self, delta):
    for d in delta:
      self.map[d["name"]].apply_delta(d)
    self.root.closure()

class allocation(object):

  parent = None

  def __init__(self, yaml, db, parent = None):
    db.append(self)
    self.name = yaml["name"]
    self.parent = parent
    self.kids = [allocation(k, db, self) for k in yaml.get("kids", ())]
    self.base = rpki.resource_set.resource_bag(
      as = rpki.resource_set.resource_set_as(yaml.get("asn")),
      v4 = rpki.resource_set.resource_set_ipv4(yaml.get("ipv4")),
      v6 = rpki.resource_set.resource_set_ipv6(yaml.get("ipv6")))

  def closure(self):
    """Compute the transitive resource closure for one resource attribute."""
    resources = self.base
    for kid in self.kids:
      resources = resources.union(kid.closure())
    self.resources = resources
    return resources

  def apply_delta(self, yaml):
    for k,v in yaml.items():
      if k != "name":
        getattr(self, "apply_" + k)(v)

  def apply_add_as(self, text):
    self.base.as = self.base.as.union(rpki.resource_set.resource_set_as(text))

  def apply_add_v4(self, text):
    self.base.v4 = self.base.v4.union(rpki.resource_set.resource_set_ipv4(text))

  def apply_add_v6(self, text):
    self.base.v6 = self.base.v6.union(rpki.resource_set.resource_set_ipv6(text))

  def apply_sub_as(self, text):
    self.base.as = self.base.as.difference(rpki.resource_set.resource_set_as(text))

  def apply_sub_v4(self, text):
    self.base.v4 = self.base.v4.difference(rpki.resource_set.resource_set_ipv4(text))

  def apply_sub_v6(self, text):
    self.base.v6 = self.base.v6.difference(rpki.resource_set.resource_set_ipv6(text))

  def dict(self):
    return { "name"   : self.name,
             "as"     : self.resources.as,
             "v4"     : self.resources.v4,
             "v6"     : self.resources.v6,
             "number" : str(self.number) }

  def is_leaf(self):
    return not self.kids

  def is_root(self):
    return self.parent is None

  def is_twig(self):
    return self.parent is not None and self.kids

  def write_conf(self):
    if self.is_twig():
      f = open(self.name + ".conf", "w")
      f.write(conf_fmt % self.dict())
      f.close()

  def write_yaml(self):
    if self.is_leaf():
      f = open(self.name + ".yaml", "w")
      f.write(yaml_fmt % self.dict())
      f.close()

dump_fmt = '''\
   #: %(number)s
Name: %(name)s
 ASN: %(as)s
IPv4: %(v4)s
IPv6: %(v6)s
'''

def dump():
  for a in db:
    print dump_fmt % a.dict()

y = [y for y in yaml.safe_load_all(open("testdb2.yaml"))]

print "Loading", str(y[0]), "\n"

db = allocation_db(y[0])
dump()

for delta in y[1:]:
  print "Applying delta", str(delta), "\n"
  db.apply_delta(delta)
  dump()

# Steps we need to take here
#
# 1: Construct config files for RPKId and IRDB instances
# 2: Initialize sql for RPKI and IRDB instances
# 3: Construct biz keys and certs for RPKI and IRDB instances
# 4: Populate IRDB(s)
# 5: Start RPKI and IRDB instances
# 6: Create objects in RPKI engines
# 7: Write YAML files for leaves
# 8: Start cycle:
# 8a: Run cron in all RPKI instances
# 8b: Run all YAML clients
# 8c: Read and apply next deltas from master YAML
#
# This is going to be ugly
