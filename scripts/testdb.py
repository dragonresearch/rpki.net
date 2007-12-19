# $Id$

import rpki.resource_set, os, yaml

class allocation_db(list):

  def __init__(self, yaml):
    allocation(yaml, self).closure()

  @classmethod
  def from_file(cls, filename):
    return cls(yaml.safe_load(open(filename)))

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

  def is_leaf(self):
    return not self.kids

  def is_root(self):
    return self.parent is None

  def __str__(self):
    s = self.name + "\n"
    if self.resources.as:
      s += "  ASN: %s\n" % self.resources.as
    if self.resources.v4:
      s += " IPv4: %s\n" % self.resources.v4
    if self.resources.v6:
      s += " IPv6: %s\n" % self.resources.v6
    if self.kids:
      s += " Kids: %s\n" % ", ".join(k.name for k in self.kids)
    if self.parent:
      s += "   Up: %s\n" % self.parent.name
    return s

if __name__ == "__main__":

  for i in allocation_db.from_file("testdb2.yaml"):
    print i
