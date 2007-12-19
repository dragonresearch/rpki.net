# $Id$

import rpki.resource_set, os, yaml

class allocation_db(list):

  def __init__(self, yaml):
    allocation(yaml, self).closure()
    for i, a in zip(range(len(self)), self):
      a.number = i

  @classmethod
  def from_file(cls, filename):
    return cls(yaml.safe_load(open(filename)))

  def dict_iter(self):
    for a in self:
      yield a.make_dict()

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

  def make_dict(self):
    return { "name"   : self.name,
             "parent" : None if self.parent is None else self.parent.name,
             "kids"   : [k.name for k in self.kids],
             "as"     : self.resources.as,
             "v4"     : self.resources.v4,
             "v6"     : self.resources.v6,
             "number" : self.number }

  def is_leaf(self):
    return not self.kids

  def is_root(self):
    return self.parent is None

if __name__ == "__main__":
  for d in allocation_db.from_file("testdb2.yaml").dict_iter():
    print '''
Name: %(name)s
 ASN: %(as)s
IPv4: %(v4)s
IPv6: %(v6)s
Rent: %(parent)s
Kids: %(kids)s
 Num: %(number)s
''' % d
