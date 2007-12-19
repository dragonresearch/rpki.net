# $Id$

import rpki.resource_set, os, yaml

class allocation(object):

  parent = None

  def __init__(self, yaml, parent = None):
    self.name = yaml["name"]
    self.parent = parent
    self.kids = [allocation(k, self) for k in yaml.get("kids", ())]
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

  def flatten(self):
    """Return a list of self and kids."""
    ret = [self]
    for kid in self.kids:
      ret.extend(kid.flatten())
    return ret

  def is_leaf(self):
    return not self.kids

  def is_root(self):
    return self.parent is None

  def __str__(self):
    return "%s\n  ASN: %s\n IPv4: %s\n IPv6: %s\n Kids: %s\n" \
           % (self.name,
              self.resources.as, self.resources.v4, self.resources.v6,
              ", ".join(k.name for k in self.kids))

f = open("testdb2.yaml")
y = yaml.safe_load(f)
f.close()

root = allocation(y)
root.closure()

for i in root.flatten():
  print i
