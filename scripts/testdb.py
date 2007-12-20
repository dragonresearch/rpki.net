# $Id$

import rpki.resource_set, os, yaml

debug = True

def main():

  y = [y for y in yaml.safe_load_all(open("testdb2.yaml"))]

  db = allocation_db(y[0])
  db.dump()

  for delta in y[1:]:
    print "Applying delta %s\n" % delta
    db.apply_delta(delta)
    db.dump()

  # Steps we need to take here
  #
  # 1: Construct config files for rpkid.py and irdb.py instances
  # 2: Initialize sql for rpki.py and irdb.py instances
  # 3: Construct biz keys and certs for rpki.py and irdb.py instances

  for a in db:
    setup_biz_certs(a.name)

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

class allocation_db(list):

  def __init__(self, yaml):
    self.root = allocation(yaml, self)
    assert self.root.is_root()
    self.root.closure()
    self.map = dict((a.name, a) for a in self)
    twigs = [a for a in self if a.is_twig()]
    for i, a in zip(range(len(twigs)), twigs):
      a.number = i

  def apply_delta(self, delta):
    for d in delta:
      self.map[d["name"]].apply_delta(d)
    self.root.closure()

  def dump(self):
    for a in self:
      print a

class allocation(object):

  parent = None
  number = None

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

  def apply_add_as(self, text): self.base.as = self.base.as.union(rpki.resource_set.resource_set_as(text))
  def apply_add_v4(self, text): self.base.v4 = self.base.v4.union(rpki.resource_set.resource_set_ipv4(text))
  def apply_add_v6(self, text): self.base.v6 = self.base.v6.union(rpki.resource_set.resource_set_ipv6(text))
  def apply_sub_as(self, text): self.base.as = self.base.as.difference(rpki.resource_set.resource_set_as(text))
  def apply_sub_v4(self, text): self.base.v4 = self.base.v4.difference(rpki.resource_set.resource_set_ipv4(text))
  def apply_sub_v6(self, text): self.base.v6 = self.base.v6.difference(rpki.resource_set.resource_set_ipv6(text))

  def __str__(self):
    s = self.name + "\n"
    if self.number is not None: s += "    #: %s\n" % self.number
    if self.resources.as:       s += "  ASN: %s\n" % self.resources.as
    if self.resources.v4:       s += " IPv4: %s\n" % self.resources.v4
    if self.resources.v6:       s += " IPv6: %s\n" % self.resources.v6
    if self.kids:               s += " Kids: %s\n" % ", ".join(k.name for k in self.kids)
    if self.parent:             s += "   Up: %s\n" % self.parent.name
    return s

  def is_leaf(self): return not self.kids
  def is_root(self): return self.parent is None
  def is_twig(self): return self.parent is not None and self.kids

biz_cert_fmt_1 = '''\
[ req ]
distinguished_name	= req_dn
x509_extensions		= req_x509_ext
prompt			= no
default_md		= sha256

[ req_dn ]
CN			= Test Certificate %s

[ req_x509_ext ]
basicConstraints	= CA:%s
subjectKeyIdentifier	= hash
authorityKeyIdentifier	= keyid:always
'''

biz_cert_fmt_2 = '''\
openssl req -new -newkey rsa:2048 -nodes -keyout %s.key -out %s.req -config %s.cnf &&
'''

biz_cert_fmt_3 = '''\
openssl x509 -req -in %s-TA.req -out %s-TA.cer -extfile %s-TA.cnf -extensions req_x509_ext -signkey %s-TA.key -days 60 &&
openssl x509 -req -in %s-CA.req -out %s-CA.cer -extfile %s-CA.cnf -extensions req_x509_ext -CA %s-TA.cer -CAkey %s-TA.key -CAcreateserial &&
openssl x509 -req -in %s-EE.req -out %s-EE.cer -extfile %s-EE.cnf -extensions req_x509_ext -CA %s-CA.cer -CAkey %s-CA.key -CAcreateserial
'''

def setup_biz_certs(name):
  s = ""
  for kind in ("EE", "CA", "TA"):
    n = "%s-%s" % (name, kind)
    c = biz_cert_fmt_1 % (n, "true" if kind in ("CA", "TA") else "false")
    if debug:
      print "Would write config file " + n + " containing:\n\n" + c
    else:
      f = open("%s.cnf" % n, "w")
      f.write(c)
      f.close()
    if not os.path.exists(n + ".key") or not os.path.exists(n + ".req"):
      s += biz_cert_fmt_2 % ((n,) * 3)
  s += biz_cert_fmt_3 % ((name,) * 14)
  if debug:
    print "Would execute:\n\n" + s
  else:
    r = os.system(s)
    if r != 0:
      raise RunTimeError, "Command failed (status %x):\n%s" % (r, s)

main()
