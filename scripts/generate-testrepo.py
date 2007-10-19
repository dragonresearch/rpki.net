# $Id$

"""Generate an RPKI test repository.

This script generates a toy RPKI repository for test purposes.  It's
designed to be relatively easy to reconfigure, making it simple to
test whatever is of interest on a given day, without a lot of setup
overhead.

Outputs are a bunch of config files for the OpenSSL CLI tool and a
makefile to drive everything.
"""

import rpki.resource_set, os

subdir  = "resource-cert-samples"
openssl = "../../openssl/openssl-0.9.8f/apps/openssl"
keybits = 2048

def main():
  """Main program, including the toy database itself."""

  db = allocation_db()
  db.add("ISP1", ipv4="192.0.2.1-192.0.2.33", asn="64533")
  db.add("ISP2", ipv4="192.0.2.44-192.0.2.100")
  db.add("ISP3", ipv6="2001:db8::44-2001:db8::100")
  db.add("ISP4", ipv6="2001:db8::10:0:44/128", asn="64544")
  db.add("ISP5a", ipv4="10.0.0.0/24", ipv6="2001:db8::a00:0/120")
  db.add("ISP5b", ipv4="10.3.0.0/24", ipv6="2001:db8::a03:0/120")
  db.add("ISP5c", asn="64534-64540")
  db.add("LIR1", children=["ISP1", "ISP2"])
  db.add("LIR2", children=["ISP3", "ISP4"])
  db.add("LIR3", children=["ISP5a", "ISP5b", "ISP5c"])
  db.add("RIR",  children=["LIR1", "LIR2", "LIR3"])

  if not os.path.isdir(subdir):
    os.mkdir(subdir)

  for i in db:
    write_maybe("%s/%s.cnf" % (subdir, i.name), i.cfg_string())

  write_maybe("%s/Makefile" % subdir,
              "# Automatically generated, do not edit.\n" +
              "".join([i.makefile_rules() for i in db]))

def write_maybe(name, new_content):
  """Write a file if and only if its contents have changed.
  This simplifies interactions with "make".
  """
  old_content = None
  if os.path.isfile(name):
    f = open(name, "r")
    old_content = f.read()
    f.close()
  if old_content != new_content:
    print "Writing", name
    f = open(name, "w")
    f.write(new_content)
    f.close()

class allocation_db(list):
  """Class to represent an allocation database."""

  def __init__(self):
    self.allocation_map = {}

  def add(self, name, **kw):
    """Add a new entry to this allocation database.
    All arguments passed through to the allocation constructor.
    """
    self.insert(0, allocation(name = name, allocation_map = self.allocation_map, **kw))

class allocation(object):
  """Class representing one entity holding allocated resources.

  In order to simplify configuration, this class automatically
  computes the set of resources that this entity must hold in order to
  serve both itself and its children.
  """

  parent = None

  def __init__(self, name, asn = None, ipv4 = None, ipv6 = None, children = [], allocation_map = None):
    """Create a new allocation entry.

    This binds the parent attributes of any children, and computes the
    transitive closure of the set of resources this entity needs.
    """
    self.name = name
    self.children = [allocation_map[i] for i in children]
    for child in self.children:
      assert child.parent is None
      child.parent = self
    self.asn  = self.summarize("asn",  rpki.resource_set.resource_set_as(asn))
    self.ipv4 = self.summarize("ipv4", rpki.resource_set.resource_set_ipv4(ipv4))
    self.ipv6 = self.summarize("ipv6", rpki.resource_set.resource_set_ipv6(ipv6))
    allocation_map[name] = self

  def summarize(self, attrname, seed = None):
    """Compute the transitive resource closure for one resource attribute."""
    if seed is None:
      seed = getattr(self, attrname)
    for child in self.children:
      seed = seed.union(child.summarize(attrname))
    return seed

  def __str__(self):
    return "%s\n  ASN: %s\n IPv4: %s\n IPv6: %s" % (self.name, self.asn, self.ipv4, self.ipv6)

  def cfg_string(self):
    """Generate the OpenSSL configuration file needed for this entity."""
    keys = { "self"       : self.name,
             "keybits"    : keybits,
             "no_parent"  : "#",
             "no_asid"    : "#",
             "no_addr"    : "#",
             "parent"     : "???",
             "asid"       : "???",
             "addr"       : "???" }
    if self.parent:
      keys["no_parent"] = ""
      keys["parent"] = self.parent.name
    if self.asn:
      keys["no_asid"] = ""
      keys["asid"] = ",".join(["AS:" + str(x) for x in self.asn])
    if self.ipv4 or self.ipv6:
      keys["no_addr"] = ""
      keys["addr"] = ",".join(["IPv4:" + str(x) for x in self.ipv4] + ["IPv6:" + str(x) for x in self.ipv6])
    return openssl_cfg_fmt % keys

  def makefile_rules(self):
    """Generate the makefile rules needed for this entity."""
    keys = { "self"     : self.name,
             "keybits"  : keybits,
             "openssl"  : openssl }
    if self.parent:
      keys["signconf"] = "%s.cnf"           % self.parent.name
      keys["signdeps"] = "%s.key"           % self.parent.name
    else:
      keys["signconf"] = "%s.cnf -selfsign" % self.name
      keys["signdeps"] = "%s.key"           % self.name
    return makefile_fmt % keys

makefile_fmt = '''\

all:: %(self)s.cer

%(self)s.key:
	%(openssl)s genrsa -out $@ %(keybits)d

%(self)s.req: %(self)s.key %(self)s.cnf Makefile
	%(openssl)s req -new -config %(self)s.cnf -key %(self)s.key -out $@

%(self)s.cer: %(self)s.req %(self)s.cnf %(signdeps)s Makefile
	@test -d %(self)s || mkdir %(self)s
	@test -f %(self)s/index || touch %(self)s/index
	@test -f %(self)s/serial || echo 01 >%(self)s/serial
	%(openssl)s ca -batch -out $@ -in %(self)s.req -extfile %(self)s.cnf -config %(signconf)s


show_req::
	%(openssl)s req -noout -text -in %(self)s.req -config /dev/null

show_cer::
	%(openssl)s x509 -noout -text -in %(self)s.cer
'''

openssl_cfg_fmt = '''# Automatically generated, do not edit.

[ ca ]
default_ca = ca_default

[ ca_default ]
certificate = %(self)s.cer
serial = %(self)s/serial
private_key = %(self)s.key
database = %(self)s/index
new_certs_dir = %(self)s
name_opt = ca_default
cert_opt = ca_default
default_days = 365
default_crl_days = 30
default_md = sha256
preserve = no
copy_extensions = copy
policy = ca_policy_anything
unique_subject = no
x509_extensions = ca_x509_ext
crl_extensions = crl_x509_ext

[ ca_policy_anything ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional
givenName = optional
surname = optional

[ req ]
default_bits = %(keybits)d
encrypt_key = no
distinguished_name = req_dn
req_extensions = req_x509_ext
prompt = no

[ req_dn ]
CN = TEST ENTITY %(self)s

[ req_x509_ext ]
basicConstraints = critical,CA:true
subjectKeyIdentifier = hash
keyUsage = critical,keyCertSign,cRLSign
subjectInfoAccess = 1.3.6.1.5.5.7.48.5;URI:rsync://wombats-r-us.hactrn.net/%(self)s/
%(no_parent)sauthorityInfoAccess = caIssuers;URI:rsync://wombats-r-us.hactrn.net/%(parent)s.cer
%(no_asid)ssbgp-autonomousSysNum = critical,%(asid)s
%(no_addr)ssbgp-ipAddrBlock = critical,%(addr)s

[ ca_x509_ext ]
basicConstraints = critical,CA:true
%(no_parent)sauthorityKeyIdentifier = keyid:always
keyUsage = critical,keyCertSign,cRLSign
subjectInfoAccess = 1.3.6.1.5.5.7.48.5;URI:rsync://wombats-r-us.hactrn.net/%(self)s/
%(no_parent)sauthorityInfoAccess = caIssuers;URI:rsync://wombats-r-us.hactrn.net/%(parent)s.cer
%(no_asid)ssbgp-autonomousSysNum = critical,%(asid)s
%(no_addr)ssbgp-ipAddrBlock = critical,%(addr)s

[ crl_x509_ext ]
authorityKeyIdentifier = keyid:always
'''

main()
