# $Id$

import rpki.resource_set

subdir  = "testrepo"
openssl = "../../openssl/openssl-0.9.8e/apps/openssl"
keybits = 2048

def main():
  """
  Main program, up front to make it easier to find.
  """

  allocation("ISP1", ipv4="192.0.2.1-192.0.2.33", asn="64533")
  allocation("ISP2", ipv4="192.0.2.44-192.0.2.100")
  allocation("ISP3", ipv6="2001:db8::44-2001:db8::100")
  allocation("ISP4", ipv6="2001:db8::10:0:44/128", asn="64544")
  allocation("LIR1", children=["ISP1", "ISP2"])
  allocation("LIR2", children=["ISP3", "ISP4"])
  allocation("RIR",  children=["LIR1", "LIR2"])

  for i in allocations:
    write_maybe("%s/%s.cnf" % (subdir, i.name), i.cfg_string())
  write_maybe("%s/Makefile" % subdir,
              "# Automatically generated, do not edit.\n" +
              "".join([i.makefile_rules() for i in allocations]))

def write_maybe(name, new_content):
  old_content = None
  try:
    f = open(name, "r")
    old_content = f.read()
    f.close()
  except IOError:
    pass
  if old_content != new_content:
    print "Writing", name
    f = open(name, "w")
    f.write(new_content)
    f.close()

allocation_dict = {}
allocations = []

class allocation(object):

  parent = None

  def __init__(self, name, asn=None, ipv4=None, ipv6=None, children=[]):
    self.name = name
    self.children = [allocation_dict[i] for i in children]
    for child in self.children:
      assert child.parent is None
      child.parent = self
    self.asn  = self.summarize("asn",  rpki.resource_set.resource_set_as(asn))
    self.ipv4 = self.summarize("ipv4", rpki.resource_set.resource_set_ipv4(ipv4))
    self.ipv6 = self.summarize("ipv6", rpki.resource_set.resource_set_ipv6(ipv6))
    allocation_dict[name] = self
    allocations.insert(0, self)

  def summarize(self, attrname, seed=None):
    if seed is None:
      seed = getattr(self, attrname)
    for child in self.children:
      seed = seed.union(child.summarize(attrname))
    return seed

  def __str__(self):
    return "%s\n  ASN: %s\n IPv4: %s\n IPv6: %s" % (self.name, self.asn, self.ipv4, self.ipv6)

  def cfg_string(self):
    keys = { "self"    : self.name,
             "keybits" : keybits,
             "no_aia"  : "#", "parent"  : "???",
             "no_asid" : "#", "asid"    : "???",
             "no_addr" : "#", "addr"    : "???" }
    if self.parent:
      keys["no_aia"] = ""
      keys["parent"] = self.parent.name
    if self.asn:
      keys["no_asid"] = ""
      keys["asid"] = ",".join(["AS:" + str(x) for x in self.asn])
    if self.ipv4 or self.ipv6:
      keys["no_addr"] = ""
      keys["addr"] = ",".join(["IPv4:" + str(x) for x in self.ipv4] + ["IPv6:" + str(x) for x in self.ipv6])
    return openssl_cfg_fmt % keys

  def makefile_rules(self):
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
	test -d %(self)s || mkdir %(self)s
	test -f %(self)s/index || touch %(self)s/index
	test -f %(self)s/serial || echo 01 >%(self)s/serial
	%(openssl)s ca -batch -verbose -notext -out $@ -in %(self)s.req -extensions req_x509_ext -extfile %(self)s.cnf -config %(signconf)s

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
default_md = sha1
preserve = no
copy_extensions = copy
policy = ca_policy_anything
unique_subject = no

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
x509_extensions = req_x509_ext
prompt = no

[ req_dn ]
CN = TEST ENTITY %(self)s

[ req_x509_ext ]
basicConstraints = critical,CA:true
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
keyUsage = critical,keyCertSign,cRLSign
subjectInfoAccess = 1.3.6.1.5.5.7.48.5;URI:rsync://wombats-r-us.hactrn.net/%(self)s/
%(no_aia)sauthorityInfoAccess = caIssuers;URI:rsync://wombats-r-us.hactrn.net/%(parent)s.cer
%(no_asid)ssbgp-autonomousSysNum = critical,%(asid)s
%(no_addr)ssbgp-ipAddrBlock = critical,%(addr)s
'''

main()
