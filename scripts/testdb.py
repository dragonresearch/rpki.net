# $Id$

import os, yaml, MySQLdb, subprocess, signal
import rpki.resource_set, rpki.sundial

just_show      = True
debug          = True

irbe_name      = "testdb"

irdb_db_pass   = "fnord"
rpki_db_pass   = "fnord"

max_engines    = 10
irdb_base_port = 4400
rpki_base_port = irdb_base_port + max_engines
root_port      = rpki_base_port + max_engines

rpki_sql       = open("../docs/rpki-db-schema.sql").read()
irdb_sql       = open("../docs/sample-irdb.sql").read()

prog_python    = "/usr/local/bin/python"
prog_rpkid     = "rpkid.py"
prog_irdbd     = "irbd.py"

def main():

  y = [y for y in yaml.safe_load_all(open("testdb2.yaml"))]

  db = allocation_db(y[0])

  if just_show:

    db.dump()
    for delta in y[1:]:
      print "Applying delta %s\n" % delta
      db.apply_delta(delta)
      db.dump()

  else:

    # Construct biz keys and certs for this script to use; construct biz
    # keys and certs for all the rpki.py and irdb.py instances.

    setup_biz_cert_chain(irbe_name)
    for a in db:
      a.setup_biz_certs()

    # Construct config files for rpkid.py and irdb.py instances

    for a in db.engines:
      a.setup_conf_file()

    # Initialize sql for rpki.py and irdb.py instances

    for a in db.engines:
      a.setup_sql(rpki_sql, irdb_sql)

    # Populate IRDB(s)

    for a in db.engines:
      a.sync_sql()

    # Start RPKI and IRDB instances

    for a in db.engines:
      a.run_daemons()

    # 6: Create objects in RPKI engines
    # 7: Write YAML files for leaves
    # 8: Start cycle:
    # 8a: Run cron in all RPKI instances
    # 8b: Run all YAML clients
    # 8c: Make sure that everybody got what they were supposed to get
    #     and that everything that was supposed to be published has been
    #     published
    # 8d: Read and apply next deltas from master YAML


class allocation_db(list):

  def __init__(self, yaml):
    self.root = allocation(yaml, self)
    assert self.root.is_root()
    self.root.closure()
    self.map = dict((a.name, a) for a in self)
    self.engines = [a for a in self if not a.is_leaf()]
    for i, a in zip(range(len(self.engines)), self.engines):
      a.set_engine_number(i)

  def apply_delta(self, delta):
    for d in delta:
      self.map[d["name"]].apply_delta(d)
    self.root.closure()

  def dump(self):
    for a in self:
      print a

class allocation(object):

  parent       = None
  irdb_db_name = None
  irdb_port    = None
  rpki_db_name = None
  rpki_port    = None

  def __init__(self, yaml, db, parent = None):
    db.append(self)
    self.name = yaml["name"]
    self.parent = parent
    self.kids = [allocation(k, db, self) for k in yaml.get("kids", ())]
    self.base = rpki.resource_set.resource_bag(
      as = rpki.resource_set.resource_set_as(yaml.get("asn")),
      v4 = rpki.resource_set.resource_set_ipv4(yaml.get("ipv4")),
      v6 = rpki.resource_set.resource_set_ipv6(yaml.get("ipv6")),
      valid_until = yaml["valid_until"])

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
  def apply_valid_until(self, stamp): self.base.valid_until = stamp

  def __str__(self):
    s = self.name + " " + self.resources.valid_until.strftime("%Y-%m-%dT%H:%M:%SZ") + "\n"
    if self.resources.as:       s += "  ASN: %s\n" % self.resources.as
    if self.resources.v4:       s += " IPv4: %s\n" % self.resources.v4
    if self.resources.v6:       s += " IPv6: %s\n" % self.resources.v6
    if self.kids:               s += " Kids: %s\n" % ", ".join(k.name for k in self.kids)
    if self.parent:             s += "   Up: %s\n" % self.parent.name
    return s

  def is_leaf(self): return not self.kids
  def is_root(self): return self.parent is None
  def is_twig(self): return self.parent is not None and self.kids

  def set_engine_number(self, n):
    if n > max_engines:
      raise RuntimeError, "You asked for %d rpki engine instances, maximum is %d, sorry" % (n, max_engines)
    self.irdb_db_name = "irdb%d" % n
    self.irdb_port    = irdb_base_port + n
    self.rpki_db_name = "rpki%d" % n
    self.rpki_port    = rpki_base_port + n

  def setup_biz_certs(self):
    for tag in ("RPKI", "IRDB"):
      setup_biz_cert_chain(self.name + "-" + tag)

  def setup_conf_file(self):
    d = { "my_name"      : self.name,
          "irbe_name"    : irbe_name,
          "irdb_db_name" : self.irdb_db_name,
          "irdb_db_pass" : irdb_db_pass,
          "irdb_port"    : self.irdb_port,
          "rpki_db_name" : self.rpki_db_name,
          "rpki_db_pass" : rpki_db_pass,
          "rpki_port"    : self.rpki_port }
    s = conf_fmt_1 % d
    if debug:
      print "Would write config file " + self.name + ".conf containing:\n" + s
    else:
      f = open(self.name + ".conf", "w")
      f.write(s)
      f.close()

  def setup_sql(self, rpki_sql, irdb_sql):
    db = MySQLdb.connect(user = "rpki", db = self.rpki_db_name, passwd = rpki_db_pass)
    db.cursor().execute(rpki_sql)
    db.close()
    db = MySQLdb.connect(user = "irdb", db = self.irdb_db_name, passwd = irdb_db_pass)
    cur = db.cursor()
    cur.execute(irdb_sql)
    for kid in self.kids:
      cur.execute("INSERT registrant (IRBE_mapped_id, subject_name, valid_until) VALUES (%s, %s, %s)", (kid.name, kid.name, kid.valid_until))
    db.close()

  def sync_sql(self):
    db = MySQLdb.connect(user = "irdb", db = self.irdb_db_name, passwd = irdb_db_pass)
    cur = db.cursor()
    cur.execute("DELETE FROM asn")
    cur.execute("DELETE FROM net")
    for kid in self.kids:
      cur.execute("SELECT registrant_id FROM registrant WHERE IRBE_mapped_id = %s", kid.name)
      registrant_id = cur.fetchone()[0]
      for as_range in kid.as:
        cur.execute("INSERT asn (start_as, end_as, registrant_id) VALUES (%s, %s, %s)", (as_range.min, as_range.max, registrant_id))
      for v4_range in kid.v4:
        cur.execute("INSERT net (start_ip, end_ip, version, registrant_id) VALUES (%s, %s, 4, %s)", (as_v4.min, as_v4.max, registrant_id))
      for v6_range in kid.v6:
        cur.execute("INSERT net (start_ip, end_ip, version, registrant_id) VALUES (%s, %s, 6, %s)", (as_v6.min, as_v6.max, registrant_id))
    db.close()

  def run_daemons(self):
    self.rpkid_process = subprocess.Popen((prog_python, prog_rpkid, "-c", self.name + ".conf"))
    self.irdbd_process = subprocess.Popen((prog_python, prog_irdbd, "-c", self.name + ".conf"))

  def kill_daemons(self):
    for proc in (self.rpkid_process, self.irdbd_process):
      try:
        os.kill(proc.pid, signal.SIGTERM)
      except:
        pass
      proc.wait()

def setup_biz_cert_chain(name):
  s = ""
  for kind in ("EE", "CA", "TA"):
    n = "%s-%s" % (name, kind)
    c = biz_cert_fmt_1 % (n, "true" if kind in ("CA", "TA") else "false")
    if debug:
      print "Would write config file " + n + ".cnf containing:\n\n" + c
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

poke_yaml_fmt_1 = '''---
version:                1
posturl:                https://localhost:%(parent_https_port)s/up-down/%(my_child_id)s
recipient-id:           "%(parent_recipient_id)s"
sender-id:              "%(my_sender_id)s"

cms-cert-file:          %(my_name)s-EE.cer
cms-key-file:           %(my_name)s-EE.key
cms-ca-cert-file:       %(parent_name)s-Root.cer
cms-cert-chain-file:    [ %(my_name)s-CA.cer ]

ssl-cert-file:          %(my_name)s-EE.cer
ssl-key-file:           %(my_name)s-EE.key
ssl-ca-cert-file:       %(parent_name)s-Root.cer

requests:
  list:
    type:               list
  issue:
    type:               issue
    class:              %(my_class_name)s
    sia:                [ "%(my_sia_dir)s" ]
  revoke:
    type:               revoke
    class:              %(my_class_name)s
    ski:                "%(my_ski)s"
'''

conf_fmt_1 = '''\

[rpkid]

sql-database	= %(rpki_db_name)s
sql-username	= rpki
sql-password	= %(rpki_db_pass)s

cms-key		= %(my_name)s-RPKI-EE.key
cms-cert.0	= %(my_name)s-RPKI-EE.cer
cms-cert.1	= %(my_name)s-RPKI-CA.cer

cms-ta-irdb	= %(my_name)s-IRDB-TA.cer
cms-ta-irbe	= %(irbe_name)s-TA.cer

https-key	= %(my_name)s-RPKI-EE.key
https-cert.0	= %(my_name)s-RPKI-EE.cer
https-cert.1	= %(my_name)s-RPKI-CA.cer

https-ta.0	= %(irbe_name)s-TA.cer
https-ta.1	= %(my_name)s-IRDB-TA.cer

irdb-url	= https://localhost:%(irdb_port)d/

https-server-port = %(rpki_port)d

[irdb]

sql-database	= %(irdb_db_name)s
sql-username	= irdb
sql-password	= %(irdb_db_pass)s

cms-key		= %(my_name)s-IRDB-EE.key
cms-cert.0	= %(my_name)s-IRDB-EE.cer
cms-cert.1	= %(my_name)s-IRDB-CA.cer
cms-ta		= %(my_name)s-RPKI-TA.cer

https-key	= %(my_name)s-IRDB-EE.key
https-cert.0	= %(my_name)s-IRDB-EE.cer
https-cert.1	= %(my_name)s-IRDB-CA.cer
https-ta.0	= %(irbe_name)s-TA.cer
https-ta.1	= %(my_name)s-RPKI-TA.cer

https-url	= https://localhost:%(irdb_port)d/

[irbe-cli]

cms-key		= %(irbe_name)s-EE.key
cms-cert.0	= %(irbe_name)s-EE.cer
cms-cert.1	= %(irbe_name)s-CA.cer
cms-ta		= %(my_name)s-RPKI-TA.cer

https-key	= %(irbe_name)s-EE.key
https-cert.0	= %(irbe_name)s-EE.cer
https-cert.1	= %(irbe_name)s-CA.cer
https-ta.0	= %(my_name)s-RPKI-TA.cer
https-ta.1	= %(my_name)s-IRDB-TA.cer

https-url	= https://localhost:4433/left-right
'''

main()
