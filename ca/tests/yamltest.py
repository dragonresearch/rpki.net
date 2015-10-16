#!/usr/bin/env python

"""
Test framework, using the same YAML test description format as
smoketest.py, but using the rpkic.py tool to do all the back-end
work.  Reads YAML file, generates .csv and .conf files, runs daemons
and waits for one of them to exit.
"""

# $Id$
#
# Copyright (C) 2013--2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2009--2012  Internet Systems Consortium ("ISC")
# Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL, ISC, AND ARIN DISCLAIM ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL DRL,
# ISC, OR ARIN BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
# OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# Much of the YAML handling code lifted from smoketest.py.
#
# Still to do:
#
# - Implement smoketest.py-style delta actions, that is, modify the
#   allocation database under control of the YAML file, dump out new
#   .csv files, and run rpkic.py again to feed resulting changes into
#   running daemons.
#

# pylint: disable=W0702,W0621

import subprocess
import re
import os
import logging
import argparse
import webbrowser
import sys
import yaml
import signal
import time
import lxml.etree
import rpki.resource_set
import rpki.sundial
import rpki.config
import rpki.log
import rpki.csv_utils
import rpki.x509
import rpki.relaxng

# Nasty regular expressions for parsing config files.  Sadly, while
# the Python ConfigParser supports writing config files, it does so in
# such a limited way that it's easier just to hack this ourselves.

section_regexp = re.compile(r"\s*\[\s*(.+?)\s*\]\s*$")
variable_regexp = re.compile(r"\s*([-a-zA-Z0-9_]+)\s*=\s*(.+?)\s*$")

def cleanpath(*names):
  """
  Construct normalized pathnames.
  """

  return os.path.normpath(os.path.join(*names))

# Pathnames for various things we need

this_dir  = os.getcwd()
test_dir  = cleanpath(this_dir, "yamltest.dir")
ca_dir    = cleanpath(this_dir, "..")

prog_rpkic = cleanpath(ca_dir, "rpkic")
prog_rpkid = cleanpath(ca_dir, "rpkid")
prog_irdbd = cleanpath(ca_dir, "irdbd")
prog_pubd  = cleanpath(ca_dir, "pubd")
prog_rootd = cleanpath(ca_dir, "rootd")
prog_rpki_manage  = cleanpath(ca_dir, "rpki-manage")

class roa_request(object):
  """
  Representation of a ROA request.
  """

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
  def parse(cls, y):
    """
    Parse a ROA request from YAML format.
    """

    return cls(y.get("asn"), y.get("ipv4"), y.get("ipv6"))


class router_cert(object):
  """
  Representation for a router_cert object.
  """

  _ecparams = None

  @classmethod
  def ecparams(cls):
    if cls._ecparams is None:
      cls._ecparams = rpki.x509.KeyParams.generateEC()
    return cls._ecparams

  def __init__(self, asn, router_id):
    self.asn = rpki.resource_set.resource_set_as("".join(str(asn).split()))
    self.router_id = router_id
    self.keypair = rpki.x509.ECDSA.generate(params = self.ecparams(), quiet = True)
    self.pkcs10 = rpki.x509.PKCS10.create(keypair = self.keypair)
    self.gski = self.pkcs10.gSKI()

  def __eq__(self, other):
    return self.asn == other.asn and self.router_id == other.router_id and self.gski == other.gski

  def __hash__(self):
    return tuple(self.asn).__hash__() + self.router_id.__hash__() + self.gski.__hash__()

  def __str__(self):
    return "%s: %s: %s" % (self.asn, self.router_id, self.gski)

  @classmethod
  def parse(cls, yaml):
    return cls(yaml.get("asn"), yaml.get("router_id"))

class allocation_db(list):
  """
  Our allocation database.
  """

  def __init__(self, yaml):
    list.__init__(self)
    self.root = allocation(yaml, self)
    assert self.root.is_root and not any(a.is_root for a in self if a is not self.root) and self[0] is self.root
    if self.root.crl_interval is None:
      self.root.crl_interval = 60 * 60
    if self.root.regen_margin is None:
      self.root.regen_margin = 24 * 60 * 60
    if self.root.base.valid_until is None:
      self.root.base.valid_until = rpki.sundial.now() + rpki.sundial.timedelta(days = 2)
    for a in self:
      if a.base.valid_until is None:
        a.base.valid_until = a.parent.base.valid_until
      if a.crl_interval is None:
        a.crl_interval = a.parent.crl_interval
      if a.regen_margin is None:
        a.regen_margin = a.parent.regen_margin
    self.root.closure()
    self.map = dict((a.name, a) for a in self)
    for a in self:
      if a.is_hosted:
        a.hosted_by = self.map[a.hosted_by]
        a.hosted_by.hosts.append(a)
        assert not a.is_root and not a.hosted_by.is_hosted

  def dump(self):
    """
    Show contents of allocation database.
    """

    for a in self:
      a.dump()


class allocation(object):
  """
  One entity in our allocation database.  Every entity in the database
  is assumed to hold resources, so needs at least rpkic services.
  Entities that don't have the hosted_by property run their own copies
  of rpkid, irdbd, and pubd, so they also need myirbe services.
  """

  base_port     = None
  parent        = None
  crl_interval  = None
  regen_margin  = None
  rootd_port    = None
  engine        = -1
  rpkid_port    = -1
  irdbd_port    = -1
  pubd_port     = -1
  rsync_port    = -1
  rootd_port    = -1
  rrdp_port     = -1
  rpkic_counter = 0L

  @classmethod
  def allocate_port(cls):
    """
    Allocate a TCP port.
    """

    cls.base_port += 1
    return cls.base_port

  base_engine = -1

  @classmethod
  def allocate_engine(cls):
    """
    Allocate an engine number, mostly used to construct MySQL database
    names.
    """

    cls.base_engine += 1
    return cls.base_engine

  def __init__(self, yaml, db, parent = None):
    db.append(self)
    self.name = yaml["name"]
    self.parent = parent
    self.kids = [allocation(k, db, self) for k in yaml.get("kids", ())]
    valid_until = None
    if "valid_until" in yaml:
      valid_until = rpki.sundial.datetime.from_datetime(yaml.get("valid_until"))
    if valid_until is None and "valid_for" in yaml:
      valid_until = rpki.sundial.now() + rpki.sundial.timedelta.parse(yaml["valid_for"])
    self.base = rpki.resource_set.resource_bag(
      asn = rpki.resource_set.resource_set_as(yaml.get("asn")),
      v4 = rpki.resource_set.resource_set_ipv4(yaml.get("ipv4")),
      v6 = rpki.resource_set.resource_set_ipv6(yaml.get("ipv6")),
      valid_until = valid_until)
    if "crl_interval" in yaml:
      self.crl_interval = rpki.sundial.timedelta.parse(yaml["crl_interval"]).convert_to_seconds()
    if "regen_margin" in yaml:
      self.regen_margin = rpki.sundial.timedelta.parse(yaml["regen_margin"]).convert_to_seconds()
    self.roa_requests = [roa_request.parse(y) for y in yaml.get("roa_request", yaml.get("route_origin", ()))]
    self.router_certs = [router_cert.parse(y) for y in yaml.get("router_cert", ())]
    if "ghostbusters" in yaml:
      self.ghostbusters = yaml.get("ghostbusters")
    elif "ghostbuster" in yaml:
      self.ghostbusters = [yaml.get("ghostbuster")]
    else:
      self.ghostbusters = []
    for r in self.roa_requests:
      if r.v4:
        self.base.v4 |= r.v4.to_resource_set()
      if r.v6:
        self.base.v6 |= r.v6.to_resource_set()
    for r in self.router_certs:
      self.base.asn |= r.asn
    self.hosted_by = yaml.get("hosted_by")
    self.hosts = []
    if not self.is_hosted:
      self.engine = self.allocate_engine()
      self.rpkid_port = self.allocate_port()
      self.irdbd_port = self.allocate_port()
    if self.runs_pubd:
      self.pubd_port  = self.allocate_port()
      self.rsync_port = self.allocate_port()
      self.rrdp_port  = self.allocate_port()
    if self.is_root:
      self.rootd_port = self.allocate_port()

  def closure(self):
    """
    Compute resource closure of this node and its children, to avoid a
    lot of tedious (and error-prone) duplication in the YAML file.
    """

    resources = self.base
    for kid in self.kids:
      resources |= kid.closure()
    self.resources = resources
    return resources

  def dump(self):
    """
    Show content of this allocation node.
    """

    print str(self)

  def __str__(self):
    s = self.name + ":\n"
    if self.resources.asn:      s += "  ASNs: %s\n" % self.resources.asn
    if self.resources.v4:       s += "  IPv4: %s\n" % self.resources.v4
    if self.resources.v6:       s += "  IPv6: %s\n" % self.resources.v6
    if self.kids:               s += "  Kids: %s\n" % ", ".join(k.name for k in self.kids)
    if self.parent:             s += "    Up: %s\n" % self.parent.name
    if self.is_hosted:          s += "  Host: %s\n" % self.hosted_by.name
    if self.hosts:              s += " Hosts: %s\n" % ", ".join(h.name for h in self.hosts)
    for r in self.roa_requests: s += "   ROA: %s\n" % r
    if not self.is_hosted:      s += " IPort: %s\n" % self.irdbd_port
    if self.runs_pubd:          s += " PPort: %s\n" % self.pubd_port
    if not self.is_hosted:      s += " RPort: %s\n" % self.rpkid_port
    if self.runs_pubd:          s += " SPort: %s\n" % self.rsync_port
    if self.is_root:            s += " TPort: %s\n" % self.rootd_port
    return s + " Until: %s\n" % self.resources.valid_until

  @property
  def is_root(self):
    """
    Is this the root node?
    """

    return self.parent is None

  @property
  def is_hosted(self):
    """
    Is this entity hosted?
    """

    return self.hosted_by is not None

  @property
  def runs_pubd(self):
    """
    Does this entity run a pubd?
    """

    return self.is_root or not (self.is_hosted or only_one_pubd)

  def path(self, *names):
    """
    Construct pathnames in this entity's test directory.
    """

    return cleanpath(test_dir, self.host.name, *names)

  def csvout(self, fn):
    """
    Open and log a CSV output file.
    """

    path = self.path(fn)
    print "Writing", path
    return rpki.csv_utils.csv_writer(path)

  def up_down_url(self):
    """
    Construct service URL for this node's parent.
    """

    return "http://localhost:%d/up-down/%s/%s" % (self.parent.host.rpkid_port,
                                                  self.parent.name,
                                                  self.name)

  def dump_asns(self):
    """
    Write Autonomous System Numbers CSV file.
    """

    fn = "%s.asns.csv" % d.name
    if not args.skip_config:
      with self.csvout(fn) as f:
        for k in self.kids:
          f.writerows((k.name, a) for a in k.resources.asn)
    if not args.stop_after_config:
      self.run_rpkic("load_asns", fn)

  def dump_prefixes(self):
    """
    Write prefixes CSV file.
    """

    fn = "%s.prefixes.csv" % d.name
    if not args.skip_config:
      with self.csvout(fn) as f:
        for k in self.kids:
          f.writerows((k.name, p) for p in (k.resources.v4 + k.resources.v6))
    if not args.stop_after_config:
      self.run_rpkic("load_prefixes", fn)

  def dump_roas(self):
    """
    Write ROA CSV file.
    """

    fn = "%s.roas.csv" % d.name
    if not args.skip_config:
      with self.csvout(fn) as f:
        for g1, r in enumerate(self.roa_requests):
          f.writerows((p, r.asn, "G%08d%08d" % (g1, g2))
                      for g2, p in enumerate((r.v4 + r.v6 if r.v4 and r.v6 else r.v4 or r.v6 or ())))
    if not args.stop_after_config:
      self.run_rpkic("load_roa_requests", fn)

  def dump_ghostbusters(self):
    """
    Write Ghostbusters vCard file.
    """

    if self.ghostbusters:
      fn = "%s.ghostbusters.vcard" % d.name
      if not args.skip_config:
        path = self.path(fn)
        print "Writing", path
        with open(path, "w") as f:
          f.write("\n".join(self.ghostbusters))
      if not args.stop_after_config:
        self.run_rpkic("load_ghostbuster_requests", fn)

  def dump_router_certificates(self):
    """
    Write EE certificates (router certificates, etc).
    """

    if self.router_certs:
      fn = "%s.routercerts.xml" % d.name
      if not args.skip_config:
        path = self.path(fn)
        print "Writing", path
        xmlns = rpki.relaxng.router_certificate.xmlns
        xml = lxml.etree.Element(xmlns + "router_certificate_requests",
                                 version = rpki.relaxng.router_certificate.version,
                                 nsmap = rpki.relaxng.router_certificate.nsmap)
        for r in self.router_certs:
          x = lxml.etree.SubElement(xml, xmlns + "router_certificate_request",
                                    router_id   = str(r.router_id),
                                    asn         = str(r.asn),
                                    valid_until = str(self.resources.valid_until))
          x.text = r.pkcs10.get_Base64()
        rpki.relaxng.router_certificate.assertValid(xml)
        lxml.etree.ElementTree(xml).write(path, pretty_print = True)
      if not args.stop_after_config:
        self.run_rpkic("add_router_certificate_request", fn)
      if not args.skip_config and args.store_router_private_keys:
        path = self.path("%s.routercerts.keys" % d.name)
        print "Writing", path
	with open(path, "w") as f:
	  for r in self.router_certs:
	    f.write(r.keypair.get_PEM())

  @property
  def pubd(self):
    """
    Walk up tree until we find somebody who runs pubd.
    """

    s = self
    while not s.runs_pubd:
      s = s.parent
    return s

  @property
  def client_handle(self):
    """
    Work out what pubd configure_publication_client will call us.
    """

    path = []
    s = self
    if not args.flat_publication:
      while not s.runs_pubd:
        path.append(s)
        s = s.parent
    path.append(s)
    return ".".join(i.name for i in reversed(path))

  @property
  def host(self):
    return self.hosted_by or self

  def dump_conf(self):
    """
    Write configuration file for OpenSSL and RPKI tools.
    """

    r = dict(
      handle                            = self.name,
      run_rpkid                         = str(not self.is_hosted),
      run_pubd                          = str(self.runs_pubd),
      run_rootd                         = str(self.is_root),
      irdbd_sql_database                = "irdb%d" % self.engine,
      irdbd_sql_username                = "irdb",
      rpkid_sql_database                = "rpki%d" % self.engine,
      rpkid_sql_username                = "rpki",
      rpkid_server_host                 = "localhost",
      rpkid_server_port                 = str(self.rpkid_port),
      irdbd_server_host                 = "localhost",
      irdbd_server_port                 = str(self.irdbd_port),
      rootd_server_port                 = str(self.rootd_port),
      pubd_sql_database                 = "pubd%d" % self.engine,
      pubd_sql_username                 = "pubd",
      pubd_server_host                  = "localhost",
      pubd_server_port                  = str(self.pubd.pubd_port),
      publication_rsync_server          = "localhost:%s" % self.pubd.rsync_port,
      publication_rrdp_notification_uri = "http://localhost:%s/rrdp/notify.xml" % self.pubd.rrdp_port,
      bpki_servers_directory            = self.path(),
      publication_base_directory        = self.path("publication"),
      rrdp_publication_base_directory   = self.path("rrdp-publication"),
      shared_sql_password               = "fnord")

    r.update(config_overrides)

    with open(self.path("rpki.conf"), "w") as f:
      f.write("# Automatically generated, do not edit\n")
      print "Writing", f.name

      section = None
      for line in open(cleanpath(ca_dir, "examples/rpki.conf")):
        m = section_regexp.match(line)
        if m:
          section = m.group(1)
        m = variable_regexp.match(line)
        option = m.group(1) if m and section == "myrpki" else None
        if option and option in r:
          line = "%s = %s\n" % (option, r[option])
        f.write(line)

  def dump_rsyncd(self):
    """
    Write rsyncd configuration file.
    """

    if self.runs_pubd:
      with open(self.path("rsyncd.conf"), "w") as f:
        print "Writing", f.name
        f.writelines(s + "\n" for s in
                     ("# Automatically generated, do not edit",
                      "port         = %d"           % self.rsync_port,
                      "address      = localhost",
                      "[rpki]",
                      "log file     = rsyncd.log",
                      "read only    = yes",
                      "use chroot   = no",
                      "path         = %s"           % self.path("publication"),
                      "comment      = RPKI test",
                      "[root]",
                      "log file     = rsyncd_root.log",
                      "read only    = yes",
                      "use chroot   = no",
                      "path         = %s"           % self.path("publication.root"),
                      "comment      = RPKI test root"))

  @classmethod
  def next_rpkic_counter(cls):
    cls.rpkic_counter += 10000
    return str(cls.rpkic_counter)

  def run_rpkic(self, *argv):
    """
    Run rpkic for this entity.
    """

    cmd = [prog_rpkic, "-i", self.name]
    if args.profile:
      cmd.append("--profile")
      cmd.append(self.path("rpkic.%s.prof" % rpki.sundial.now()))
    cmd.extend(str(a) for a in argv if a is not None)
    print 'Running "%s"' % " ".join(cmd)
    env = dict(os.environ,
               YAMLTEST_RPKIC_COUNTER = self.next_rpkic_counter(),
               RPKI_CONF = self.path("rpki.conf"))
    subprocess.check_call(cmd, cwd = self.host.path(), env = env)

  def syncdb(self):
    """
    Run whatever Django ORM commands are necessary to set up the
    database this week.
    """

    # Fork a sub-process for each syncdb/migrate run, because it's
    # easier than figuring out how to change Django settings after
    # initialization.

    def sync_settings(settings, verbosity = 1):

      if verbosity > 0:
        print "Running Django setup for", self.name

      pid = os.fork()

      if pid == 0:
        logging.getLogger().setLevel(logging.WARNING)

        os.environ.update(RPKI_CONF = self.path("rpki.conf"),
                          DJANGO_SETTINGS_MODULE = "rpki.django_settings." + settings)

        import django
        django.setup()

        import django.core.management
        django.core.management.call_command("migrate", verbosity = verbosity, no_color = True,
                                            load_initial_data = False, interactive = False)

        if settings in ("gui", "irdb"):
          from django.contrib.auth.models import User
          User.objects.create_superuser("root", "root@example.org", "fnord")

        sys.exit(0)

      elif os.waitpid(pid, 0)[1]:
        raise RuntimeError("Django setup failed for %s %s" % (self.name, settings))

    for settings in ("rpkid", "pubd", "gui"):
      sync_settings(settings)

  def run_python_daemon(self, prog):
    """
    Start a Python daemon and return a subprocess.Popen object
    representing the running daemon.
    """

    basename = os.path.splitext(os.path.basename(prog))[0]
    cmd = [prog, "--foreground", "--log-level", "debug",
           "--log-file", self.path(basename + ".log")]
    if args.profile and basename != "rootd":
      cmd.extend((
           "--profile",  self.path(basename + ".prof")))
    env = dict(os.environ, RPKI_CONF = self.path("rpki.conf"))
    p = subprocess.Popen(cmd, cwd = self.path(), env = env)
    print "Running %s for %s: pid %d process %r" % (" ".join(cmd), self.name, p.pid, p)
    return p

  def run_rpkid(self):
    """
    Run rpkid.
    """

    return self.run_python_daemon(prog_rpkid)

  def run_irdbd(self):
    """
    Run irdbd.
    """

    return self.run_python_daemon(prog_irdbd)

  def run_pubd(self):
    """
    Run pubd.
    """

    return self.run_python_daemon(prog_pubd)

  def run_rootd(self):
    """
    Run rootd.
    """

    return self.run_python_daemon(prog_rootd)

  def run_rsyncd(self):
    """
    Run rsyncd.
    """

    p = subprocess.Popen(("rsync", "--daemon", "--no-detach", "--config", "rsyncd.conf"),
                         cwd = self.path())
    print "Running rsyncd for %s: pid %d process %r" % (self.name, p.pid, p)
    return p

  def run_gui(self):
    """
    Start an instance of the RPKI GUI under the Django test server and
    return a subprocess.Popen object representing the running daemon.
    """

    port = 8000 + self.engine
    cmd = (prog_rpki_manage, "runserver", str(port))
    env = dict(os.environ,
               RPKI_CONF = self.path("rpki.conf"),
               RPKI_DJANGO_DEBUG = "yes",
               ALLOW_PLAIN_HTTP_FOR_TESTING = "I solemnly swear that I am not running this in production")
    p = subprocess.Popen(cmd, cwd = self.path(), env = env,
                         stdout = open(self.path("gui.log"), "w"), stderr = subprocess.STDOUT)
    print "Running %s for %s: pid %d process %r" % (" ".join(cmd), self.name, p.pid, p)
    return p


def create_root_certificate(db_root):

  print "Creating rootd RPKI root certificate"

  root_resources = rpki.resource_set.resource_bag(
    asn = rpki.resource_set.resource_set_as("0-4294967295"),
    v4  = rpki.resource_set.resource_set_ipv4("0.0.0.0/0"),
    v6  = rpki.resource_set.resource_set_ipv6("::/0"))

  root_key = rpki.x509.RSA.generate(quiet = True)

  root_uri = "rsync://localhost:%d/rpki/%s-root/root" % (db_root.pubd.rsync_port, db_root.name)

  rrdp_uri = "http://localhost:%s/rrdp/notify.xml" % db.root.pubd.rrdp_port

  root_sia = (root_uri + "/", root_uri + "/root.mft", None, rrdp_uri)

  root_cert = rpki.x509.X509.self_certify(
    keypair     = root_key,
    subject_key = root_key.get_public(),
    serial      = 1,
    sia         = root_sia,
    notAfter    = rpki.sundial.now() + rpki.sundial.timedelta(days = 365),
    resources   = root_resources)

  with open(db_root.path("root.cer"), "wb") as f:
    f.write(root_cert.get_DER())

  with open(db_root.path("root.key"), "wb") as f:
    f.write(root_key.get_DER())

  with open(os.path.join(test_dir, "root.tal"), "w") as f:
    f.write(root_uri + ".cer\n\n")
    f.write(root_key.get_public().get_Base64())


logger = logging.getLogger(__name__)

os.environ.update(DJANGO_SETTINGS_MODULE = "rpki.django_settings.irdb",
                  TZ = "UTC")
time.tzset()

parser = argparse.ArgumentParser(description = __doc__)
parser.add_argument("-c", "--config",
                    help = "configuration file")
parser.add_argument("-f", "--flat_publication", action = "store_true",
                    help = "disable hierarchical publication")
parser.add_argument("-k", "--keep_going", action = "store_true",
                    help = "keep going until all subprocesses exit")
parser.add_argument("-p", "--pidfile",
                    help = "save pid to this file")
parser.add_argument("--skip_config", action = "store_true",
                    help = "skip over configuration phase")
parser.add_argument("--stop_after_config", action = "store_true",
                    help = "stop after configuration phase")
parser.add_argument("--synchronize", action = "store_true",
                    help = "synchronize IRDB with daemons")
parser.add_argument("--profile", action = "store_true",
                    help = "enable profiling")
parser.add_argument("-g", "--run_gui", action = "store_true",
                    help = "enable GUI using django-admin runserver")
parser.add_argument("--browser", action = "store_true",
                    help = "create web browser tabs for GUI")
parser.add_argument("--notify-when-startup-complete", type = int,
                    help = "send SIGUSR1 to this process when startup is complete")
parser.add_argument("--store-router-private-keys", action = "store_true",
                    help = "write generate router private keys to disk")
parser.add_argument("yaml_file", type = argparse.FileType("r"),
                    help = "YAML description of test network")
args = parser.parse_args()

try:

  if args.pidfile is not None:
    open(args.pidfile, "w").write("%s\n" % os.getpid())

  rpki.log.init("yamltest", argparse.Namespace(log_level   = logging.DEBUG,
                                               log_handler = lambda: logging.StreamHandler(sys.stdout)))

  # Allow optional config file for this tool to override default
  # passwords: this is mostly so that I can show a complete working
  # example without publishing my own server's passwords.

  cfg = rpki.config.parser(set_filename = args.config, section = "yamltest", allow_missing = True)

  only_one_pubd = cfg.getboolean("only_one_pubd", True)
  allocation.base_port = cfg.getint("base_port", 4400)

  config_overrides = dict(
    (k, cfg.get(k))
    for k in ("rpkid_sql_password", "irdbd_sql_password", "pubd_sql_password",
              "rpkid_sql_username", "irdbd_sql_username", "pubd_sql_username")
    if cfg.has_option(k))

  # Start clean, maybe

  if not args.skip_config:
    for root, dirs, files in os.walk(test_dir, topdown = False):
      for fn in files:
        os.unlink(os.path.join(root, fn))
      for d in dirs:
        os.rmdir(os.path.join(root, d))

  # Read first YAML doc in file and process as compact description of
  # test layout and resource allocations.  Ignore subsequent YAML docs,
  # they're for smoketest.py, not this script.

  db = allocation_db(yaml.safe_load_all(args.yaml_file).next())

  # Show what we loaded

  #db.dump()

  if args.skip_config:

    print "Skipping pre-daemon configuration, assuming you already did that"

  else:

    # Set up each entity in our test, create publication directories,
    # and initialize server BPKI.

    for d in db:
      if not d.is_hosted:
        print "Initializing", d.name
        os.makedirs(d.path())
        d.dump_conf()
        if d.runs_pubd:
          os.makedirs(d.path("publication"))
          d.dump_rsyncd()
        if d.is_root:
          os.makedirs(d.path("publication.root"))
        d.syncdb()
        d.run_rpkic("initialize_server_bpki")
        print

    # Initialize resource holding BPKI and generate self-descriptor
    # for each entity.

    for d in db:
      d.run_rpkic("create_identity", d.name)

    # Create RPKI root certificate.

    create_root_certificate(db.root)

    # Set up rootd.

    db.root.run_rpkic("configure_root")

  # From here on we need to pay attention to initialization order.  We
  # used to do all the pre-configure_daemons stuff before running any
  # of the daemons, but that doesn't work right in hosted cases, so we
  # have to interleave configuration with starting daemons, just as
  # one would in the real world for this sort of thing.

  progs = []

  try:

    for d in db:

      if not d.is_hosted:
        print
        print "Running daemons for", d.name
        if d.is_root:
          progs.append(d.run_rootd())
        progs.append(d.run_irdbd())
        progs.append(d.run_rpkid())
        if d.runs_pubd:
          progs.append(d.run_pubd())
          progs.append(d.run_rsyncd())
        if args.run_gui:
          progs.append(d.run_gui())

    if args.synchronize or not args.skip_config:

      print
      print "Giving daemons time to start up"
      time.sleep(20)
      assert all(p.poll() is None for p in progs)

    if args.skip_config:

      print
      print "Skipping configure_*, you'll have to do that yourself if needed"

    else:

      for d in db:

        print
        print "Configuring", d.name
        print
        if d.is_root:
          assert not d.is_hosted
          d.run_rpkic("configure_publication_client",
                      "--flat" if args.flat_publication else None,
                      d.path("%s.%s.repository-request.xml" % (d.name, d.name)))
          print
          d.run_rpkic("configure_repository",
                      d.path("%s.repository-response.xml" % d.client_handle))
          print
        else:
          d.parent.run_rpkic("configure_child",
                             "--valid_until", d.resources.valid_until,
                             d.path("%s.identity.xml" % d.name))
          print
          d.run_rpkic("configure_parent",
                      d.parent.path("%s.%s.parent-response.xml" % (d.parent.name, d.name)))
          print
          d.pubd.run_rpkic("configure_publication_client",
                           "--flat" if args.flat_publication else None,
                           d.path("%s.%s.repository-request.xml" % (d.name, d.parent.name)))
          print
          d.run_rpkic("configure_repository",
                      d.pubd.path("%s.repository-response.xml" % d.client_handle))
          print

      print
      print "Done with initial configuration"
      print

    if args.synchronize:
      print
      print "Synchronizing"
      print
      for d in db:
        if not d.is_hosted:
          d.run_rpkic("synchronize")

    if args.synchronize or not args.skip_config:
      print
      print "Loading CSV files"
      print
      for d in db:
        d.dump_asns()
        d.dump_prefixes()
        d.dump_roas()
        d.dump_ghostbusters()
        d.dump_router_certificates()

    if args.run_gui:
      print
      print 'GUI user "root", password "fnord"'
      for d in db:
        if not d.is_hosted:
          url = "http://127.0.0.1:%d/rpki/" % (8000 + d.engine)
          print "GUI URL", url, "for", d.name
          if args.browser:
            if d is db.root:
              webbrowser.open_new(url)
            else:
              webbrowser.open_new_tab(url)
            time.sleep(2)

    # Wait until something terminates.

    if not args.stop_after_config or args.keep_going:
      if args.notify_when_startup_complete:
        print
        print "Sending SIGUSR1 to process", args.notify_when_startup_complete
        os.kill(args.notify_when_startup_complete, signal.SIGUSR1)
      print
      print "Waiting for daemons to exit"
      signal.signal(signal.SIGCHLD, lambda *dont_care: None)
      while (any(p.poll() is None for p in progs)
             if args.keep_going else
             all(p.poll() is None for p in progs)):
        signal.pause()

  finally:

    print
    print "Shutting down"
    print

    signal.signal(signal.SIGCHLD, signal.SIG_DFL)

    if args.profile:
      how_long = 300
    else:
      how_long =  30

    how_often = how_long / 2

    for i in xrange(how_long):
      if i % how_often == 0:
        for p in progs:
          if p.poll() is None:
            print "Politely nudging pid %d" % p.pid
            p.terminate()
        print
      if all(p.poll() is not None for p in progs):
        break
      time.sleep(1)

    for p in progs:
      if p.poll() is None:
        print "Pulling the plug on pid %d" % p.pid
        p.kill()

    for p in progs:
      print "Program pid %d %r returned %d" % (p.pid, p, p.wait())

finally:
  if args.pidfile is not None:
    os.unlink(args.pidfile)
