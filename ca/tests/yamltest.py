#!/usr/bin/env python

"""
Test framework, using the same YAML test description format as
smoketest.py, but using the rpkic.py tool to do all the back-end
work.  Reads YAML file, generates .csv and .conf files, runs daemons
and waits for one of them to exit.
"""

# $Id$
#
# Copyright (C) 2015--2016  Parsons Government Services ("PARSONS")
# Portions copyright (C) 2013--2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2009--2012  Internet Systems Consortium ("ISC")
# Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND PARSONS, DRL, ISC, AND ARIN
# DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT
# SHALL PARSONS, DRL, ISC, OR ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
# RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
# CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# Much of the YAML handling code lifted from smoketest.py.
#
# Still to do:
#
# - Implement smoketest.py-style delta actions, that is, modify the
#   allocation database under control of the YAML file, dump out new
#   .csv files, and run rpkic.py again to feed resulting changes into
#   running daemons.
#

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
import textwrap
import lxml.etree
import rpki.resource_set
import rpki.sundial
import rpki.log
import rpki.csv_utils
import rpki.x509
import rpki.relaxng
import rpki.config

# pylint: disable=W0621

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

this_dir    = os.getcwd()
test_dir    = cleanpath(this_dir, "yamltest.dir")
ca_dir      = cleanpath(this_dir, "..")
rp_conf_dir = cleanpath(this_dir, "..", "..", "rp", "config")
rpki_dir    = cleanpath(this_dir, "..", "..")

prog_rpkid = cleanpath(ca_dir, "rpkid")
prog_irdbd = cleanpath(ca_dir, "irdbd")
prog_pubd  = cleanpath(ca_dir, "pubd")
prog_rpki_confgen = cleanpath(rp_conf_dir, "rpki-confgen")

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
    engine        = -1
    rpkid_port    = -1
    irdbd_port    = -1
    pubd_port     = -1
    rsync_port    = -1
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
        Allocate an engine number, mostly used to construct SQL database
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
            asn         = str(yaml.get("asn", "")),
            v4          = yaml.get("ipv4"),
            v6          = yaml.get("ipv6"),
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

    def closure(self):
        """
        Compute resource closure of this node and its children, to avoid a
        lot of tedious (and error-prone) duplication in the YAML file.
        """

        resources = self.base
        for kid in self.kids:
            resources |= kid.closure()
        self.resources = resources      # pylint: disable=W0201
        return resources

    def dump(self):
        """
        Show content of this allocation node.
        """

        print str(self)

    def __str__(self):
        # pylint: disable=C0321
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

        return self.is_root or (args.one_pubd_per_rpkid and not self.is_hosted)

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
                for r in self.roa_requests:
                    f.writerows((p, r.asn)
                                for p in (r.v4 + r.v6 if r.v4 and r.v6 else r.v4 or r.v6 or ()))
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
            rpkid_server_host                 = "localhost",
            rpkid_server_port                 = str(self.rpkid_port),
            irdbd_server_host                 = "localhost",
            irdbd_server_port                 = str(self.irdbd_port),
            pubd_server_host                  = "localhost",
            pubd_server_port                  = str(self.pubd.pubd_port),
            publication_rsync_server          = "localhost:%s" % self.pubd.rsync_port,
            publication_rrdp_base_uri         = "https://localhost:%s/" % self.pubd.rrdp_port,
            bpki_servers_directory            = self.path(),
            publication_base_directory        = self.path("publication.rsync"),
            rrdp_publication_base_directory   = self.path("publication.rrdp"),
            shared_sql_engine                 = args.sql_engine,
            shared_sql_password               = "fnord",
            irdbd_sql_username                = "irdb",
            rpkid_sql_username                = "rpki",
            pubd_sql_username                 = "pubd")

        if args.sql_engine == "sqlite3":
            r.update(
                irdbd_sql_database            = self.path("irdb.sqlite3"),
                rpkid_sql_database            = self.path("rpkidb.sqlite3"),
                pubd_sql_database             = self.path("pubdb.sqlite3"))
        else:
            r.update(
                irdbd_sql_database            = "irdb%d" % self.engine,
                rpkid_sql_database            = "rpki%d" % self.engine,
                pubd_sql_database             = "pubd%d" % self.engine)

        fn = self.path("rpki.conf")

        cmd = [sys.executable, prog_rpki_confgen,
               "--read-xml", prog_rpki_confgen + ".xml",
               "--autoconf"]
        for k, v in r.iteritems():
            cmd.extend(("--set", "myrpki::{}={}".format(k, v)))
        cmd.extend(("--write-conf", fn))

        print "Writing", fn
        subprocess.check_call(cmd)

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
                              "path         = %s"           % self.path("publication.rsync"),
                              "comment      = RPKI test",
                              "[root]",
                              "log file     = rsyncd_root.log",
                              "read only    = yes",
                              "use chroot   = no",
                              "path         = %s"           % self.path("publication.root"),
                              "comment      = RPKI test root"))

    def dump_httpsd(self):
        """
        Write certificates for internal RRDP httpsd.
        """

        # For the moment we create a new TA for each httpsd server
        # instance, which will be a mess if the RRDP client wants to
        # verify them.  At the moment, running RRDP over HTTPS is more
        # of a political statement than a technical requirement
        # derived from the underlying security model, so we defer
        # shaving that yak for another day.  Likewise, we defer
        # deciding whether we really only wanted one TA/EE pair for an
        # entire yamltest run, or perhaps a single TA and multiple EEs
        # (all with the same name!), or ....
        #
        # If and when we ever deal with this, we might also see about
        # getting the Django test GUI server to run over TLS.  Then
        # again, since we have no sane way of telling the user's web
        # browser about our TA, this pretty much guarantees a lot of
        # tedious browser exception pop-ups every time.  Feh.

        if self.runs_pubd:
            print "Creating certificates for %s RRDP HTTPS server" % self.name

            ca_key = rpki.x509.RSA.generate(quiet = True)
            ee_key = rpki.x509.RSA.generate(quiet = True)
            ca_dn  = rpki.x509.X501DN.from_cn("%s RRDP HTTPS trust anchor" % self.name)
            ee_dn  = rpki.x509.X501DN.from_cn("localhost")
            notAfter  = rpki.sundial.now() + rpki.sundial.timedelta(days = 365)

            ca_cer = rpki.x509.X509.bpki_self_certify(
                keypair      = ca_key,
                subject_name = ca_dn,
                serial       = 1,
                notAfter     = notAfter)

            ee_cer = ca_cer.bpki_certify(
                keypair      = ca_key,
                subject_name = ee_dn,
                subject_key  = ee_key.get_public(),
                serial       = 2,
                notAfter     = notAfter,
                is_ca        = False)

            with open(self.path("httpsd.client.pem"), "w") as f:
                f.write(ca_cer.get_PEM())

            with open(self.path("httpsd.server.pem"), "w") as f:
                f.write(ee_key.get_PEM())
                f.write(ee_cer.get_PEM())
                f.write(ca_cer.get_PEM())

    @classmethod
    def next_rpkic_counter(cls):
        cls.rpkic_counter += 10000
        return str(cls.rpkic_counter)

    def run_rpkic(self, *argv):
        """
        Run rpkic for this entity.
        """

        cmd = [sys.executable, "-c", "import rpki.rpkic; rpki.rpkic.main()", "-i", self.name]
        if args.profile:
            cmd.append("--profile")
            cmd.append(self.path("rpkic.{!s}.prof".format(rpki.sundial.now())))
        cmd.extend(str(a) for a in argv if a is not None)
        print 'Running "rpkic {}"'.format(" ".join(cmd[3:]))
        env = dict(os.environ,
                   YAMLTEST_RPKIC_COUNTER = self.next_rpkic_counter(),
                   RPKI_CONF = self.path("rpki.conf"),
                   PYTHONPATH = rpki_dir)
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
        cmd = [prog, "--foreground", 
               "--log-level", "debug", 
               "--log-destination", "file",
               "--log-filename", self.path(basename + ".log")]
        if args.profile:
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

    def run_rsyncd(self):
        """
        Run rsyncd.
        """

        p = subprocess.Popen(("rsync", "--daemon", "--no-detach", "--config", "rsyncd.conf"),
                             cwd = self.path())
        print "Running rsyncd for %s: pid %d process %r" % (self.name, p.pid, p)
        return p

    def run_httpsd(self):
        """
        Run httpsd (minimal HTTPS server, for RRDP).
        """

        # Minimal HTTPS server hack from:
        # https://www.piware.de/2011/01/creating-an-https-server-in-python/
        # coded as a script so that we can run this using the
        # subprocess API used by all our other daemon processes.

        if self.runs_pubd:
            script = textwrap.dedent('''\
                import BaseHTTPServer, SimpleHTTPServer, ssl
                httpd = BaseHTTPServer.HTTPServer(("localhost", {port}), SimpleHTTPServer.SimpleHTTPRequestHandler)
                httpd.socket = ssl.wrap_socket(httpd.socket, server_side = True, certfile = "{pem}")
                httpd.serve_forever()
                '''.format(port = self.rrdp_port, pem = self.path("httpsd.server.pem")))
            p = subprocess.Popen((sys.executable, "-c", script),
                                 stdout = open(self.path("httpsd.log"), "w"), stderr = subprocess.STDOUT,
                                 cwd = self.path("publication.rrdp"))
            print "Running httpsd for %s: pid %d process %r" % (self.name, p.pid, p)
            return p

    def run_gui(self):
        """
        Start an instance of the RPKI GUI under the Django test server and
        return a subprocess.Popen object representing the running daemon.
        """

        env = dict(os.environ,
                   RPKI_CONF = self.path("rpki.conf"),
                   DJANGO_SETTINGS_MODULE = "rpki.django_settings.gui",
                   RPKI_DJANGO_DEBUG = "yes",
                   LANG = "en_US.UTF-8",
                   ALLOW_PLAIN_HTTP_FOR_TESTING = "I solemnly swear that I am not running this in production")

        if False:
            # This ought to work, doesn't.  Looks like some kind of Django argv hairball.
            cmd = (sys.executable, "-c", textwrap.dedent('''\
                import django
                django.setup()
                import django.core.management
                django.core.management.call_command("runserver", "{port}")
                '''.format(port = 8000 + self.engine)))
        else:
            cmd = ("django-admin", "runserver", str(8000 + self.engine))

        p = subprocess.Popen(cmd, cwd = self.path(), env = env,
                             stdout = open(self.path("gui.log"), "w"), stderr = subprocess.STDOUT)
        print "Running GUI for %s: pid %d process %r" % (self.name, p.pid, p)
        return p

    def extract_root_cert_and_tal(self):
        """
        Use rpkic to extract the root certficate and TAL and place them
        where we can use them to check the published result using rcynic.
        """

        print
        self.run_rpkic("extract_root_tal", "--output", 
                       os.path.join(test_dir, "root.tal"))

        root_cer = self.path("root.cer")
        self.run_rpkic("extract_root_certificate", "--output", root_cer)
        gski = rpki.x509.X509(DER_file = root_cer).gSKI()
        fn = self.path("publication.rrdp", gski + ".cer")
        print "Linking", root_cer
        print "to     ", fn
        os.link(root_cer, fn)


logger = logging.getLogger(__name__)

os.environ.update(DJANGO_SETTINGS_MODULE = "rpki.django_settings.irdb",
                  TZ = "UTC")
time.tzset()

parser = argparse.ArgumentParser(description = __doc__)
parser.add_argument("-f", "--flat-publication", action = "store_true",
                    help = "disable hierarchical publication")
parser.add_argument("-k", "--keep-going", action = "store_true",
                    help = "keep going until all subprocesses exit")
parser.add_argument("-p", "--pidfile",
                    help = "save pid to this file")
parser.add_argument("--skip-config", action = "store_true",
                    help = "skip over configuration phase")
parser.add_argument("--stop-after-config", action = "store_true",
                    help = "stop after configuration phase")
parser.add_argument("--synchronize", action = "store_true",
                    help = "synchronize IRDB with daemons")
parser.add_argument("--profile", action = "store_true",
                    help = "enable profiling")
parser.add_argument("-g", "--run-gui", "--gui", action = "store_true",
                    help = "enable GUI using django-admin runserver")
parser.add_argument("--no-browser", action = "store_true",
                    help = "don't create web browser tabs for GUI")
parser.add_argument("--notify-when-startup-complete", type = int,
                    help = "send SIGUSR1 to this process when startup is complete")
parser.add_argument("--store-router-private-keys", action = "store_true",
                    help = "write generate router private keys to disk")
parser.add_argument("--sql-engine", choices = ("mysql", "sqlite3", "postgresql"), default = "sqlite3",
                    help = "select SQL engine to use")
parser.add_argument("--one-pubd-per-rpkid", action = "store_true",
                    help = "enable separate a pubd process for each rpkid process")
parser.add_argument("--base-port", type = int, default = 4400,
                    help = "base port number for allocated TCP ports")
parser.add_argument("yaml_file", type = argparse.FileType("r"),
                    help = "YAML description of test network")
args = parser.parse_args()

try:

    if args.pidfile is not None:
        with open(args.pidfile, "w") as f:
            print "Writing pidfile", f.name
            f.write("%s\n" % os.getpid())

    log_handler = logging.StreamHandler(sys.stdout)
    log_handler.setFormatter(rpki.config.Formatter("yamltest", log_handler, logging.DEBUG))
    logging.getLogger().addHandler(log_handler)
    logging.getLogger().setLevel(logging.DEBUG)

    allocation.base_port = args.base_port

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
                    os.makedirs(d.path("publication.rsync"))
                    os.makedirs(d.path("publication.rrdp"))
                    d.dump_rsyncd()
                    d.dump_httpsd()
                d.syncdb()
                d.run_rpkic("initialize_server_bpki")
                print

        # Initialize resource holding BPKI and generate self-descriptor
        # for each entity.

        for d in db:
            d.run_rpkic("create_identity", d.name)

        # Set up root

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
                progs.append(d.run_irdbd())
                progs.append(d.run_rpkid())
                if d.runs_pubd:
                    progs.append(d.run_pubd())
                    progs.append(d.run_rsyncd())
                    progs.append(d.run_httpsd())
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

        db.root.extract_root_cert_and_tal()

        if args.run_gui:
            print
            print 'GUI user "root", password "fnord"'
            gui_count = 0
            for d in db:
                if not d.is_hosted:
                    url = "http://127.0.0.1:%d/rpki/" % (8000 + d.engine)
                    print "GUI URL", url, "for", d.name
                    if not args.no_browser:
                        gui_count += 1
                        if d is db.root:
                            webbrowser.open_new(url)
                        else:
                            webbrowser.open_new_tab(url)
                        time.sleep(2)
            if gui_count > 1:
                print "Warning: Logging into more than one GUI instance at once will probably fail due to CSRF protection"

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

except Exception, e:
    print "Blowing out on exception", str(e)
    raise

finally:
    if args.pidfile is not None and os.path.exists(args.pidfile):
        os.unlink(args.pidfile)

# Local Variables:
# indent-tabs-mode: nil
# End:
