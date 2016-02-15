#!/usr/bin/python
#
# $Id$
#
# Copyright (C) 2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2013  Internet Systems Consortium ("ISC")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL AND ISC DISCLAIM ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL DRL OR
# ISC BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
# DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA
# OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
# TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
Debian/Ubuntu package build tool, based on pbuilder-dist and reprepro.
"""

import os
import sys
import time
import fcntl
import errno
import socket
import logging
import argparse
import subprocess

from textwrap import dedent

rpki_packages = ("rpki-rp", "rpki-ca")
rpki_source_package = "rpki"

parser = argparse.ArgumentParser(description = __doc__,
                                 formatter_class = argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("--debug", action = "store_true",
                    help = "enable debugging code")
parser.add_argument("--update-build-after", type = int, default = 7 * 24 * 60 * 60,
                    help = "interval (in seconds) after which we should update the pbuilder environment")
parser.add_argument("--lockfile", default = os.path.expanduser("~/builder.lock"),
                    help = "avoid collisions between multiple instances of this script")
parser.add_argument("--keyring",  default = os.path.expanduser("~/.gnupg/pubring.gpg"),
                    help = "PGP keyring")
parser.add_argument("--svn-tree", default = os.path.expanduser("~/source/trunk/"),
                    help = "subversion tree")
parser.add_argument("--apt-tree", default = os.path.expanduser("~/repository/"),
                    help = "reprepro repository")
parser.add_argument("--srv-path", default = "aptbot@download.rpki.net:/usr/local/www/data/download.rpki.net/APT/",
                    help = "upload destination")
parser.add_argument("--source-format", default = "http://download.rpki.net/APT/%(distribution)s %(release)s main",
                    help = "source.list format string")
args = parser.parse_args()

# Maybe logging should be conigurable too.  Later.

logging.basicConfig(level = logging.INFO, timefmt = "%Y-%m-%dT%H:%M:%S",
                    format = "%(asctime)s [%(process)d] %(levelname)s %(message)s")

upload = socket.getfqdn() == "build-u.rpki.net"

def run(*cmd, **kwargs):
    if args.debug:
        #logging.info("Running %r %r", cmd, kwargs)
        logging.info("Running %s", " ".join(cmd))
    subprocess.check_call(cmd, **kwargs)

# Getting this to work right also required adding:
#
#   DEBBUILDOPTS="-b"
#
# to /etc/pbuilderrc; without this, reprepro (eventually, a year after
# we set this up) started failing to incorporate some of the built
# packages, because the regenerated source packages had different
# checksums than the ones loaded initially.  See:
#
# http://stackoverflow.com/questions/21563872/reprepro-complains-about-the-generated-pbuilder-debian-tar-gz-archive-md5
#
# Putting stuff in ~/.pbuilderrc didn't work with pbuilder-dist when I
# tried it last year, this may just be that sudo isn't configured to
# pass HOME through, thus pbuilder is looking for ~root/.pbuilderrc.
# Worth trying again at some point but not all that critical.

logging.info("Starting")

try:
    lock = os.open(args.lockfile, os.O_RDONLY | os.O_CREAT | os.O_NONBLOCK, 0666)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
except (IOError, OSError), e:
    sys.exit(0 if e.errno == errno.EAGAIN else "Error %r opening lock %r" % args.lockfile)

run("svn", "--quiet", "update", cwd = args.svn_tree)

source_version = subprocess.check_output(("svnversion", "-c"), cwd = args.svn_tree).strip().split(":")[-1]

if not source_version.isdigit() and not args.debug:
    sys.exit("Sources don't look pristine, not building (%r)" % source_version)

source_version = "0." + source_version
search_version = "_" + source_version + "~"

dsc_dir = os.path.abspath(os.path.join(args.svn_tree, ".."))

if not os.path.isdir(args.apt_tree):
    logging.info("Creating %s", args.apt_tree)
    os.makedirs(args.apt_tree)

fn = os.path.join(args.apt_tree, "apt-gpg-key.asc")
if not os.path.exists(fn):
    logging.info("Creating %s", fn)
    run("gpg", "--export", "--armor", "--keyring", args.keyring, stdout = open(fn, "w"))

class Release(object):

    architectures = dict(amd64 = "", i386 = "-i386")

    releases = []
    packages = {}

    def __init__(self, release, distribution, *backports):
        self.release = release
        self.distribution = distribution
        self.backports = backports
        if backports:
            self.env = dict(os.environ,
                            OTHERMIRROR = "deb " + args.source_format  % dict(distribution = distribution, release = release))
        else:
            self.env = os.environ
        self.releases.append(self)

    @classmethod
    def do_all_releases(cls):
        for release in cls.releases:
            release.setup_reprepro()
        for release in cls.releases:
            release.list_repository()
        for release in cls.releases:
            for release.arch, release.tag in cls.architectures.iteritems():
                release.do_one_architecture()
            del release.arch, release.tag

    @staticmethod
    def repokey(release, architecture, package):
        return (release, architecture, package)

    def list_repository(self):
        cmd = ("reprepro", "list", self.release)
        logging.info("Running %s", " ".join(cmd))
        listing = subprocess.check_output(cmd, cwd = self.tree)
        for line in listing.replace(":", " ").replace("|", " ").splitlines():
            rel, comp, arch, pkg, ver = line.split()
            key = (rel, arch, pkg)
            assert key not in self.packages
            self.packages[key] = ver

    @property
    def deb_in_repository(self):
        return all(self.packages.get((self.release, self.arch, package)) == self.version
                   for package in rpki_packages)

    @property
    def src_in_repository(self):
        return self.packages.get((self.release, "source", rpki_source_package)) == self.version

    @property
    def version(self):
        return source_version + "~" + self.release

    @property
    def dsc(self):
        return os.path.join(dsc_dir, "rpki_%s.dsc" % self.version)

    @property
    def tree(self):
        return os.path.join(args.apt_tree, self.distribution, "")

    @property
    def basefile(self):
        return os.path.expanduser("~/pbuilder/%s%s-base.tgz" % (self.release, self.tag))

    @property
    def result(self):
        return os.path.expanduser("~/pbuilder/%s%s_result" % (self.release, self.tag))

    @property
    def changes(self):
        return os.path.join(self.result, "rpki_%s_%s.changes" % (self.version, self.arch))

    def do_one_architecture(self):
        logging.info("Running build for %s %s %s", self.distribution, self.release, self.arch)

        if not os.path.exists(self.dsc):
            logging.info("Building source package %s", self.version)
            for fn in os.listdir(dsc_dir):
                if fn != "trunk" and search_version not in fn:
                    os.unlink(os.path.join(dsc_dir, fn))
            run("rm", "-rf", "debian", cwd = args.svn_tree)
            run(sys.executable, "buildtools/make-version.py", cwd = args.svn_tree)
            run(sys.executable, "buildtools/build-debian-packages.py", "--version-suffix", self.release, cwd = args.svn_tree)
            run("dpkg-buildpackage", "-S", "-us", "-uc", "-rfakeroot", cwd = args.svn_tree)

        if not os.path.exists(self.basefile):
            logging.info("Creating build environment %s %s", self.release, self.arch)
            run("pbuilder-dist", self.release, self.arch, "create", env = self.env)

        elif time.time() > os.stat(self.basefile).st_mtime + args.update_build_after:
            logging.info("Updating build environment %s %s", self.release, self.arch)
            run("pbuilder-dist", self.release, self.arch, "update", env = self.env)

        if not os.path.exists(self.changes):
            logging.info("Building binary packages %s %s %s", self.release, self.arch, self.version)
            for fn in os.listdir(self.result):
                os.unlink(os.path.join(self.result, fn))
            run("pbuilder-dist", self.release, self.arch, "build", "--keyring", args.keyring, self.dsc, env = self.env)

        if not self.deb_in_repository:
            logging.info("Updating repository for %s %s %s", self.release, self.arch, self.version)
            run("reprepro", "--ignore=wrongdistribution", "include", self.release, self.changes, cwd = self.tree)

        if not self.src_in_repository:
            logging.info("Updating repository for %s source %s", self.release, self.version)
            run("reprepro", "--ignore=wrongdistribution", "includedsc", self.release, self.dsc, cwd = self.tree)

    def setup_reprepro(self):

        logging.info("Configuring reprepro for %s/%s", self.distribution, self.release)

        dn = os.path.join(self.tree, "conf")
        if not os.path.isdir(dn):
            logging.info("Creating %s", dn)
            os.makedirs(dn)

        fn = os.path.join(self.tree, "conf", "distributions")
        distributions = open(fn, "r").read() if os.path.exists(fn) else ""
        if ("Codename: %s\n" % self.release) not in distributions:
            logging.info("%s %s", "Editing" if distributions else "Creating", fn)
            with open(fn, "w") as f:
                if distributions:
                    f.write(distributions)
                    f.write("\n")
                f.write(dedent("""\
                        Origin: rpki.net
                        Label: rpki.net %(distribution)s repository
                        Codename: %(release)s
                        Architectures: %(architectures)s source
                        Components: main
                        Description: rpki.net %(Distribution)s APT Repository
                        SignWith: yes
                        DebOverride: override.%(release)s
                        DscOverride: override.%(release)s
                        """ % dict(
                    distribution  = self.distribution,
                    Distribution  = self.distribution.capitalize(),
                    architectures = " ".join(self.architectures),
                    release       = self.release)))

        fn = os.path.join(self.tree, "conf", "options")
        if not os.path.exists(fn):
            logging.info("Creating %s", fn)
            with open(fn, "w") as f:
                f.write(dedent("""\
                        verbose
                        ask-passphrase
                        basedir .
                        """))

        fn = os.path.join(self.tree, "conf", "override." + self.release)
        if not os.path.exists(fn):
            logging.info("Creating %s", fn)
            with open(fn, "w") as f:
                for pkg in self.backports:
                    f.write(dedent("""\
                        %-30s   Priority        optional
                        %-30s   Section         python
                        """ % (pkg, pkg)))
                f.write(dedent("""\
                        rpki-ca                 Priority        extra
                        rpki-ca                 Section         net
                        rpki-rp                 Priority        extra
                        rpki-rp                 Section         net
                        """))

        fn = os.path.join(args.apt_tree, "rpki.%s.list" % self.release)
        if not os.path.exists(fn):
            logging.info("Creating %s", fn)
            source = args.source_format % dict(distribution = self.distribution, release = self.release)
            with open(fn, "w") as f:
                f.write("deb %s\n" % source)
                f.write("deb-src %s\n" % source)

# Finally, here's where we specify the distributions for which we're building.

Release("trusty", "ubuntu", "python-django-south")
Release("wheezy", "debian", "python-django", "python-django-south")
Release("precise", "ubuntu", "python-django", "python-django-south")

# Do all the real work.

Release.do_all_releases()

# Upload results, maybe.

if upload:
    logging.info("Synching repository to server")
    run("rsync", "-ai4",
        "--ignore-existing",
        args.apt_tree, args.srv_path)
    run("rsync", "-ai4",
        "--exclude", "HEADER.html",
        "--exclude", "HEADER.css",
        "--delete", "--delete-delay",
        args.apt_tree, args.srv_path)

logging.info("Done")
