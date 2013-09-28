#!/usr/bin/python
#
# $Id$
#
# Copyright (C) 2013 Internet Systems Consortium ("ISC")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

import os
import sys
import time
import fcntl
import errno
import socket
import subprocess

debug  = False
upload = socket.getfqdn() == "build-u.rpki.net"

def run(*args, **kwargs):
    if debug:
        log("Running %r %r" % (args, kwargs))
    subprocess.check_call(args, **kwargs)

def log(msg):
    # Maybe this should go to syslog instead, but this works for now.
    sys.stdout.write(time.strftime("%Y-%m-%dT%H:%M:%SZ ", time.gmtime()))
    sys.stdout.write(msg)
    sys.stdout.write("\n")
    sys.stdout.flush()

lockfile = os.path.expanduser("~/builder.lock")
svn_tree = os.path.expanduser("~/source/trunk/")
apt_tree = os.path.expanduser("~/repository/")
ubu_tree = os.path.join(apt_tree, "ubuntu/")
deb_tree = os.path.join(apt_tree, "debian/")
srv_path = "aptbot@download.rpki.net:/usr/local/www/data/download.rpki.net/APT/"
ubu_env  = dict(os.environ,
                OTHERMIRROR = "deb http://download.rpki.net/APT/ubuntu precise main")
deb_env  = os.environ

try:
    lock = os.open(lockfile, os.O_RDONLY | os.O_CREAT | os.O_NONBLOCK, 0666)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
except (IOError, OSError), e:
    sys.exit(0 if e.errno == errno.EAGAIN else "Error %r opening lock %r" % lockfile)

os.chdir(svn_tree)

run("svn", "--quiet", "update")

version = subprocess.check_output(("svnversion", "-c")).strip().split(":")[-1]

if not version.isdigit() and not debug:
    sys.exit("Sources don't look pristine, not building (%r)" % version)

version = "0." + version

dsc = os.path.join(svn_tree, "..", "rpki_%s.dsc" % version)

if not os.path.exists(dsc):
    log("Building source package %s" % version)
    for fn in os.listdir(".."):
        if fn != "trunk":
            os.unlink(os.path.join("..", fn))
    run("rm", "-rf", "debian")
    run("python", "buildtools/make-version.py")
    run("python", "buildtools/build-ubuntu-ports.py")
    run("dpkg-buildpackage", "-S", "-us", "-uc", "-rfakeroot")

for dist, tree, env in (("precise", ubu_tree, ubu_env),
                        ("wheezy",  deb_tree, deb_env)):

    for arch, tag in (("amd64", ""), ("i386",  "-i386")):

        basedir = os.path.expanduser("~/pbuilder/%s%s-base.tgz" % (dist, tag))
        result  = os.path.expanduser("~/pbuilder/%s%s_result" % (dist, tag))
        changes = os.path.join(result, "rpki_%s_%s.changes" % (version, arch))

        # Update the build environment if it's been more than a week since
        # we last did that.  If this turns out to be error-prone, we might
        # want to put it in a cron job of its own so it doesn't crash the
        # normal cycle, but let's try it this way for a start.
        #
        if time.time() > os.stat(basedir).st_mtime + (7 * 24 * 60 * 60):
            log("Updating build environment %s %s" % (dist, arch))
            run("pbuilder-dist", dist, arch, "update",
                env = env)

        if not os.path.exists(changes):
            # The need for --ignore=wrongdistribution may indicate
            # something I'm doing wrong in hack-debian-changelog.py,
            # revisit that later.  For now, just whack with a stick.
            #
            log("Building binary packages %s %s %s" % (dist, arch, version))
            for fn in os.listdir(result):
                os.unlink(os.path.join(result, fn))
            run("pbuilder-dist", dist, arch, "build", dsc,
                env = env)
            run("reprepro", "--ignore=wrongdistribution", "include", dist, changes,
                cwd = tree)

if upload:
    run("rsync", "-ai4",
        "--ignore-existing",
        apt_tree, srv_path)
    run("rsync", "-ai4",
        "--exclude", "HEADER.html",
        "--exclude", "HEADER.css",
        "--delete", "--delete-delay",
        apt_tree, srv_path)
