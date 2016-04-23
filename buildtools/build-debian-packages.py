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
Set up for a Debian or Ubuntu package build.

This is a script because we need to create the changelog.  Other than
that, we just copy the Debian skeleton and optionally run the programs
necessary to produce a test build (production builds are happened
elsewhere, under pbuilder).
"""

import subprocess
import platform
import argparse
import shutil
import sys
import os

parser = argparse.ArgumentParser(description = __doc__)
parser.add_argument("-b", "--debuild", action = "store_true", help = "run debuild")
parser.add_argument("-i", "--debi", action = "store_true", help = "run debi")
parser.add_argument("-s", "--version-suffix", nargs = "?", const = platform.linux_distribution()[2],
                    help = "suffix to add to version string")
args = parser.parse_args()

if os.path.exists(".svn"):
    version = "0.{rev}".format(
        rev    = subprocess.check_output(("svnversion", "-c")).strip().split(":")[-1])
elif os.path.exists(".git/svn"):
    git_svn_log = subprocess.check_output(("git", "svn", "log", "--show-commit", "--oneline", "--limit=1")).split()
    version = "0.{rev}.{count}.{commit}".format(
        rev    = git_svn_log[0][1:],
        count  = subprocess.check_output(("git", "rev-list", "--count", git_svn_log[2] + "..HEAD")).strip(),
        commit = git_svn_log[2])
    del git_svn_log
else:
    sys.exit("Sorry, don't know how to extract version number from this source tree")

if os.path.exists("debian"):
    shutil.rmtree("debian")

def ignore_dot_svn(src, names):
    return [name for name in names if name == ".svn"]

shutil.copytree("buildtools/debian-skeleton", "debian", ignore = ignore_dot_svn)

os.chmod("debian/rules", 0755)

msg = "Version %s of https://subvert-rpki.hactrn.net/trunk/" % version

if args.version_suffix:
    version += "~" + args.version_suffix

subprocess.check_call(("dch", "--create", "--package", "rpki", "--newversion",  version, msg),
                      env = dict(os.environ,
                                 EDITOR   = "true",
                                 VISUAL   = "true",
                                 TZ       = "UTC",
                                 DEBEMAIL = "APT Builder Robot <aptbot@rpki.net>"))

if args.debuild or args.debi:
    subprocess.check_call(("debuild", "-us", "-uc"))

if args.debi:
    subprocess.check_call(("sudo", "debi", "--with-depends"))
