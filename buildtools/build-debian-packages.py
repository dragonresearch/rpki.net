# Copyright (C) 2015--2016  Parsons Government Services ("PARSONS")
# Portions copyright (C) 2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2013  Internet Systems Consortium ("ISC")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND PARSONS, DRL, AND ISC DISCLAIM
# ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL
# PARSONS, DRL, OR ISC BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
# OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

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

version = subprocess.check_output((sys.executable, os.path.join(os.path.dirname(sys.argv[0]), "make-version.py"), "--stdout")).strip()

if os.path.exists("debian"):
    shutil.rmtree("debian")

shutil.copytree("buildtools/debian-skeleton", "debian")

os.chmod("debian/rules", 0755)

msg = "Version {} of RPKI toolkit".format(version)

assert version.startswith("buildbot-")

version = version[len("buildbot-"):].replace("-", ".")

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
