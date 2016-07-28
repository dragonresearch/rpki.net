#!/usr/bin/env python

# Copyright (C) 2016 Parsons Government Services ("PARSONS")
# Portions copyright (C) 2013 Internet Systems Consortium ("ISC")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND PARSONS AND ISC DISCLAIM
# ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL
# PARSONS OR ISC BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
# OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
Kludge to extract revision information from environment at build
time, if possible, using it to construct the software version number
that one of our users so desperately wants us to have.  This is a
bit tricky because we want this to be automatic, want it to work
whether installing from binary package or git checkout or frozen
tarball, and need to be careful both to update it whenever the
revision changes and not to stomp on it when the git revision
information isn't available.
"""

import subprocess
import argparse
import time
import sys

parser = argparse.ArgumentParser(description = __doc__)
parser.add_argument("--stdout", action = "store_true", help = "write version information to stdout")

# The next two are only for use by other build scripts.  Using these directly will
# likely result in version numbering that diverges from the semi-official packaged
# binaries, which is unlikely to be what you want.  Because of this, we suppress all
# mention of these options from the --help output.

parser.add_argument("--build-tag",     action = "store_true", help = argparse.SUPPRESS)
parser.add_argument("--major-version", default = "1.0",       help = argparse.SUPPRESS)

args = parser.parse_args()

if args.build_tag:
    try:
        subprocess.check_call(("git", "describe", "--match", "buildbot-*", "--exact"),
                              stdout = open("/dev/null", "w"), stderr = subprocess.STDOUT)
    except subprocess.CalledProcessError:
        subprocess.check_call(("git", "tag", "-a", "-m", "Build robot",
                               "buildbot-{}.{}".format(args.major_version, int(time.time()))))

try:
    ver = subprocess.check_output(("git", "describe", "--match", "buildbot-*", "--dirty"), stderr = open("/dev/null", "w")).strip()
except subprocess.CalledProcessError:
    ver = None

try:
    old = open("VERSION", "r").read().strip()
except IOError:
    old = None

if ver is None:
    ver = old

if ver is None and old is None:
    sys.exit("Could not determine software version")

if ver != old:
    with open("rpki/version.py", "w") as f:
        f.write("VERSION = \"{}\"\n".format(ver))
    with open("VERSION", "w") as f:
        f.write("{}\n".format(ver))

if args.stdout:
    sys.stdout.write("{}\n".format(ver))
