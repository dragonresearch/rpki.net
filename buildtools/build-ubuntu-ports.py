# Set up for an Ubuntu package build.
#
# This is a script because we need to set the changelog, and some day
# we may need to do something about filtering specific files so we can
# use the same skeleton for both Ubuntu and Debian builds without
# requiring them to be identical.
#
# For now, though, this just copies the debian skeleton and creates a
# changelog.
#
# $Id$
#
# Copyright (C) 2013  Internet Systems Consortium ("ISC")
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

import subprocess
import shutil
import sys
import os

version = "0." + subprocess.check_output(("svnversion", "-c")).strip().split(":")[-1]

shutil.copytree("buildtools/debian-skeleton", "debian")

subprocess.check_call(("dch", "--create", "--package", "rpki", "--newversion",  version,
                       "Version %s of https://subvert-rpki.hactrn.net/trunk/" % version),
                      env = dict(os.environ,
                                 EDITOR   = "true",
                                 VISUAL   = "true",
                                 TZ       = "UTC",
                                 DEBEMAIL = "APT Builder Robot <aptbot@rpki.net>"))
