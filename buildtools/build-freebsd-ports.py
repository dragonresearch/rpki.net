# $Id$
#
# Copyright (C) 2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2012-2013  Internet Systems Consortium ("ISC")
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
Construct FreeBSD port directories.

This is a script because we need to generate package lists and update
version numbers in the Makefiles.
"""

import sys
import os
import re
import subprocess
import errno
import glob
import shutil
import argparse

def check_dir(s):
  if not os.path.isdir(s):
    raise argparse.ArgumentTypeError("%r is not a directory" % s)
  return s

parser = argparse.ArgumentParser(description = __doc__)
parser.add_argument("--allow-dirty", action = "store_true",
                    help = "don't insist on pristine subversion checkout")
parser.add_argument("--make-package", action = "store_true",
                    help = "build binary package")
parser.add_argument("--no-clean", action = "store_true",
                    help = "don't clean port after staging etc (implies --no-tarball)")
parser.add_argument("--no-tarball", action = "store_true",
                    help = "don't create tarball of generated port")
parser.add_argument("svndir", metavar = "subversion-working-directory", type = check_dir,
                    help = "directory containing subversion working tree")
args = parser.parse_args()

svnversion = subprocess.check_output(("svnversion", "-c", args.svndir)).strip().split(":")[-1]

if args.allow_dirty:
  svnversion = svnversion.translate(None, "M")

if not svnversion.isdigit():
  sys.exit("Sources don't look pristine, not building (%r)" % svnversion)

branch  = os.path.basename(args.svndir.rstrip(os.path.sep))

if branch != "trunk" and (branch[:2] != "tk" or not branch[2:].isdigit()):
  sys.exit("Could not parse branch from working directory name, not building (%r)" % branch)

version = "0." + svnversion
tarname = "rpki-%s-r%s" % (branch, svnversion)
tarball = tarname + ".tar.xz"
url     = "http://download.rpki.net/" + tarball

portsdir = os.path.abspath("freebsd-ports")
portsdir_old = portsdir + ".old"

# Could perhaps use distutils.sysconfig.get_python_lib() instead of
# this regexp hack, but would be just as complicated in its own way,
# so just go with this for the moment.

py_lib     = re.compile(r"^lib/python\d+\.\d+")
py_sitelib = re.compile(r"^lib/python\d+\.\d+/site-packages")

if os.path.isdir(portsdir_old):
  shutil.rmtree(portsdir_old)

if os.path.isdir(portsdir):
  os.rename(portsdir, portsdir_old)

shutil.copytree(os.path.join(args.svndir, "buildtools", "freebsd-skeleton"), portsdir)

if os.path.exists(os.path.join(portsdir_old, tarball)):
  os.link(os.path.join(portsdir_old, tarball), os.path.join(portsdir, tarball))
elif os.path.exists(os.path.join("/usr/ports/distfiles", tarball)):
  shutil.copy(os.path.join("/usr/ports/distfiles", tarball), os.path.join(portsdir, tarball))

if os.path.isdir(portsdir_old):
  shutil.rmtree(portsdir_old)

if args.make_package:
  pkgdir = os.path.join(portsdir, "packages")
  os.mkdir(pkgdir)

formatdict = dict(SVNVERSION = svnversion, SVNBRANCH  = branch)

keepdirs = ("usr", "etc", "bin", "var", "lib", "libexec", "sbin", "share", "etc/rc.d", "%%PYTHON_SITELIBDIR%%")

for port in ("rpki-rp", "rpki-ca"):

  base = os.path.join(portsdir, port)
  stage = os.path.join(base, "work", "stage")
  fn = os.path.join(portsdir, port, "Makefile")
  with open(fn, "r") as f:
    template = f.read()
  with open(fn, "w") as f:
    f.write(template % formatdict)

  subprocess.check_call(("make", "makesum", "stage", "DISTDIR=" + portsdir), cwd = base)

  with open(os.path.join(base, "pkg-plist"), "w") as f:
    usr_local = None
    for dirpath, dirnames, filenames in os.walk(stage, topdown = False):
      dn = dirpath[len(stage)+1:]
      if dn.startswith("usr/local"):
        if not usr_local and usr_local is not None:
          f.write("@cwd\n")
        usr_local = True
        dn = dn[len("usr/local/"):]
        dn = py_sitelib.sub("%%PYTHON_SITELIBDIR%%", dn)
        if dn == "etc/rc.d":
          continue
      else:
        if usr_local:
          f.write("@cwd /\n")
        usr_local = False
      for fn in filenames:
        f.write(os.path.join(dn, fn) + "\n")
      if dn and dn not in keepdirs and not py_lib.match(dn):
        f.write("@dirrm %s\n" % dn)

  if args.make_package:
    subprocess.check_call(("make", "clean", "package", "PKGREPOSITORY=" + pkgdir), cwd = base)

  if not args.no_clean:
    subprocess.check_call(("make", "clean"), cwd = base)

  if not args.no_tarball and not args.no_clean:
    subprocess.check_call(("tar", "czf", "%s-port.tgz" % port, port), cwd = portsdir)
