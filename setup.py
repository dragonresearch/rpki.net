# Experimental top-level setup.py for rpki CA tools.
# 
# This is not yet ready for prime time.
#
# General idea here is that we can use this with Python-aware platform
# packaging systems, and our code here deals with the strange build
# environment required when the system copy of OpenSSL isn't usable.
#
# So yes, you are seeing a setup.py which calls autoconf and make.
# Strange, but so long as it works as Python expects, good enough.

# $Id$
#
# Copyright (C) 2011-2012  Internet Systems Consortium ("ISC")
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
import subprocess
from distutils.core import setup, Extension, Command
from distutils.command.build_ext import build_ext as _build_ext

ac = None

class autoconf(Command):

  description = "run autoconf if hasn't been run already"

  user_options = []

  def initialize_options(self):
    pass

  def finalize_options(self):
    pass

  def run(self):
    try:
      import ac_rpki
    except ImportError:
      subprocess.check_call(("./configure",))
      import ac_rpki
    global ac
    ac = ac_rpki.ac

class build_openssl(Command):

  description = "build private OpenSSL libraries when needed by POW extension"

  user_options = []

  def initialize_options(self):
    pass

  def finalize_options(self):
    pass

  def run(self):
    self.run_command("autoconf")
    if ac.build_openssl:
      subprocess.check_call(("make",), cwd = "openssl")

class build_ext(_build_ext):
  def run(self):
    self.run_command("autoconf")
    self.run_command("build_openssl")

    # Non-standard extension build specification: we need to force
    # whatever build options our top-level ./configure selected, and we
    # have to specify our libraries as extra_link_args because they may be
    # complete pathnames to .a files elsewhere in the build tree.  Most of
    # this insanity is to kludge around pre-existing OpenSSL libraries
    # that would screw up our build without these gymnastics.

    # Not sure yet, but if we use autoconf to update or override
    # options to build_ext, we might need to reinitialize here,
    # something like:
    #
    #self = self.reinitialize_command(self)
    #self.ensure_finalized()

    # Might end up just whacking the one and only Extension object
    # queued up for this build_ext command.  Ugly, non-standard, but
    # simple.

    # For now just try whacking self.extensions and see what happens

    assert self.extensions and len(self.extensions) == 1
    ext = self.extensions[0]
    ext.extra_compile_args = ac.CFLAGS
    ext.extra_link_args    = ac.LDFLAGS + ac.LIBS

    return _build_ext.run(self)

# Be careful constructing data_files, empty file lists here appear to
# confuse setup into putting dangerous nonsense into the list of
# installed files.
#
# bdist_rpm seems to get confused by relative names for scripts, so we
# have to prefix source names here with the build directory name.

# Not sure why these are being treated as data files instead of
# scripts, probably historical based on our use of autoconf.  More
# distutils commands needed to customize scripts, probably

scripts      = ['rpki-sql-backup',
                'rpki-sql-setup',
                'rpki-start-servers',
                'irbe_cli',
                'irdbd',
                'pubd',
                'rootd',
                'rpkic',
                'rpkid',
                'portal-gui/scripts/rpkigui-rcynic',
                'portal-gui/scripts/rpkigui-import-routes',
                'portal-gui/scripts/rpkigui-check-expired',
                'portal-gui/scripts/rpki-manage']

aux_scripts  = []

data_files = []

# XXX disable all scripts for now until I get extension build working.

if False:

  if ac.sbindir and scripts:
    data_files.append((ac.sbindir,
                       ["%s/%s" % (ac.abs_builddir, f) for f in scripts]))
  if ac.libexecdir and aux_scripts:
    data_files.append((ac.libexecdir,
                       ["%s/%s" % (ac.abs_builddir, f) for f in aux_scripts]))
if not data_files:
  data_files = None

setup(name              = "rpkitoolkit",
      version           = "1.0",
      description       = "RPKI Toolkit",
      license           = "BSD",
      url               = "http://www.rpki.net/",
      cmdclass          = {"autoconf" : autoconf,
                           "build_ext"  : build_ext,
                           "build_openssl" : build_openssl},
      package_dir       = {"" : "rpkid"},
      packages          = ["rpki", "rpki.POW", "rpki.irdb",
                           "rpki.gui", "rpki.gui.app", "rpki.gui.cacheview",
                           "rpki.gui.api", "rpki.gui.routeview"],
      ext_modules       = [Extension("rpki.POW._POW", ["rpkid/ext/POW.c"])],
      package_data      = {
          'rpki.gui.app': ['migrations/*.py', 'static/*/*',
                           'templates/*.html', 'templates/*/*.html',
                           'templatetags/*.py'],
          'rpki.gui.cacheview': ['templates/*/*.html']
      },
      data_files	= data_files)
