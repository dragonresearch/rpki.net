# $Id$
#
# Copyright (C) 2011-2013  Internet Systems Consortium ("ISC")
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

from distutils.core import setup, Extension
import os

# We can't build POW without these settings, but allow them to be null
# so that things like "python setup.py --help" will work.

try:
  import setup_autoconf
  ac_cflags      = setup_autoconf.CFLAGS.split()
  ac_ldflags     = setup_autoconf.LDFLAGS.split()
  ac_libs        = setup_autoconf.LIBS.split()
  ac_sbindir     = setup_autoconf.sbindir
  ac_libexecdir  = setup_autoconf.libexecdir
  ac_datarootdir = os.path.join(setup_autoconf.datarootdir, "rpki")
  ac_sysconfdir  = os.path.join(setup_autoconf.sysconfdir, "rpki")

except ImportError:
  ac_cflags      = ()
  ac_ldflags     = ()
  ac_libs        = ()
  ac_sbindir     = None
  ac_libexecdir  = None
  ac_datarootdir = None
  ac_sysconfdir  = None

# Scripts and data files, moved here from Makefile.in.

ac_scripts = [
  "rpki-sql-backup",
  "rpki-sql-setup",
  "rpki-start-servers",
  "irbe_cli",
  "irdbd",
  "pubd",
  "rootd",
  "rpkic",
  "rpkid",
  "rpki-confgen",
  "portal-gui/scripts/rpkigui-import-routes",
  "portal-gui/scripts/rpkigui-check-expired",
  "portal-gui/scripts/rpkigui-rcynic",
  "portal-gui/scripts/rpki-manage" ]

ac_aux_scripts = []

ac_data_files = []

ac_conf_files = [
  "portal-gui/apache.conf",
  "rpki-confgen.xml" ]

# Non-standard extension build specification: we need to force
# whatever build options our top-level ./configure selected, and we
# have to specify our libraries as extra_link_args because they may be
# complete pathnames to .a files elsewhere in the build tree.  Most of
# this insanity is to kludge around pre-existing OpenSSL libraries
# that would screw up our build without these gymnastics.

# pylint: disable=W0622

pow = Extension("rpki.POW._POW", ["ext/POW.c"], 
                extra_compile_args = ac_cflags,
                extra_link_args    = ac_ldflags + ac_libs)

# Be careful constructing data_files, empty file lists here appear to
# confuse setup into putting dangerous nonsense into the list of
# installed files.
#
# bdist_rpm seems to get confused by relative names for scripts, so we
# have to prefix source names here with the build directory name.  Well,
# if we care about bdist_rpm, which it now looks like we don't, but
# leave it alone for the moment.

data_files = []
if ac_sbindir and ac_scripts:
  data_files.append((ac_sbindir,     [os.path.abspath(f) for f in ac_scripts]))
if ac_libexecdir and ac_aux_scripts:
  data_files.append((ac_libexecdir,  [os.path.abspath(f) for f in ac_aux_scripts]))
if ac_datarootdir and ac_data_files:
  data_files.append((ac_datarootdir, [os.path.abspath(f) for f in ac_data_files]))
if ac_sysconfdir and ac_conf_files:
  data_files.append((ac_sysconfdir,  [os.path.abspath(f) for f in ac_conf_files]))
if not data_files:
  data_files = None

setup(name              = "rpkitoolkit",
      version           = "1.0",
      description       = "RPKI Toolkit",
      license           = "BSD",
      url               = "http://www.rpki.net/",
      packages          = ["rpki", "rpki.POW", "rpki.irdb",
                           "rpki.gui", "rpki.gui.app", "rpki.gui.cacheview",
                           "rpki.gui.api", "rpki.gui.routeview" ],
      ext_modules       = [pow],
      package_data      = {
          'rpki.gui.app': ['migrations/*.py', 'static/*/*',
                           'templates/*.html', 'templates/*/*.html',
                           'templatetags/*.py'],
          'rpki.gui.cacheview': ['templates/*/*.html']
      },
      data_files        = data_files)
