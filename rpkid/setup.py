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
import setup_extensions
import os

try:
  # Import settings derived from autoconf tests and configuration.
  #
  import setup_autoconf as autoconf
  ac_cflags      = autoconf.CFLAGS.split()
  ac_ldflags     = autoconf.LDFLAGS.split()
  ac_libs        = autoconf.LIBS.split()
  ac_sbindir     = autoconf.sbindir
  ac_libexecdir  = autoconf.libexecdir
  ac_datarootdir = os.path.join(autoconf.datarootdir, "rpki")
  ac_sysconfdir  = os.path.join(autoconf.sysconfdir, "rpki")

except ImportError:
  # We can't build POW without the autoconf settings, but we allow them
  # to be absent when running things like "python setup.py --help".
  #
  ac_cflags      = ()
  ac_ldflags     = ()
  ac_libs        = ()
  ac_sbindir     = None
  ac_libexecdir  = None
  ac_datarootdir = None
  ac_sysconfdir  = None

# pylint: disable=W0622

setup(name              = "rpkitoolkit",
      version           = "1.0",
      description       = "RPKI Toolkit",
      license           = "BSD",
      url               = "http://rpki.net/",
      cmdclass          = {"build_scripts"   : setup_extensions.build_scripts,
                           "install_scripts" : setup_extensions.install_scripts},
      packages          = ["rpki",
                           "rpki.POW",
                           "rpki.irdb",
                           "rpki.gui",
                           "rpki.gui.app",
                           "rpki.gui.cacheview",
                           "rpki.gui.api",
                           "rpki.gui.routeview"],
      ext_modules       = [Extension("rpki.POW._POW", ["ext/POW.c"], 
                                     extra_compile_args = ac_cflags,
                                     extra_link_args    = ac_ldflags + ac_libs)],
      package_data      = {"rpki.gui.app"       : ["migrations/*.py",
                                                   "static/*/*",
                                                   "templates/*.html",
                                                   "templates/*/*.html",
                                                   "templatetags/*.py"],
                           "rpki.gui.cacheview" : ["templates/*/*.html"]},
      scripts           = [(ac_sbindir,
                            ["rpkic",
                             "rpki-confgen",
                             "rpki-start-servers",
                             "rpki-sql-backup",
                             "rpki-sql-setup",
                             "portal-gui/scripts/rpki-manage",
                             "irbe_cli"]),
                           (ac_libexecdir,
                            ["irdbd",
                             "pubd",
                             "rootd",
                             "rpkid",
                             "portal-gui/scripts/rpkigui-import-routes",
                             "portal-gui/scripts/rpkigui-check-expired",
                             "portal-gui/scripts/rpkigui-rcynic"])],
      data_files        = [(ac_sysconfdir,
                            ["portal-gui/apache.conf",
                             "rpki-confgen.xml"])])
