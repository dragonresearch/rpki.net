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
from glob import glob
import setup_extensions

try:
  import setup_autoconf as autoconf

except ImportError:
  class autoconf:
    "Fake autoconf object to let --help work without autoconf."
    sbindir = libexecdir = datarootdir = sysconfdir = CFLAGS = LDFLAGS = LIBS = ""

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
                                     extra_compile_args =  autoconf.CFLAGS.split(),
                                     extra_link_args    = (autoconf.LDFLAGS + " " +
                                                           autoconf.LIBS).split())],
      package_data      = {"rpki.gui.app" :
                             ["migrations/*.py",
                              "static/*/*",
                              "templates/*.html",
                              "templates/*/*.html",
                              "templatetags/*.py"],
                           "rpki.gui.cacheview" :
                             ["templates/*/*.html"]},
      scripts           = [(autoconf.sbindir,
                            ["rpkic",
                             "rpki-confgen",
                             "rpki-start-servers",
                             "rpki-sql-backup",
                             "rpki-sql-setup",
                             "portal-gui/scripts/rpki-manage",
                             "portal-gui/scripts/rpkigui-query-routes",
                             "irbe_cli"]),
                           (autoconf.libexecdir,
                            ["irdbd",
                             "pubd",
                             "rootd",
                             "rpkid",
                             "portal-gui/scripts/rpkigui-import-routes",
                             "portal-gui/scripts/rpkigui-check-expired",
                             "portal-gui/scripts/rpkigui-rcynic",
                             "portal-gui/scripts/rpkigui-apache-conf-gen"])],
      data_files        = [(autoconf.sysconfdir  + "/rpki",
                            ["rpki-confgen.xml"]),
                           (autoconf.datarootdir + "/rpki/wsgi",
                            ["portal-gui/rpki.wsgi"]),
                           (autoconf.datarootdir + "/rpki/media/css",
                            glob("rpki/gui/app/static/css/*")),
                           (autoconf.datarootdir + "/rpki/media/js",
                            glob("rpki/gui/app/static/js/*")),
                           (autoconf.datarootdir + "/rpki/media/img",
                            glob("rpki/gui/app/static/img/*"))])
