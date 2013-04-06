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
from distutils.util import change_root, convert_path
from distutils.command.build_scripts   import build_scripts   as _build_scripts
from distutils.command.install_scripts import install_scripts as _install_scripts
from distutils import log
from stat import S_IMODE
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

class build_scripts(_build_scripts):
  """
  Hacked version of distutils.build_scripts, designed to support
  multiple target installation directories like install_data does.

  [(target_directory, [list_of_source_scripts]), ...]

  Most of the real work is in the companion hacked install_scripts,
  but we need to tweak the list of source files that build_scripts
  pulls out of the Distribution object.
  """

  def finalize_options(self):
    _build_scripts.finalize_options(self)
    self.scripts = []
    for script in self.distribution.scripts:
      if isinstance(script, str):
        self.scripts.append(script)
      else:        
        self.scripts.extend(script[1])

class install_scripts(_install_scripts):
  """
  Hacked version of distutils.install_scripts, designed to support
  multiple target installation directories like install_data does.

  [(target_directory, [list_of_source_scripts]), ...]

  The code here is a tweaked combination of what the stock
  install_scripts and install_data classes do.
  """

  user_options = _install_scripts.user_options + [
    ("root=", None, "install everything relative to this alternate root directory")]

  def initialize_options(self):
    _install_scripts.initialize_options(self)
    self.outfiles = []
    self.root = None

  def finalize_options (self):
    self.set_undefined_options("build",
                               ("build_scripts", "build_dir"))
    self.set_undefined_options("install",
                               ("install_scripts", "install_dir"),
                               ("root", "root"),
                               ("force", "force"),
                               ("skip_build", "skip_build"))

  def run(self):
    if not self.skip_build:
      self.run_command("build_scripts")
    for script in self.distribution.scripts:
      if isinstance(script, str):
        fn = os.path.join(self.build_dir, os.path.basename(convert_path(script)))
        out, _ = self.copy_file(fn, self.install_dir)
        self.outfiles.append(out)
      else:
        dn = convert_path(script[0])
        if not os.path.isabs(dn):
          dn = os.path.join(self.install_dir, dn)
        elif self.root:
          dn = change_root(self.root, dn)
        self.mkpath(dn)
        if not script[1]:
          self.outfiles.append(dn)
        else:
          for s in script[1]:
            fn = os.path.join(self.build_dir, os.path.basename(convert_path(s)))
            out, _ = self.copy_file(fn, dn)
            self.outfiles.append(out)
    if os.name == "posix":
      for fn in self.get_outputs():
        mode = S_IMODE(os.stat(fn).st_mode) | 0555
        log.info("changing mode of %s to %o", fn, mode)
        if not self.dry_run:
          os.chmod(fn, mode)

# pylint: disable=W0622

setup(name              = "rpkitoolkit",
      version           = "1.0",
      description       = "RPKI Toolkit",
      license           = "BSD",
      url               = "http://rpki.net/",
      cmdclass          = {"build_scripts"   : build_scripts,
                           "install_scripts" : install_scripts},
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
