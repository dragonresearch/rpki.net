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

import os
import stat
import subprocess
from distutils.core import setup, Extension, Command
from distutils.command.build_ext import build_ext as _build_ext
from distutils.command.install_data import install_data as _install_data
from distutils.command.sdist import sdist as _sdist

try:
  from ac_rpki import ac
except ImportError:
  ac = None

class autoconf(Command):

  description = "run autoconf if hasn't been run already"

  user_options = []

  def initialize_options(self):
    pass

  def finalize_options(self):
    pass

  def run(self):
    global ac
    if ac is None:
      subprocess.check_call(("./configure",))
      import ac_rpki
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

# The following hack uses "svn ls -R" to generate the manifest.
# Haven't decided yet whether that's a good idea or not, commented out
# of cmdclass for now.

class sdist(_sdist):
  def add_defaults(self):
    try:
      self.filelist.extend(subprocess.check_output(("svn", "ls", "-R")).splitlines())
    except CalledProcessError:
      return _sdist.add_default(self)

# Be careful constructing data_files, empty file lists here appear to
# confuse setup into putting dangerous nonsense into the list of
# installed files.
#
# bdist_rpm seems to get confused by relative names for scripts, so we
# have to prefix source names here with the build directory name.

# We handle these as data files instead of scripts because
# install_scripts isn't clever enough to let us choose the
# installation directory.  We need to construct these files anyway, so
# that's not a big deal.
#
# At present we build these in rpkid/Makefile, but we need to change that
# to build these here in a new (not yet written) distutils command.

daemon_scripts = ["rpkid/rpki-sql-backup",
                  "rpkid/rpki-sql-setup",
                  "rpkid/rpki-start-servers",
                  "rpkid/irbe_cli",
                  "rpkid/irdbd",
                  "rpkid/pubd",
                  "rpkid/rootd",
                  "rpkid/rpkic",
                  "rpkid/rpkid"]

django_scripts = ["rpkid/portal-gui/scripts/rpkigui-rcynic",
                  "rpkid/portal-gui/scripts/rpkigui-import-routes",
                  "rpkid/portal-gui/scripts/rpkigui-check-expired",
                  #"rpkid/portal-gui/scripts/rpki-manage",
                  ]

# rpkid/Makefile.in stuff not handled yet:
#  portal-gui/settings.py
#  portal-gui/scripts/rpki-manage

# Not sure these really all should be in sbin, the Django stuff looks
# more libexec to me.  Preserve existing locations for now.

sbin_scripts = daemon_scripts + django_scripts

libexec_scripts  = []

daemon_script_template = '''\
#!%(ac_PYTHON)s
# Automatically constructed script header

# Set location of global rpki.conf file
if __name__ == "__main__":
  import rpki.config
  rpki.config.default_dirname = "%(ac_sysconfdir)s"

# Original script starts here

'''

django_script_template = '''\
#!%(ac_PYTHON)s
# Automatically constructed script header

import sys, os
# sys.path[0] is the cwd of the script being executed, so we add the
# path to the settings.py file after it
sys.path.insert(1, '%(ac_sysconfdir)s/rpki')
os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'

# Original script starts here

'''

class build_data(Command):

  description = 'build various constructed "data" files'

  # Most of these are really scripts, but install_scripts has no
  # provision for installing in different directories, and we do have
  # some real data files as well, so it's easiest just to handle all
  # of that here.

  user_options = []

  def initialize_options(self):
    pass

  def finalize_options(self):
    pass

  def run(self):
    self.run_command("autoconf")
    for fn in daemon_scripts:
      self.build_script(fn, daemon_script_template,
                        ac_PYTHON = ac.PYTHON,
                        ac_sysconfdir = ac.sysconfdir)
    for fn in django_scripts:
      self.build_script(fn, django_script_template,
                        ac_PYTHON = ac.PYTHON,
                        ac_sysconfdir = ac.sysconfdir)

  def build_script(self, fn, template, **kwargs):
    pyfn = fn + ".py"
    mode = stat.S_IMODE(os.stat(pyfn).st_mode) | 0555
    f = open(fn, "w")
    f.write(template % kwargs)
    f.write(open(pyfn, "r").read())
    f.close()
    os.chmod(fn, mode)

class install_data(_install_data):
  def run(self):
    self.run_command("build_data")
    return _install_data.run(self)

# Have to be careful with configuration that comes from autoconf.

data_files   = []

if ac is not None:

  if ac.sbindir and sbin_scripts:
    data_files.append((ac.sbindir,
                       ["%s/%s" % (ac.abs_builddir, f) for f in sbin_scripts]))
  if ac.libexecdir and libexec_scripts:
    data_files.append((ac.libexecdir,
                       ["%s/%s" % (ac.abs_builddir, f) for f in libexec_scripts]))

# Then there's all the stuff from rpkid/portal-gui/Makefile.in which
# also needs to go into data_files.

if not data_files:
  data_files = None

setup(name              = "rpkitoolkit",
      version           = "1.0",
      description       = "RPKI Toolkit",
      license           = "BSD",
      url               = "http://www.rpki.net/",
      cmdclass          = {"autoconf" : autoconf,
                           "build_ext"  : build_ext,
                           "build_data" : build_data,
                           "build_openssl" : build_openssl,
                           "install_data" : install_data,
                           # "sdist" : sdist,
                           },
      package_dir       = {"" : "rpkid"},
      packages          = ["rpki", "rpki.POW", "rpki.irdb",
                           "rpki.gui", "rpki.gui.app", "rpki.gui.cacheview",
                           "rpki.gui.api", "rpki.gui.routeview"],
      ext_modules       = [Extension("rpki.POW._POW", ["rpkid/ext/POW.c"])],
      package_data      = {"rpki.gui.app"       : ["migrations/*.py",
                                                   "static/*/*",
                                                   "templates/*.html",
                                                   "templates/*/*.html",
                                                   "templatetags/*.py"],
                           "rpki.gui.cacheview" : ["templates/*/*.html"] },
      data_files	= data_files)
