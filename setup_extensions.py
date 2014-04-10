# $Id$
#
# This module extends the stock distutils install_setup code to
# support installation into multiple target directories, with
# semantics similar to what distutils already supports for
# script_files.  The bulk of this code is taken directly from the
# stock distutils package, with minor changes.  As such, I consider
# this to be a derivative work of the distutils package for copyright
# purposes.

from distutils.util import change_root, convert_path
from distutils.command.build_scripts   import build_scripts   as _build_scripts
from distutils.command.install_scripts import install_scripts as _install_scripts
from distutils import log
from stat import S_IMODE
import os

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
