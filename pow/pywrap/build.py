"""
Hack to build our Python wrapper.  Basic problem here is that we need
a bunch of arguments that were given to ./configure when Python itself
was built, and there appears to be no real consistancy about how
different unix-like distributions use the various parameters, so even
the standard python-config script is not smart enough to figure out
which arguments we need on every platform.  Feh.

This script is an attempt to pull the relevant information out of the
distutils.sysconfig module.  If I understood distutils better, I could
probably figure out some way to wrap this whole thing up nicely in the
distutils framework; if you understand how to do this, please do so
and send me the code.

As it is, this is a minimal hack to get the job done, and probably a
bit fragile.  Much of the code is taken from python-config.  If
there's any real documentation on how to do this sort of thing, I have
not found it yet.  YMMV.  Beware Of Dog.

$Id$
"""

import os, subprocess, sys

from distutils.sysconfig import (get_config_var as getvar,
                                 get_python_inc as getinc)

openssl_dir = os.path.realpath(os.path.join(os.getcwd(), "../../openssl/openssl"))

cmd = [getvar("CC"), "-o", "python", "python.c",
       "-Wl,-rpath,%s" % openssl_dir,
       "-L%s" % openssl_dir,
       "-lcrypto", "-lssl",
       "-I%s" % getinc(plat_specific = False),
       "-I%s" % getinc(plat_specific = True)]

if not getvar("Py_ENABLE_SHARED"):
  cmd.append("-L%s" % getvar("LIBPL"))

for var in ("CFLAGS", "LIBS", "SYSLIBS", "LDFLAGS"):
  cmd.extend(getvar(var).split())

cmd.append("-lpython%s" % getvar("VERSION"))

print " ".join(cmd)

sys.exit(subprocess.call(cmd))
