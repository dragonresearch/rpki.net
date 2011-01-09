"""
Hack to build our Python extension module.

In a sane world, we'd just use the excellent distutils package, which
would do all the work for us.  But we have this little problem of
sometimes needing to use a private copy of the OpenSSL libraries to
kludge around obsolete system libraries, and a further problem that
GNU ld has bizzare issues with linking static libraries into shared
objects on 64-bit platforms.

In the long term, this problem will go away, when everybody updates to
a reasonable version of OpenSSL with CMS and RFC 3779 support enabled.
When that happens, this whackiness should be replaced by a normal
setup.py using distutils.

In the meantime, we pull config information from distutils, but do the
build ourselves.

This is a minimal hack to get the job done, and probably a bit
fragile.  Much of the code is taken from python-config and the
distutils.sysconfig.customize_compiler.  If there's any real
documentation on how to do this sort of thing, I have not found it
yet.  YMMV.  Beware Of Dog.

$Id$
"""

import os, subprocess, sys

from distutils.sysconfig import (get_config_var as getvar,
                                 get_python_inc as getinc)

static_libraries = []
other_libraries = []
for lib in os.environ["AC_LIBS"].split():
  if lib.startswith("-"):
    other_libraries.append(lib)
  else:
    static_libraries.append(lib)

cmd = getvar("CC").split()
cmd.extend(("-c", "-o", "POW.o", "POW.c"))
cmd.extend(os.environ["AC_CFLAGS"].split())
cmd.append("-I%s" % getinc(plat_specific = False))
cmd.append("-I%s" % getinc(plat_specific = True))
cmd.extend(getvar("CFLAGS").split())
cmd.extend(getvar("CCSHARED").split())
print " ".join(cmd)
r = subprocess.call(cmd)
if r:
  sys.exit(r)

if static_libraries:
  cmd = ["ld", "-r", "-o", "_POW.o", "POW.o"] + static_libraries
  print " ".join(cmd)
  r = subprocess.call(cmd)
  if r:
    sys.exit(r)
else:
  os.link("POW.o", "_POW.o")

cmd = getvar("LDSHARED").split()
cmd.extend(("-o", "POW/_POW.so", "_POW.o"))
cmd.extend(os.environ["AC_LDFLAGS"].split())
cmd.extend(getvar("LDFLAGS").split())
cmd.extend(other_libraries)
print " ".join(cmd)
r = subprocess.call(cmd)
if r:
  sys.exit(r)

objcopy = os.getenv("AC_OBJCOPY")
if objcopy:
  cmd = [objcopy, "-G", "init_POW", "-x", "POW/_POW.so"]
  print " ".join(cmd)
  r = subprocess.call(cmd)
  if r:
    sys.exit(r)
