# [sra] Changes here are specific to the RPKI project, in order to get POW linked
#       against a copy of the OpenSSL libraries with the right options enabled.
#       Unlike the other changes to this package, I don't expect this one to be
#       useful to other POW users.

from distutils.core import setup, Extension
import sys, os, cfgparse

print 'parsing configuration file'
oidinfo = cfgparse.Parser('dumpasn1.cfg')
print 'writing object module'
oidinfo.dumpobjs('lib/_objects.py')
print 'writing oid module'
oidinfo.dumpoids('lib/_oids.py')

# Setting -rpath to point to the OpenSSL build directory is temporary.
# Once we figure out how and where to install this stuff, we'll need
# to adjust this to point to the installation location.  We wouldn't
# be using shared libraries at all except for a GNU linker bug.  Ick.

openssl_dir = os.path.realpath(os.path.join(os.getcwd(), "../../openssl/openssl"))

library_dirs    = [ openssl_dir ]
include_dirs    = [ openssl_dir + "/include" ]
libraries       = [ "ssl", "crypto" ]
extra_link_args = [ "-Wl,-rpath", openssl_dir ]

setup(name = 'POW',
      version = '0.7',
      description = 'Python OpenSSL Wrappers',
      author = 'Peter Shannon',
      author_email = 'peter_shannon@yahoo.com',
      license = 'BSD',
      url = 'http://www.sourceforge.net/projects/pow',
      packages = ['POW'],
      package_dir = {'POW':'lib'},
      ext_modules = [ Extension('POW._POW', 
                                ['POW.c'], 
                                libraries       = libraries,
#                                library_dirs    = library_dirs,
#                                include_dirs    = include_dirs,
#                                extra_link_args = extra_link_args,
                                extra_compile_args = list(os.environ["AC_CFLAGS"].split()),
                                extra_link_args = list(os.environ["AC_LDFLAGS"].split())
                                ) ])

os.remove('lib/_objects.py')
os.remove('lib/_oids.py')
