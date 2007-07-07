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

library_dirs = [ "../../openssl/openssl-0.9.8e" ]
include_dirs = [ library_dirs[0] + "include" ]
libraries    = [ "ssl", "crypto" ]
define_macros= [ ("NO_RC5_32_12_16", 1) ]

setup(name='POW',
      version='0.7',
      description='Python OpenSSL Wrappers',
      author='Peter Shannon',
      author_email='peter_shannon@yahoo.com',
      licence='BSD',
      url='http://www.sourceforge.net/projects/pow',
      packages=['POW'],
      package_dir={'POW':'lib'},
      ext_modules=[  
                     Extension('POW._POW', 
                        ['POW.c'], 
                        libraries=libraries,
                        library_dirs=library_dirs,
                        include_dirs=include_dirs,
                        define_macros=define_macros)
                  ])

os.remove('lib/_objects.py')
os.remove('lib/_oids.py')
