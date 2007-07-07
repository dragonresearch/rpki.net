from distutils.core import setup, Extension
import sys, os, cfgparse

print 'parsing configuration file'
oidinfo = cfgparse.Parser('dumpasn1.cfg')
print 'writing object module'
oidinfo.dumpobjs('lib/_objects.py')
print 'writing oid module'
oidinfo.dumpoids('lib/_oids.py')

if sys.platform == 'win32':
    library_dirs = [ os.path.join(sys.prefix, 'bin') ]
    libraries = [ 'ssleay32', 'libeay32' ]
else:
    library_dirs = [ os.path.join(sys.prefix, 'lib') ]
    libraries = [ 'ssl', 'crypto' ]

include_dirs = [os.path.join(sys.prefix, 'include')]

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
                        include_dirs=include_dirs )
                  ])

os.remove('lib/_objects.py')
os.remove('lib/_oids.py')
