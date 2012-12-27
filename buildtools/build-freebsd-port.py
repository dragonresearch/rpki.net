"""
Construct a FreeBSD port template given the URL of a source tarball.

$Id$

Copyright (C) 2012  Internet Systems Consortium ("ISC")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import sys
import os
import subprocess
import urlparse
import errno
import glob

try:
  url = sys.argv[1]
except IndexError:
  sys.exit("Usage: %s URL-of-source-tarball" % sys.argv[0])

def stripext(fn, *exts):
  fn1, fn2 = os.path.splitext(fn)
  return fn1 if fn2 in exts else fn

def mkdir_maybe(*args):
  try:
    print "Creating", args[0]
    os.makedirs(*args)
  except OSError, e:
    if e.errno != errno.EEXIST:
      raise

name = os.path.basename(urlparse.urlparse(url).path)
name = stripext(name, ".gz", ".bz2", ".xz")
name = stripext(name, ".tar", ".tgz", ".tbz", ".txz")

# Up until this point this is fairly generic, but we reach the point
# of diminishing returns when we have to parse the port name and
# version number out of the filename.  This will need to be changed
# when we start doing this with something other than snapshot
# tarballs.

try:
  base, trunk, vers = name.split("-")
except:
  base, trunk, vers = None

if trunk != "trunk" or not vers.isdigit():
  sys.exit("Unexpected tarball URL name format")

mkdir_maybe(base)

fn = os.path.join(base, "Makefile")

print "Writing", fn

with open(fn, "w") as f:
  f.write('''\
PORTNAME=	%(portname)s
PORTVERSION=	0.%(snapshot)s
CATEGORIES=	net
MASTER_SITES=	%(master_sites)s
DISTFILES=	%(distfiles)s
WRKSRC=         ${WRKDIR}/%(tarname)s

MAINTAINER=	sra@hactrn.net
COMMENT=	rpki.net RPKI tools package

GNU_CONFIGURE=  yes
USE_PYTHON=	2.7+
USE_MYSQL=      server
USE_APACHE_RUN= 22+
USE_GNOME=      libxml2 libxslt

# For OpenSSL, not needed otherwise
USE_PERL5_BUILD=yes

# Split between dependency targets is somewhat arbitrary here, much of what is
# listed as BUILD_DEPENDS might be better as RUN_DEPENDS.

BUILD_DEPENDS+= ${PYTHON_PKGNAMEPREFIX}lxml>0:${PORTSDIR}/devel/py-lxml                 \\
                ${PYTHON_PKGNAMEPREFIX}MySQLdb>0:${PORTSDIR}/databases/py-MySQLdb       \\
                ${PYTHON_PKGNAMEPREFIX}django>=1.3:${PORTSDIR}/www/py-django            \\
                ${PYTHON_PKGNAMEPREFIX}vobject>0:${PORTSDIR}/deskutils/py-vobject       \\
                ${PYTHON_PKGNAMEPREFIX}yaml>0:${PORTSDIR}/devel/py-yaml                 \\
                ${PYTHON_PKGNAMEPREFIX}south>=0.7.6:${PORTSDIR}/databases/py-south      \\
                makedepend>0:${PORTSDIR}/devel/makedepend

RUN_DEPENDS+=   rrdtool>0:${PORTSDIR}/databases/rrdtool                                 \\
                ${APACHE_PKGNAMEPREFIX}mod_wsgi>3:${PORTSDIR}/www/mod_wsgi3

.include <bsd.port.mk>
''' % { "portname"      : base,
        "snapshot"      : vers,
        "tarname"       : name,
        "master_sites"  : os.path.dirname(url) + "/",
        "distfiles"     : os.path.basename(url) })

fn = os.path.join(base, "pkg-descr")

print "Writing", fn

with open(fn, "w") as f:
  f.write('''\
This is a port of the rpki.net RPKI toolkit.

WWW: http://rpki.net/
''')

print "Generating checksum"

subprocess.check_call(("make", "makesum", "DISTDIR=" + os.getcwd()), cwd = base)

fn = os.path.join(base, "pkg-plist")
print "Creating empty", fn
open(fn, "w").close()

print "Running make configure"

# The "USE_GNOME=" setting is to silence a mess of grep errors we'd get otherwise.
# Not sure what this is about, seems to trigger on empty pkg-plist, so just disable
# this while generating pkg-plist so we can leave proper USE_GNOME setting in Makefile.

subprocess.check_call(("make", "configure", "DISTDIR=" + os.getcwd(),
                       "USE_GNOME=", "NO_DEPENDS=yes"),
                      cwd = base)

print "Running make installation-manifest"

subprocess.check_call(("make", "installation-manifest"),
                      cwd = os.path.join(base, "work", name))

files = []
dirs = []

dirmap = {
  "%%BINDIR%%"                  : "bin",
  "%%DATAROOTDIR%%"             : "share",
  "%%PYTHON_SITELIBDIR%%"       : "%%PYTHON_SITELIBDIR%%",
  "%%RCDIR%%"                   : "etc/rc.d",
  "%%RCYNICJAILDIR%%"           : "/var/rcynic",
  "%%SBINDIR%%"                 : "sbin",
  "%%SYSCONFDIR%%"              : "etc" }

fn = os.path.join(base, "work", name, "installation-manifest")

print "Parsing", fn

with open(fn, "r") as f:
  for line in f:
    kind, fn = line.rstrip("/").split()
    dir, sep, tail =  fn.partition("/")
    if dir in dirmap:
      fn = dirmap[dir] + sep + tail
    else:
      print "Warning: No mapping for %r in %r, blundering onwards" % (dir, fn)
    if kind == "F":
      files.append(fn)
    elif kind == "D":
      dirs.append(fn)
    else:
      sys.exit("Don't know what to do with %r" % line)

files.sort()
dirs.sort(reverse = True)

fn = os.path.join(base, "pkg-plist")
print "Writing", fn
with open(fn, "w") as f:
  for fn in files:
    f.write("%s\n" % fn)
  for fn in dirs:
    f.write("@dirrm %s\n" % fn)
