"""
Construct a FreeBSD port template given the URL of a source tarball.

$Id$

Copyright (C) 2012-2013  Internet Systems Consortium ("ISC")

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
  base, branch, vers = name.split("-")
except:
  base, branch, vers = None

if base not in ("rpkitools", "rpki"):
  base = None

if branch != "trunk" and (branch[:2] != "tk" or not branch[2:].isdigit()):
  branch = None

if not vers.isdigit() and (base != "rpki" or vers[0] != "r" or not vers[1:].isdigit()):
  vers = None

if None in (base, branch, vers):
  sys.exit("Unexpected tarball URL name format")

base += "-ca"

mkdir_maybe(base)

with open(os.path.join(base, "Makefile"), "w") as f:
  print "Writing", f.name

  f.write('''\
PORTNAME=	%(portname)s
PORTVERSION=	0.%(snapshot)s
CATEGORIES=	net
MASTER_SITES=	%(master_sites)s
DISTFILES=	%(distfiles)s
WRKSRC=         ${WRKDIR}/%(tarname)s

MAINTAINER=	sra@hactrn.net
COMMENT=	rpki.net RPKI CA tools

GNU_CONFIGURE=  yes
USE_PYTHON=	2.7+
USE_GNOME=      libxml2 libxslt
USE_MYSQL=      server
USE_APACHE_RUN= 22+

# In theory, this invokes all the Python magic for us.  Whether that
# solves any of our problems remains to be seen.
USE_PYDISTUTILS=yes

# For OpenSSL, not needed otherwise
USE_PERL5_BUILD=yes

# For building OpenSSL, not needed otherwise
BUILD_DEPENDS+= makedepend>0:${PORTSDIR}/devel/makedepend

# Needed at build to keep ./configure from complaining.
BUILD_DEPENDS+= rsync>0:${PORTSDIR}/net/rsync

RPKID_DEPENDS=	${PYTHON_PKGNAMEPREFIX}lxml>0:${PORTSDIR}/devel/py-lxml                 \\
                ${PYTHON_PKGNAMEPREFIX}MySQLdb>0:${PORTSDIR}/databases/py-MySQLdb       \\
                ${PYTHON_PKGNAMEPREFIX}django>=1.3:${PORTSDIR}/www/py-django            \\
                ${PYTHON_PKGNAMEPREFIX}vobject>0:${PORTSDIR}/deskutils/py-vobject       \\
                ${PYTHON_PKGNAMEPREFIX}yaml>0:${PORTSDIR}/devel/py-yaml                 \\
                ${PYTHON_PKGNAMEPREFIX}south>=0.7.6:${PORTSDIR}/databases/py-south

BUILD_DEPENDS+=	${RPKID_DEPENDS}
RUN_DEPENDS+=	${RPKID_DEPENDS}

RUN_DEPENDS+=	${APACHE_PKGNAMEPREFIX}mod_wsgi>3:${PORTSDIR}/www/mod_wsgi3

# Try to use system OpenSSL if we can.
CONFIGURE_ENV=  CFLAGS="-I${LOCALBASE}/include" LDFLAGS="-L${LOCALBASE}/lib"

.include <bsd.port.mk>
''' % { "portname"      : base,
        "snapshot"      : vers,
        "tarname"       : name,
        "master_sites"  : os.path.dirname(url) + "/",
        "distfiles"     : os.path.basename(url) })

with open(os.path.join(base, "pkg-descr"), "w") as f:
  print "Writing", f.name

  f.write('''\
This is a port of the rpki.net RPKI toolkit CA tools.

WWW: http://rpki.net/
''')

#with open(os.path.join(base, "pkg-plist"), "w") as f:
#  print "Writing empty", f.name

print "Generating checksum"

subprocess.check_call(("make", "makesum", "DISTDIR=" + os.getcwd()), cwd = base)

# In theory, using the magic Python stuff means we don't have to write
# a pkg-plist.

# We will need a pkg-install and perhaps a pkg-deinstall, but I don't
# know what they look like (yet).
