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
  base, trunk, vers = name.split("-")
except:
  base, trunk, vers = None

if trunk != "trunk" or not vers.isdigit():
  sys.exit("Unexpected tarball URL name format")

mkdir_maybe(base)

# Just want relying party tools, and have to whack rcynic jail
# location to something acceptable to FreeBSD package system.

configure_args = "--disable-ca-tools --with-rcynic-jail=/usr/local/var/rcynic"

with open(os.path.join(base, "Makefile"), "w") as f:
  print "Writing", f.name

  f.write('''\
PORTNAME=	%(portname)s-rp
PORTVERSION=	0.%(snapshot)s
CATEGORIES=	net
MASTER_SITES=	%(master_sites)s
DISTFILES=	%(distfiles)s
WRKSRC=         ${WRKDIR}/%(tarname)s

MAINTAINER=	sra@hactrn.net
COMMENT=	rpki.net RPKI relying party tools

GNU_CONFIGURE=  yes
USE_PYTHON=	2.7+
USE_GNOME=      libxml2 libxslt

# For OpenSSL, not needed otherwise
USE_PERL5_BUILD=yes

# For OpenSSL, not needed otherwise
BUILD_DEPENDS+= makedepend>0:${PORTSDIR}/devel/makedepend

# For rcynic-html
RUN_DEPENDS+=   rrdtool>0:${PORTSDIR}/databases/rrdtool

CONIGURE_ARGS=  %(configure_args)s

.include <bsd.port.mk>
''' % { "portname"      : base,
        "snapshot"      : vers,
        "tarname"       : name,
        "master_sites"  : os.path.dirname(url) + "/",
        "distfiles"     : os.path.basename(url),
        "configure_args": configure_args })

with open(os.path.join(base, "pkg-descr"), "w") as f:
  print "Writing", f.name

  f.write('''\
This is a port of the rpki.net RPKI toolkit relying party tools.

WWW: http://rpki.net/
''')

with open(os.path.join(base, "pkg-plist"), "w") as f:

  print "Writing empty", f.name

print "Generating checksum"

subprocess.check_call(("make", "makesum", "DISTDIR=" + os.getcwd()), cwd = base)

print "Extracting list of trust anchors"

trust_anchors = ["var/rcynic/etc/trust-anchors/%s" % os.path.basename(fn)
                 for fn in subprocess.check_output(("tar", "tf", os.path.basename(url))).splitlines()
                 if "/rcynic/sample-trust-anchors/" in fn and fn.endswith(".tal")]

with open(os.path.join(base, "pkg-plist"), "w") as f:

  print "Writing", f.name

  f.write('''\
bin/find_roa
bin/hashdir
bin/print_roa
bin/print_rpki_manifest
bin/rtr-origin
bin/scan_roas
etc/rc.d/rcynic
var/rcynic/bin/rcynic
var/rcynic/bin/rcynic-html
var/rcynic/bin/rsync
''')

  for trust_anchor in trust_anchors:
    f.write("%s\n" % trust_anchor)

  f.write('''\
@dirrm var/rcynic/var
@dirrm var/rcynic/etc/trust-anchors
@dirrm var/rcynic/etc
@dirrm var/rcynic/dev
@dirrm var/rcynic/data
@dirrm var/rcynic/bin
@dirrm var/rcynic
''')
