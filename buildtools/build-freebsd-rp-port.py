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

base += "-rp"

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

# Just want relying party tools, try to use system OpenSSL if we can.

CONFIGURE_ARGS=  --disable-ca-tools
CONFIGURE_ENV=  CFLAGS="-I${LOCALBASE}/include" LDFLAGS="-L${LOCALBASE}/lib"

# This is not necessary at the moment because "make install" does
# all the same things.  This is here as a reminder in case that changes.
#
#post-install:; PKG_PREFIX=${PREFIX} ${SH} ${PKGINSTALL} ${PKGNAME} POST-INSTALL.

.include <bsd.port.mk>
''' % { "portname"      : base,
        "snapshot"      : vers,
        "tarname"       : name,
        "master_sites"  : os.path.dirname(url) + "/",
        "distfiles"     : os.path.basename(url) })

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

trust_anchors = [os.path.basename(fn)
                 for fn in subprocess.check_output(("tar", "tf", os.path.basename(url))).splitlines()
                 if "/rcynic/sample-trust-anchors/" in fn and fn.endswith(".tal")]

with open(os.path.join(base, "pkg-plist"), "w") as f:

  print "Writing", f.name

  f.write('''\
bin/find_roa
bin/hashdir
bin/print_roa
bin/print_rpki_manifest
bin/rcynic
bin/rcynic-cron
bin/rcynic-html
bin/rcynic-svn
bin/rcynic-text
bin/rtr-origin
bin/scan_roas
bin/validation_status
@unexec if cmp -s %D/etc/rcynic.conf.sample %D/etc/rcynic.conf; then rm -f %D/etc/rcynic.conf; fi
etc/rcynic.conf.sample
@exec if [ ! -f  %D/etc/rcynic.conf ] ; then cp -p %D/%F %D/etc/rcynic.conf; fi
''')

  for trust_anchor in sorted(trust_anchors):
    f.write("etc/rpki/trust-anchors/%s\n" % trust_anchor)

  f.write('''\
@cwd /
@exec install -d -o root   -g wheel  %D/var/rcynic
@exec install -d -o rcynic -g rcynic %D/var/rcynic/data
@dirrm var/rcynic/data
@exec install -d -o rcynic -g rcynic %D/var/rcynic/rpki-rtr
@dirrm var/rcynic/rpki-rtr
@dirrm var/rcynic
''')

# 90% of this is $top/rcynic/installation-scripts/freebsd/install.sh.
# Somehow or another this duplication needs to go away, but priority
# for today is a working package.

with open(os.path.join(base, "pkg-install"), "w") as f:

  print "Writing", f.name

  f.write('''\
#!/bin/sh -

case $2 in

PRE-INSTALL)
    if /usr/sbin/pw groupshow "rcynic" 2>/dev/null; then
        echo "You already have a group \"rcynic\", so I will use it."
    elif /usr/sbin/pw groupadd rcynic; then
        echo "Added group \"rcynic\"."
    else
        echo "Adding group \"rcynic\" failed..."
        echo "Please create it, then try again."
        exit 1
    fi
    if /usr/sbin/pw usershow "rcynic" 2>/dev/null; then
        echo "You already have a user \"rcynic\", so I will use it."
    elif /usr/sbin/pw useradd rcynic -g rcynic -h - -d /nonexistant -s /usr/sbin/nologin -c "RPKI validation system"; then
        echo "Added user \"rcynic\"."
    else
        echo "Adding user \"rcynic\" failed..."
        echo "Please create it, then try again."
        exit 1
    fi
    ;;

POST-INSTALL)
    echo "Setting up rcynic's crontab to run rcynic-cron script"
    /usr/bin/crontab -l -u rcynic 2>/dev/null |
    /usr/bin/awk -v t=`hexdump -n 2 -e '"%u\n"' /dev/random '
        BEGIN {
	    cmd = "exec /usr/local/bin/rcynic-cron";
	}
	$0 !~ cmd {
	    print;
	}
	END {
	    printf "%u * * * *\t%s\n", t % 60, cmd;
	}' |
    /usr/bin/crontab -u root -
    ;;

*)
    echo "No clue what this script is meant to do when invoked with arguments \"$*\".  Punting."
    exit 1
    ;;

esac
''')

with open(os.path.join(base, "pkg-message"), "w") as f:

  print "Writing", f.name

  f.write('''\
You may want to customize /usr/local/etc/rcynic.conf.  If you did not
install your own trust anchors, a default set of SAMPLE trust anchors
may have been installed for you, but you, the relying party, are the
only one who can decide whether you trust those anchors.  rcynic will
not do anything useful without good trust anchors.

rcynic-cron has been configured to run hourly, at a randomly selected
minute, to spread load on the global RPKI repository servers.  Please
do NOT adjust this to run on the hour.  In particular please do NOT
adjust this to run at midnight UTC.
''')
