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

if branch not in ("trunk", "tk377") or not vers.isdigit():
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

# Just want relying party tools, and have to whack rcynic jail
# location to something acceptable to FreeBSD package system.

CONFIGURE_ARGS=  --disable-ca-tools --with-rcynic-jail=/usr/local/var/rcynic

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
bin/rtr-origin
bin/scan_roas
etc/rc.d/rcynic
var/rcynic/bin/rcynic
var/rcynic/bin/rcynic-html
var/rcynic/bin/rsync
@unexec if cmp -s %D/var/rcynic/etc/rcynic.conf.sample %D/var/rcynic/etc/rcynic.conf; then rm -f %D/var/rcynic/etc/rcynic.conf; fi
var/rcynic/etc/rcynic.conf.sample
@exec if [ ! -f  %D/var/rcynic/etc/rcynic.conf ] ; then cp -p %D/%F %D/var/rcynic/etc/rcynic.conf; fi
''')

  for trust_anchor in sorted(trust_anchors):
    f.write("var/rcynic/etc/trust-anchors/%s\n" % trust_anchor)

  f.write('''\
@exec mkdir -p %D/var/rcynic/var
@dirrm var/rcynic/var
@dirrm var/rcynic/etc/trust-anchors
@dirrm var/rcynic/etc
@exec mkdir -p %D/var/rcynic/dev
@dirrm var/rcynic/dev
@exec mkdir -p %D/var/rcynic/data
@dirrm var/rcynic/data
@dirrm var/rcynic/bin
@dirrm var/rcynic
''')

# 90% of this is $top/rcynic/installation-scripts/freebsd/install.sh.
# Somehow or another this duplication needs to go away, but priority
# for today is a working package.

with open(os.path.join(base, "pkg-install"), "w") as f:

  print "Writing", f.name

  f.write('''\
#!/bin/sh -

/bin/test "X$2" = 'XPRE-INSTALL' && exit 0

: ${jaildir="${DESTDIR}/usr/local/var/rcynic"}
: ${jailuser="rcynic"}
: ${jailgroup="rcynic"}
: ${setupcron="NO"}

echo "Setting up \"${jaildir}\" as a chroot jail for rcynic."

if /usr/sbin/pw groupshow "${jailgroup}" 2>/dev/null; then
    echo "You already have a group \"${jailgroup}\", so I will use it."
elif /usr/sbin/pw groupadd ${jailgroup}; then
    echo "Added group \"${jailgroup}\"."
else
    echo "Adding group \"${jailgroup}\" failed..."
    echo "Please create it, then try again."
    exit 1
fi

if /usr/sbin/pw usershow "${jailuser}" 2>/dev/null; then
    echo "You already have a user \"${jailuser}\", so I will use it."
elif /usr/sbin/pw useradd ${jailuser} -g ${jailgroup} -h - -d /nonexistant -s /usr/sbin/nologin -c "RPKI validation system"; then
    echo "Added user \"${jailuser}\"."
else
    echo "Adding user \"${jailuser}\" failed..."
    echo "Please create it, then try again."
    exit 1
fi

echo "Setting up jail directories"

/usr/sbin/mtree -deU -p "$jaildir" <<EOF

	/set type=dir uname=root gname=wheel mode=0555
	.
		bin
		..
		dev
		..
		etc
			trust-anchors
			..
		..
		var
			run
			..
		..
		data	uname=$jailuser gname=$jailgroup mode=0755
		..
	..
EOF

for i in /etc/localtime /etc/resolv.conf; do
        j="${jaildir}${i}"
        if /bin/test -r "$i" && ! /usr/bin/cmp -s "$i" "$j"; then
		/usr/bin/install -m 444 -o root -g wheel -p "$i" "$j"
	fi
done

case "$setupcron" in
YES|yes)
    # "'"
    echo "Setting up root's crontab to run jailed rcynic"
    /usr/bin/crontab -l -u root 2>/dev/null |
    /usr/bin/awk -v "jailuser=$jailuser" -v "jailgroup=$jailgroup" -v "jaildir=$jaildir" '
	BEGIN {
	    cmd = "exec /usr/sbin/chroot -u " jailuser " -g " jailgroup " " jaildir;
	    cmd = cmd " /bin/rcynic -c /etc/rcynic.conf";
	}
	$0 !~ cmd {
	    print;
	}
	END {
	    "/usr/bin/hexdump -n 2 -e \"\\\"%u\\\\\\n\\\"\" /dev/random" | getline;
	    printf "%u * * * *\t%s\n", $1 % 60, cmd;
	}' |
    /usr/bin/crontab -u root -
    /bin/cat <<EOF

	crontab is set up to run rcynic hourly, at a randomly selected
	minute (to spread load on the rsync servers).  Please do NOT
	adjust this to run on the hour.  In particular please do NOT
	adjust this to run at midnight UTC.
EOF
    ;;

*)
    /bin/cat <<EOF

	You'll need to add a crontab entry running the following command as root:

	    /usr/sbin/chroot -u $jailuser -g $jailgroup $jaildir /bin/rcynic -c /etc/rcynic.conf

	Please try to pick a random time for this, don't just run it on the hour,
	or at local midnight, or, worst of all, at midnight UTC.

EOF
    ;;

esac
''')

with open(os.path.join(base, "pkg-message"), "w") as f:

  print "Writing", f.name

  f.write('''\
You may need to customize /usr/local/var/rcynic/etc/rcynic.conf.
If you did not install your own trust anchors, a default set of SAMPLE
trust anchors may have been installed for you, but you, the relying
party, are the only one who can decide whether you trust those
anchors.  rcynic will not do anything useful without good trust
anchors.
''')
