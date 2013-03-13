"""
Construct FreeBSD ports templates given the URL of a source tarball.

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

def mkdir_maybe(d):
  try:
    print "Creating", d
    os.makedirs(d)
  except OSError, e:
    if e.errno != errno.EEXIST:
      raise

name = os.path.basename(urlparse.urlparse(url).path)
name = stripext(name, ".gz", ".bz2", ".xz")
name = stripext(name, ".tar", ".tgz", ".tbz", ".txz")

try:
  base, branch, vers = name.split("-")
except:
  base, branch, vers = None

if base != "rpki":
  base = None

if branch != "trunk" and (branch[:2] != "tk" or not branch[2:].isdigit()):
  branch = None

if not vers.isdigit() and (base != "rpki" or vers[0] != "r" or not vers[1:].isdigit()):
  vers = None
else:
  vers = vers[1:]

if None in (base, branch, vers):
  sys.exit("Unexpected tarball URL name format")

base_rp = base + "-rp"
base_ca = base + "-ca"

mkdir_maybe(base_rp)
mkdir_maybe(base_ca)

with open(os.path.join(base_rp, "Makefile"), "w") as f:
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

# For building OpenSSL, not needed otherwise
BUILD_DEPENDS+= makedepend>0:${PORTSDIR}/devel/makedepend

# Needed at build to keep ./configure from complaining;
# needed at runtime for rcynic to do anything useful.
BUILD_DEPENDS+= rsync>0:${PORTSDIR}/net/rsync
RUN_DEPENDS+=   rsync>0:${PORTSDIR}/net/rsync

# For rcynic-html
RUN_DEPENDS+=   rrdtool>0:${PORTSDIR}/databases/rrdtool

# Just want relying party tools, try to use system OpenSSL if we can.

CONFIGURE_ARGS= --disable-ca-tools
CONFIGURE_ENV=  CFLAGS="-I${LOCALBASE}/include" LDFLAGS="-L${LOCALBASE}/lib"

# rcynic's Makefile constructs an rcynic.conf for us if it doesn't
# find one already installed.  This turns out to be exactly what
# FreeBSD's rules want us to install as rcynic.conf.sample, so we
# shuffle things around a bit just before and just after installation
# to make this all come out right.
# 
# If I ever teach rcynic to construct a .conf.sample file per the
# FreeBSD way of doing things, this will need to change to match.

pre-install:
	PKG_PREFIX=${PREFIX} ${SH} ${PKGINSTALL} ${PKGNAME} PRE-INSTALL
	@if [ -f ${PREFIX}/etc/rcynic.conf ]; then \
		${MV} -f ${PREFIX}/etc/rcynic.conf ${PREFIX}/etc/rcynic.conf.real ; \
	fi

post-install:
	PKG_PREFIX=${PREFIX} ${SH} ${PKGINSTALL} ${PKGNAME} POST-INSTALL
	@if [ -f ${PREFIX}/etc/rcynic.conf.real ]; then \
		${MV} -f ${PREFIX}/etc/rcynic.conf ${PREFIX}/etc/rcynic.conf.sample ; \
		${MV} -f ${PREFIX}/etc/rcynic.conf.real ${PREFIX}/etc/rcynic.conf ; \
	else \
		${CP} -p ${PREFIX}/etc/rcynic.conf ${PREFIX}/etc/rcynic.conf.sample ; \
	fi

.include <bsd.port.mk>
''' % { "portname"      : base_rp,
        "snapshot"      : vers,
        "tarname"       : name,
        "master_sites"  : os.path.dirname(url) + "/",
        "distfiles"     : os.path.basename(url) })

with open(os.path.join(base_rp, "pkg-descr"), "w") as f:
  print "Writing", f.name

  f.write('''\
This is a port of the rpki.net RPKI toolkit relying party tools.

WWW: http://rpki.net/
''')

with open(os.path.join(base_rp, "pkg-plist"), "w") as f:

  print "Writing empty", f.name

print "Generating checksum"

subprocess.check_call(("make", "makesum", "DISTDIR=" + os.getcwd()), cwd = base_rp)

print "Extracting list of trust anchors"

trust_anchors = [os.path.basename(fn)
                 for fn in subprocess.check_output(("tar", "tf", os.path.basename(url))).splitlines()
                 if "/rcynic/sample-trust-anchors/" in fn and fn.endswith(".tal")]

with open(os.path.join(base_rp, "pkg-plist"), "w") as f:

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
@dirrm etc/rpki/trust-anchors
@dirrmtry etc/rpki
@dirrm www/apache22/data/rcynic
@cwd /
@exec install -d -o root   -g wheel  %D/var/rcynic
@exec install -d -o rcynic -g rcynic %D/var/rcynic/data
@dirrm var/rcynic/data
@exec install -d -o rcynic -g rcynic %D/var/rcynic/rpki-rtr
@dirrm var/rcynic/rpki-rtr/sockets
@dirrm var/rcynic/rpki-rtr
@dirrm var/rcynic
''')

# 90% of this is $top/rcynic/installation-scripts/freebsd/install.sh.
# Somehow or another this duplication needs to go away, but priority
# for today is a working package.

with open(os.path.join(base_rp, "pkg-install"), "w") as f:

  print "Writing", f.name

  f.write('''\
#!/bin/sh -

case $2 in

PRE-INSTALL)
    if /usr/sbin/pw groupshow "rcynic" 2>/dev/null; then
        echo "You already have a group \\"rcynic\\", so I will use it."
    elif /usr/sbin/pw groupadd rcynic; then
        echo "Added group \\"rcynic\\"."
    else
        echo "Adding group \\"rcynic\\" failed..."
        echo "Please create it, then try again."
        exit 1
    fi
    if /usr/sbin/pw usershow "rcynic" 2>/dev/null; then
        echo "You already have a user \\"rcynic\\", so I will use it."
    elif /usr/sbin/pw useradd rcynic -g rcynic -h - -d /nonexistant -s /usr/sbin/nologin -c "RPKI validation system"; then
        echo "Added user \\"rcynic\\"."
    else
        echo "Adding user \\"rcynic\\" failed..."
        echo "Please create it, then try again."
        exit 1
    fi
    ;;

POST-INSTALL)
    htmldir=/usr/local/www/apache22/data/rcynic
    if ! test -d $htmldir ; then
        echo "Creating $htmldir"
        install -o rcynic -g rcynic -d $htmldir
    fi
    sockdir=/var/rcynic/rpki-rtr/sockets
    if ! test -d $sockdir ; then
        echo "Creating $sockdir"
        install -o nobody -g rcynic -d $sockdir
    fi
    echo "Setting up rcynic's crontab to run rcynic-cron script"
    /usr/bin/crontab -l -u rcynic 2>/dev/null |
    /usr/bin/awk -v t=`hexdump -n 2 -e '"%u\\n"' /dev/random` '
        BEGIN {
	    cmd = "exec /usr/local/bin/rcynic-cron";
	}
	$0 !~ cmd {
	    print;
	}
	END {
	    printf "%u * * * *\\t%s\\n", t % 60, cmd;
	}' |
    /usr/bin/crontab -u rcynic -
    echo "Setting up rpki-rtr listener under inetd"
    if /usr/bin/egrep -q '^rpki-rtr' /etc/services ; then
        echo "You already have a /etc/services entry for rpki-rtr, so I will use it."
    elif echo >>/etc/services "rpki-rtr	43779/tcp  #RFC 6810" ; then
        echo "Added rpki-rtr to /etc/services."
    else
        echo "Adding rpki-rtr to /etc/services failed, please fix this, then try again."
        exit 1
    fi
    if /usr/bin/egrep -q "rpki-rtr[ 	]+stream[ 	]+tcp[ 	]" /etc/inetd.conf; then
        echo "You already have an inetd.conf entry for rpki-rtr on TCPv4, so I will use it."
    elif echo >>/etc/inetd.conf "rpki-rtr	stream	tcp	nowait	nobody	/usr/local/bin/rtr-origin	rtr-origin --server /var/rcynic/rpki-rtr"; then
        echo "Added rpki-rtr for TCPv4 to /etc/inetd.conf."
    else
        echo "Adding rpki-rtr for TCPv4 to /etc/inetd.conf failed, please fix this, then try again."
        exit 1
    fi
    if /usr/bin/egrep -q "rpki-rtr[ 	]+stream[ 	]+tcp6[ 	]" /etc/inetd.conf; then
        echo "You already have an inetd.conf entry for rpki-rtr on TCPv6, so I will use it."
    elif echo >>/etc/inetd.conf "rpki-rtr	stream	tcp6	nowait	nobody	/usr/local/bin/rtr-origin	rtr-origin --server /var/rcynic/rpki-rtr"; then
        echo "Added rpki-rtr for TCPv6 to /etc/inetd.conf."
    else
        echo "Adding rpki-rtr for TCPv6 to /etc/inetd.conf failed, please fix this, then try again."
        exit 1
    fi
    ;;

*)
    echo "No clue what this script is meant to do when invoked with arguments \\"$*\\".  Punting."
    exit 1
    ;;

esac
''')

with open(os.path.join(base_rp, "pkg-deinstall"), "w") as f:

  print "Writing", f.name

  f.write('''\
#!/bin/sh -

case $2 in

DEINSTALL)
    echo "Whacking rcynic's crontab"
    /usr/bin/crontab -l -u rcynic 2>/dev/null |
    /usr/bin/awk '
	$0 !~ "exec /usr/local/bin/rcynic-cron" {
	    line[++n] = $0;
	}
	END {
	    if (n)
		for (i = 1; i <= n; i++)
		    print line[i] | "/usr/bin/crontab -u rcynic -";
	    else
		system("/usr/bin/crontab -u rcynic -r");
	}'
    ;;

POST-DEINSTALL)
    ;;

*)
    echo "No clue what this script is meant to do when invoked with arguments \\"$*\\".  Punting."
    exit 1
    ;;

esac
''')

with open(os.path.join(base_rp, "pkg-message"), "w") as f:

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

with open(os.path.join(base_ca, "Makefile"), "w") as f:
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

USE_RC_SUBR=	rpki-ca

# For OpenSSL, not needed otherwise
USE_PERL5_BUILD=yes

# For building OpenSSL, not needed otherwise
BUILD_DEPENDS+= makedepend>0:${PORTSDIR}/devel/makedepend

# Needed at build to keep ./configure from complaining.
BUILD_DEPENDS+= rsync>0:${PORTSDIR}/net/rsync

RPKID_DEPENDS=	${PYTHON_PKGNAMEPREFIX}lxml>0:${PORTSDIR}/devel/py-lxml                 \\
                ${PYTHON_PKGNAMEPREFIX}MySQLdb>0:${PORTSDIR}/databases/py-MySQLdb       \\
                ${PYTHON_PKGNAMEPREFIX}django>=1.3.7:${PORTSDIR}/www/py-django          \\
                ${PYTHON_PKGNAMEPREFIX}vobject>0:${PORTSDIR}/deskutils/py-vobject       \\
                ${PYTHON_PKGNAMEPREFIX}yaml>0:${PORTSDIR}/devel/py-yaml                 \\
                ${PYTHON_PKGNAMEPREFIX}south>=0.7.6:${PORTSDIR}/databases/py-south

BUILD_DEPENDS+=	${RPKID_DEPENDS}
RUN_DEPENDS+=	${RPKID_DEPENDS}

RUN_DEPENDS+=	${APACHE_PKGNAMEPREFIX}mod_wsgi>3:${PORTSDIR}/www/mod_wsgi3

# Try to use system OpenSSL if we can.
CONFIGURE_ENV=  CFLAGS="-I${LOCALBASE}/include" LDFLAGS="-L${LOCALBASE}/lib"

CONFIGURE_ARGS= --disable-target-installation --disable-rp-tools

.include <bsd.port.mk>
''' % { "portname"      : base_ca,
        "snapshot"      : vers,
        "tarname"       : name,
        "master_sites"  : os.path.dirname(url) + "/",
        "distfiles"     : os.path.basename(url) })

with open(os.path.join(base_ca, "pkg-descr"), "w") as f:
  print "Writing", f.name

  f.write('''\
This is a port of the rpki.net RPKI toolkit CA tools.

WWW: http://rpki.net/
''')

mkdir_maybe(os.path.join(base_ca, "files"))

with open(os.path.join(base_ca, "files", "rpki-ca.in"), "w") as f:
  print "Writing", f.name

  f.write('''\
#!/bin/sh

# PROVIDE: rpki-ca
# REQUIRE: LOGIN mysql
# KEYWORD: shutdown
#
# Add the following line to /etc/rc.conf[.local] to enable whatever
# RPKI CA services you have configured in rpki.conf
#
# rpkica_enable="YES"

. /etc/rc.subr

name="rpkica"
rcvar=rpkica_enable

required_files="/usr/local/etc/rpki.conf"

start_cmd="rpkica_start"
stop_cmd="rpkica_stop"

load_rc_config $name

: ${rpkica_enable="NO"}

: ${rpkica_pid_dir="/var/run/rpki"}

rpkica_start()
{
	/usr/bin/install -m 755 -d $rpkica_pid_dir
	/usr/local/sbin/rpki-start-servers
	return 0
}

rpkica_stop()
{
	for i in rpkid pubd irdbd rootd
	do
		if /bin/test -f $rpkica_pid_dir/$i.pid
		then
			/bin/kill `/bin/cat $rpkica_pid_dir/$i.pid`
		fi
	done
	return 0
}

run_rc_command "$1"
''')


#with open(os.path.join(base_ca, "pkg-plist"), "w") as f:
#  print "Writing empty", f.name

print "Generating checksum"

subprocess.check_call(("make", "makesum", "DISTDIR=" + os.getcwd()), cwd = base_ca)

# We will need a pkg-install and perhaps a pkg-deinstall, but I don't
# know what they look like (yet).

print "Building"

# "USE_GNOME=" gets rid of annoying whining due to empty or
# non-existent pkg-plist.  The (direct) Gnome dependency doesn't
# matter while constructing the port skeleton, so it's simplest just
# to disable it for this one command.

subprocess.check_call(("make", "DISTDIR=" + os.getcwd(), "USE_GNOME="), cwd = base_ca)

print "Installing to temporary tree"

tempdir = os.path.join(base_ca, "work", "temp-install", "")

subprocess.check_call(("make", "install", "DESTDIR=" + os.path.abspath(tempdir)),
                      cwd = os.path.join(base_ca, "work", name))

print "Generating pkg-plist"

with open(os.path.join(base_ca, "pkg-plist"), "w") as f:

  dont_remove = ("usr", "etc", "bin", "var", "lib", "sbin", "share", "lib/python2.7", "lib/python2.7/site-packages")

  usr_local = None

  for dirpath, dirnames, filenames in os.walk(tempdir, topdown = False):
    dn = dirpath[len(tempdir):]

    if dn.startswith("usr/local"):
      if not usr_local and usr_local is not None:
        f.write("@cwd\n")
      usr_local = True
      dn = dn[len("usr/local/"):]
    else:
      if usr_local:
        f.write("@cwd /\n")
      usr_local = False

    if not dirnames and not filenames:
      f.write("@exec mkdir -p %%D/%s\n" % dn)

    for fn in filenames:
      if fn == "rpki.conf.sample":
        f.write("@unexec if cmp -s %%D/%s/rpki.conf.sample %%D/%s/rpki.conf; then rm -f %%D/%s/rpki.conf; fi\n" % (dn, dn, dn))
      f.write(os.path.join(dn, fn) + "\n")
      if fn == "rpki.conf.sample":
        f.write("@exec if [ ! -f %%D/%s/rpki.conf ] ; then cp -p %%D/%s/rpki.conf.sample %%D/%s/rpki.conf; fi\n" % (dn, dn, dn))

    if dn and dn not in dont_remove:
      f.write("@dirrm %s\n" % dn)

print "Cleaning up"

subprocess.check_call(("make", "clean"), cwd = base_ca)
