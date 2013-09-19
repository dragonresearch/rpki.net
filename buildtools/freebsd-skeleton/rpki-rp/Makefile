PORTNAME=	rpki-rp
PORTVERSION=	0.%(SVNVERSION)s
CATEGORIES=	net
MASTER_SITES=	http://download.rpki.net/
DISTFILES=	rpki-%(SVNBRANCH)s-r%(SVNVERSION)s.tar.xz
WRKSRC=         ${WRKDIR}/rpki-%(SVNBRANCH)s-r%(SVNVERSION)s
MAINTAINER=	sra@hactrn.net
COMMENT=	rpki.net RPKI relying party tools
WWW=		http://rpki.net/

GNU_CONFIGURE=  yes
USE_PYTHON=	2.7+
USE_GNOME=      libxml2 libxslt
USE_APACHE_RUN= 22+

SUB_FILES=	pkg-install
SUB_LIST=	APACHE_VERSION=${APACHE_VERSION}
PLIST_SUB=	APACHE_VERSION=${APACHE_VERSION}

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

CONFIGURE_ARGS= --disable-ca-tools APACHE_VERSION=${APACHE_VERSION}
CONFIGURE_ENV=  CFLAGS="-I${LOCALBASE}/include" LDFLAGS="-L${LOCALBASE}/lib"

MAKE_JOBS_UNSAFE= yes

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
	@if test -f ${PREFIX}/etc/rcynic.conf; \
	 then \
	    ${MV} -f ${PREFIX}/etc/rcynic.conf ${PREFIX}/etc/rcynic.conf.real; \
	 fi

post-install:
	PKG_PREFIX=${PREFIX} ${SH} ${PKGINSTALL} ${PKGNAME} POST-INSTALL
	@if test -f ${PREFIX}/etc/rcynic.conf.real; \
	 then \
	    ${MV} -f ${PREFIX}/etc/rcynic.conf ${PREFIX}/etc/rcynic.conf.sample; \
	    ${MV} -f ${PREFIX}/etc/rcynic.conf.real ${PREFIX}/etc/rcynic.conf; \
	 else \
	    ${CP} -p ${PREFIX}/etc/rcynic.conf ${PREFIX}/etc/rcynic.conf.sample; \
	 fi

.include <bsd.port.mk>
