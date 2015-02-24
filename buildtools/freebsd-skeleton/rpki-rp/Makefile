PORTNAME=	rpki-rp
PORTVERSION=	0.%(SVNVERSION)s
CATEGORIES=	net
MASTER_SITES=	http://download.rpki.net/
DISTFILES=	rpki-%(SVNBRANCH)s-r%(SVNVERSION)s.tar.xz
WRKSRC=         ${WRKDIR}/rpki-%(SVNBRANCH)s-r%(SVNVERSION)s
MAINTAINER=	sra@hactrn.net
COMMENT=	rpki.net RPKI relying party tools
WWW=		http://rpki.net/

USES=		python:2.7+
GNU_CONFIGURE=  yes
NO_MTREE=	yes
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

# Needed at build to keep ./configure from complaining;
# used at runtime by rcynic-html.
BUILD_DEPENDS+=	rrdtool>0:${PORTSDIR}/databases/rrdtool
RUN_DEPENDS+=   rrdtool>0:${PORTSDIR}/databases/rrdtool

# Just want relying party tools, try to use system OpenSSL if we can.

CONFIGURE_ARGS= --disable-target-installation --disable-runtime-dependencies --disable-ca-tools APACHE_VERSION=${APACHE_VERSION}
CONFIGURE_ENV=  CFLAGS="-I${LOCALBASE}/include" LDFLAGS="-L${LOCALBASE}/lib"

# Disable parallel builds, they failed the last time I tried and we don't really need them
MAKE_JOBS_UNSAFE= yes

# rcynic's Makefile constructs an rcynic.conf for us if it doesn't
# find one already installed.  This turns out to be exactly what
# FreeBSD's rules want us to install as rcynic.conf.sample, so we just
# rename it.

post-install:
	${MV} -vf ${STAGEDIR}${PREFIX}/etc/rcynic.conf ${STAGEDIR}${PREFIX}/etc/rcynic.conf.sample

.include <bsd.port.mk>
