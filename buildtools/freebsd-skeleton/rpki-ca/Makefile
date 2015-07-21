PORTNAME=	rpki-ca
PORTVERSION=	0.%(SVNVERSION)s
CATEGORIES=	net
MASTER_SITES=	http://download.rpki.net/
DISTFILES=	rpki-%(SVNBRANCH)s-r%(SVNVERSION)s.tar.xz
WRKSRC=         ${WRKDIR}/rpki-%(SVNBRANCH)s-r%(SVNVERSION)s
MAINTAINER=	sra@hactrn.net
COMMENT=	rpki.net RPKI CA tools
WWW=		http://rpki.net/

USES=		python:2.7+
GNU_CONFIGURE=  yes
NO_MTREE=	yes
USE_GNOME=      libxml2 libxslt
USE_MYSQL=      server
USE_APACHE_RUN= 22+

USE_RC_SUBR=	rpki-ca

# Disable parallel builds, they failed last time I tried and we don't really need them
MAKE_JOBS_UNSAFE= yes

# We depend on our own relying party code.  Perhaps this should require our own version number?
BUILD_DEPENDS+= rpki-rp>0:${PORTSDIR}/net/rpki-rp
RUN_DEPENDS+=   rpki-rp>0:${PORTSDIR}/net/rpki-rp

# For OpenSSL, not needed otherwise
USE_PERL5_BUILD=yes

# For building OpenSSL, not needed otherwise
BUILD_DEPENDS+= makedepend>0:${PORTSDIR}/devel/makedepend

RPKID_DEPENDS=	${PYTHON_PKGNAMEPREFIX}lxml>0:${PORTSDIR}/devel/py-lxml                 \
                ${PYTHON_PKGNAMEPREFIX}MySQLdb>0:${PORTSDIR}/databases/py-MySQLdb       \
                ${PYTHON_PKGNAMEPREFIX}django14>=1.4:${PORTSDIR}/www/py-django14          \
                ${PYTHON_PKGNAMEPREFIX}vobject>0:${PORTSDIR}/deskutils/py-vobject       \
                ${PYTHON_PKGNAMEPREFIX}yaml>0:${PORTSDIR}/devel/py-yaml                 \
                ${PYTHON_PKGNAMEPREFIX}netifaces>0:${PORTSDIR}/net/py-netifaces         \
                ${PYTHON_PKGNAMEPREFIX}south>=0.7.6:${PORTSDIR}/databases/py-south

BUILD_DEPENDS+=	${RPKID_DEPENDS}
RUN_DEPENDS+=	${RPKID_DEPENDS}

RUN_DEPENDS+=	${APACHE_PKGNAMEPREFIX}mod_wsgi4>0:${PORTSDIR}/www/mod_wsgi4

# Try to use system OpenSSL if we can.
CONFIGURE_ENV=  CFLAGS="-I${LOCALBASE}/include" LDFLAGS="-L${LOCALBASE}/lib"

CONFIGURE_ARGS= --disable-target-installation --disable-runtime-dependencies --disable-rp-tools APACHE_VERSION=${APACHE_VERSION}

pre-install:
	@test -d ${STAGEDIR}${PREFIX}/etc/rc.d || mkdir -p ${STAGEDIR}${PREFIX}/etc/rc.d

# Kludge to cope with setup.py insisting on including egg info every
# time it is called, which creates a problem for the way we use it.
#
# The real solution for this would be for the FreeBSD port system to
# grow up and let us build multiple binary packages from a single
# port, at which point this kludge will no longer be necessary (and
# this port will merge with rpki-rp).
#
# Until that glorious day, just whack the egg info, which should be a
# duplicate of the one that rpki-rp installs.

post-install:
	find ${STAGEDIR} -name '*.egg-info' -delete

.include <bsd.port.mk>
