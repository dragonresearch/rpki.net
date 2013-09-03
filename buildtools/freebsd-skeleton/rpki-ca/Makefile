PORTNAME=	rpki-ca
PORTVERSION=	0.%(SVNVERSION)s
CATEGORIES=	net
MASTER_SITES=	http://download.rpki.net/
DISTFILES=	rpki-%(SVNBRANCH)s-r%(SVNVERSION)s.tar.xz
WRKSRC=         ${WRKDIR}/rpki-%(SVNBRANCH)s-r%(SVNVERSION)s
MAINTAINER=	sra@hactrn.net
COMMENT=	rpki.net RPKI CA tools
WWW=		http://rpki.net/

GNU_CONFIGURE=  yes
USE_PYTHON=	2.7+
USE_GNOME=      libxml2 libxslt
USE_MYSQL=      server
USE_APACHE_RUN= 22+

USE_RC_SUBR=	rpki-ca

MAKE_JOBS_UNSAFE= yes

# For OpenSSL, not needed otherwise
USE_PERL5_BUILD=yes

# For building OpenSSL, not needed otherwise
BUILD_DEPENDS+= makedepend>0:${PORTSDIR}/devel/makedepend

# Needed at build to keep ./configure from complaining.
BUILD_DEPENDS+= rsync>0:${PORTSDIR}/net/rsync

RPKID_DEPENDS=	${PYTHON_PKGNAMEPREFIX}lxml>0:${PORTSDIR}/devel/py-lxml                 \
                ${PYTHON_PKGNAMEPREFIX}MySQLdb>0:${PORTSDIR}/databases/py-MySQLdb       \
                ${PYTHON_PKGNAMEPREFIX}django>=1.3.7:${PORTSDIR}/www/py-django          \
                ${PYTHON_PKGNAMEPREFIX}vobject>0:${PORTSDIR}/deskutils/py-vobject       \
                ${PYTHON_PKGNAMEPREFIX}yaml>0:${PORTSDIR}/devel/py-yaml                 \
                ${PYTHON_PKGNAMEPREFIX}south>=0.7.6:${PORTSDIR}/databases/py-south

BUILD_DEPENDS+=	${RPKID_DEPENDS}
RUN_DEPENDS+=	${RPKID_DEPENDS}

RUN_DEPENDS+=	${APACHE_PKGNAMEPREFIX}mod_wsgi>3:${PORTSDIR}/www/mod_wsgi3

# Try to use system OpenSSL if we can.
CONFIGURE_ENV=  CFLAGS="-I${LOCALBASE}/include" LDFLAGS="-L${LOCALBASE}/lib"

CONFIGURE_ARGS= --disable-target-installation --disable-rp-tools

pre-install:
	PKG_PREFIX=${PREFIX} ${SH} ${PKGINSTALL} ${PKGNAME} PRE-INSTALL

post-install:
	PKG_PREFIX=${PREFIX} ${SH} ${PKGINSTALL} ${PKGNAME} POST-INSTALL

.include <bsd.port.mk>
