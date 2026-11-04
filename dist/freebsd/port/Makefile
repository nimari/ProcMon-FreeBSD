PORTNAME=	procmon-freebsd
DISTVERSION=	2.2.2.1
CATEGORIES=	sysutils
# Unpublished local distfile. Set an immutable public release URL before submission.
MASTER_SITES=

MAINTAINER=	ports@FreeBSD.org
COMMENT=	Community native FreeBSD syscall monitor
WWW=	https://github.com/microsoft/ProcMon-Linux

LICENSE=	MIT PD
LICENSE_COMB=	multi
LICENSE_FILE_MIT=	${WRKSRC}/LICENSE
LICENSE_FILE_PD=	${WRKSRC}/dist/freebsd/SQLITE-NOTICE

ONLY_FOR_ARCHS=	amd64
ONLY_FOR_ARCHS_REASON=	native syscall/CTF contract validated on FreeBSD 15.1 amd64

USES=	cmake compiler:c++17-lang
CMAKE_OFF=	BUILD_TESTING

.include <bsd.port.mk>
