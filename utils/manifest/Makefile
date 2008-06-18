# $Id$

OPENSSL_DIR = ../../openssl/openssl

CFLAGS = -g -I${OPENSSL_DIR}/include

# -H -Wl,-t

BIN = manifest
OBJ = manifest.o
LIB = ${OPENSSL_DIR}/libcrypto.a

all: ${BIN}

clean:
	rm -f ${BIN} ${OBJ}

${BIN}: ${OBJ} ${LIB} Makefile
	${CC} -g -o $@ ${OBJ} ${LIB}

MANIFEST_DIR = ../../rpkid/testbed.dir/publication

test: all
	-date -u +'now:            %Y%m%d%H%M%SZ'
	if test -d ${MANIFEST_DIR}; then find ${MANIFEST_DIR} -type f -name '*.mnf' -print -exec ./manifest {} \; ; else :; fi
