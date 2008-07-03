# $Id$

OPENSSL_DIR = ../../openssl/openssl

CFLAGS = -g -I${OPENSSL_DIR}/include

# -H -Wl,-t

NAME = print_roa

BIN = ${NAME}
OBJ = ${NAME}.o
LIB = ${OPENSSL_DIR}/libcrypto.a

all: ${BIN}

clean:
	rm -f ${BIN} ${OBJ}

${BIN}: ${OBJ} ${LIB} Makefile
	${CC} -g -o $@ ${OBJ} ${LIB}

ROA_DIR = ../../rpkid/testbed.dir/publication

test: all
	-date -u +'now:            %Y%m%d%H%M%SZ'
	if test -d ${ROA_DIR}; then find ${ROA_DIR} -type f -name '*.roa' -print -exec ./${BIN} {} \; ; else :; fi
