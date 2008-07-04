# $Id$

OPENSSL_DIR = ../../openssl/openssl

CFLAGS = -g -I${OPENSSL_DIR}/include -Wall

# -H -Wl,-t

NAME = find_roa

BIN = ${NAME}
OBJ = ${NAME}.o
LIB = ${OPENSSL_DIR}/libcrypto.a

all: ${BIN}

clean:
	rm -f ${BIN} ${OBJ}

${BIN}: ${OBJ} ${LIB} Makefile
	${CC} -g -o $@ ${OBJ} ${LIB}

test: ${BIN}
	./${BIN} 10.3.0.44 ../../rcynic/rcynic-data/authenticated
