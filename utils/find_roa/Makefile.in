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
	rm -rf ${BIN} ${OBJ} hashed-pem-dir

${BIN}: ${OBJ} ${LIB} Makefile
	${CC} -g -o $@ ${OBJ} ${LIB}

TEST_ARGS = ../../rcynic/rcynic-data/authenticated 10.3.0.44 10.2.0.6 10.0.0.0/24

test: ${BIN}
#	./${BIN} ${TEST_ARGS}
	sh ./test_roa.sh ${TEST_ARGS}
