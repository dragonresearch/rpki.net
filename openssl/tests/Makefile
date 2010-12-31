# $Id$

OPENSSL_DIR = ../openssl

CFLAGS = -g -I${OPENSSL_DIR}/include

# -H -Wl,-t

BIN = resource-set-test
OBJ = resource-set-test.o
LIB = ${OPENSSL_DIR}/libcrypto.a

all: ${BIN}

clean:
	rm -f ${BIN} ${OBJ}

${BIN}: ${OBJ} ${LIB} Makefile
	${CC} -g -o $@ ${OBJ} ${LIB}

# This test needs more work

test: ${BIN} test.cer
	./${BIN} -v -a AS:17 -i IPv4:10.0.0.44 -d test.cer

test.cer: test.conf
	${OPENSSL_DIR}/apps/openssl req -new -x509 -config test.conf -keyout test.key -out test.cer -outform DER

distclean: clean
	rm -f test.key test.cer
