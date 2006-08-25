# $Id$

OPENSSL_DIR = ../../openssl/trunk

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

test:
	@echo This test needs more work
	@echo ''
	${OPENSSL_DIR}/apps/openssl req -new -x509 -config rfc3779-test.conf -key rfc3779-test.key -out rfc3779-test.cert
	@echo ''
	./resource-set-test  -v -a AS:17 -i IPv4:10.0.0.44 -p rfc3779-test.cert
