# $Id$

OPENSSL_DIR = ../../openssl/openssl-0.9.8f

CFLAGS = -g -I${OPENSSL_DIR}/include

# -H -Wl,-t

BIN = uri
OBJ = uri.o
LIB = ${OPENSSL_DIR}/libcrypto.a

all: ${BIN}

clean:
	rm -f ${BIN} ${OBJ}

${BIN}: ${OBJ} ${LIB} Makefile
	${CC} -g -o $@ ${OBJ} ${LIB}
