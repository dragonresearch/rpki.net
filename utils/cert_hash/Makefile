# $Id$

OPENSSL_DIR = ../../openssl/openssl

CFLAGS = -g -I${OPENSSL_DIR}/include

# -H -Wl,-t

BIN = cert_hash
OBJ = cert_hash.o
LIB = ${OPENSSL_DIR}/libcrypto.a

all: ${BIN}

clean:
	rm -f ${BIN} ${OBJ}

${BIN}: ${OBJ} ${LIB} Makefile
	${CC} -g -o $@ ${OBJ} ${LIB}

TARGET = ../../rpkid/testbed.dir/publication/localhost:4400/testbed/WOMBAT.cer

test: all
	./${BIN} ${TARGET}
	openssl dgst -sha256 -c < ${TARGET}
