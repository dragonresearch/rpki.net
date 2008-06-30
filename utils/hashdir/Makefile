# $Id$

OPENSSL_DIR = ../../openssl/openssl

CFLAGS = -g -I${OPENSSL_DIR}/include

# -H -Wl,-t

BIN = hashdir
OBJ = hashdir.o
LIB = ${OPENSSL_DIR}/libcrypto.a

all: ${BIN}

clean::
	rm -f ${BIN} ${OBJ}

${BIN}: ${OBJ} ${LIB} Makefile
	${CC} -g -o $@ ${OBJ} ${LIB}

INPUT  = ../../rcynic/rcynic-data/authenticated
OUTPUT = test.out

test: ${BIN}
	if test -d ${INPUT}; then rm -rf ${OUTPUT} && mkdir ${OUTPUT} && ./hashdir ${INPUT} ${OUTPUT}; else :; fi

clean::
	rm -rf ${OUTPUT}
