# $Id$

OPENSSL_DIR = ../openssl/trunk

CFLAGS = -g -I${OPENSSL_DIR}/include -Wall -Werror -Wshadow -Wmissing-prototypes -Wmissing-declarations

# -H -Wl,-t

BIN = rcynic
OBJ = rcynic.o
LIB = ${OPENSSL_DIR}/libcrypto.a

all: ${BIN}

clean:
	rm -f ${BIN} ${OBJ}

${BIN}: ${OBJ} ${LIB} Makefile
	${CC} -g -o $@ ${OBJ} ${LIB}
