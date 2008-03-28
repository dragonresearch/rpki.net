# $Id$

OPENSSL_DIR = ../openssl/openssl

# Disable -Werror as long as we're using OpenSSL snapshots.

CFLAGS = -g -I${OPENSSL_DIR}/include -Wall -Wshadow -Wmissing-prototypes -Wmissing-declarations
LDFLAGS = -static

# -H -Wl,-t

BIN = rcynic
OBJ = rcynic.o
LIB = ${OPENSSL_DIR}/libcrypto.a

all: ${BIN}

clean:
	rm -f ${BIN} ${OBJ}

${BIN}: ${OBJ} ${LIB} Makefile
	${CC} -g -o $@ ${OBJ} ${LIB} ${LDFLAGS}

test: ${BIN}
	./${BIN} -j 0

install: ${BIN} scripts/install.sh
	cd scripts; . ./install.sh
