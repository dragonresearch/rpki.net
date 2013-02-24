# $Id$

# Only need to make listener if not already present

install-listener: ${DESTDIR}/etc/xinetd.d/rpki-rtr

${DESTDIR}/etc/xinetd.d/rpki-rtr:
	@${AWK} 'BEGIN { \
	    print "service rpki-rtr"; \
	    print "{"; \
	    print "    socket_type    = stream"; \
	    print "    protocol       = tcp"; \
	    print "    port           = ${RPKI_RTR_PORT}"; \
	    print "    wait           = no"; \
	    print "    user           = nobody"; \
	    print "    server         = /usr/bin/rtr-origin"; \
	    print "    server_args    = --server /var/rpki-rtr"; \
	    print "}"; \
	}' >xinetd.rpki-rtr
	${INSTALL} -m 644 xinetd.rpki-rtr $@
	rm  xinetd.rpki-rtr
