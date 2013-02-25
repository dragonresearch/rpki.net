# $Id$

install-always: install-binary

install-postconf: install-listener

install-listener: .FORCE
	@if /usr/bin/egrep -q '^rpki-rtr' /etc/services ; \
	then \
	    echo "You already have a /etc/services entry for rpki-rtr, so I will use it."; \
	elif echo >>/etc/services "rpki-rtr	${RPKI_RTR_PORT}/tcp  #RFC 6810" ; \
	then \
	    echo "Added rpki-rtr to /etc/services."; \
	else \
	    echo "Adding rpki-rtr to /etc/services failed, please fix this, then try again."; \
	    exit 1; \
	fi
	@if /usr/bin/egrep -q "rpki-rtr[ 	]+stream[ 	]+tcp[ 	]" /etc/inetd.conf; \
	then \
	    echo "You already have an inetd.conf entry for rpki-rtr on TCPv4, so I will use it."; \
	elif echo >>/etc/inetd.conf "rpki-rtr	stream	tcp	nowait	nobody	/usr/local/bin/rtr-origin	rtr-origin --server /var/rcynic/rpki-rtr"; \
	then \
	    echo "Added rpki-rtr for TCPv4 to /etc/inetd.conf."; \
	else \
	    echo "Adding rpki-rtr for TCPv4 to /etc/inetd.conf failed, please fix this, then try again."; \
	    exit 1; \
	fi
	@if /usr/bin/egrep -q "rpki-rtr[ 	]+stream[ 	]+tcp6[ 	]" /etc/inetd.conf; \
	then \
	    echo "You already have an inetd.conf entry for rpki-rtr on TCPv6, so I will use it."; \
	elif echo >>/etc/inetd.conf "rpki-rtr	stream	tcp6	nowait	nobody	/usr/local/bin/rtr-origin	rtr-origin --server /var/rcynic/rpki-rtr"; \
	then \
	    echo "Added rpki-rtr for TCPv6 to /etc/inetd.conf."; \
	else \
	    echo "Adding rpki-rtr for TCPv6 to /etc/inetd.conf failed, please fix this, then try again."; \
	    exit 1; \
	fi
