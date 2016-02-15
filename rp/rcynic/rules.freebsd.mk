# $Id$

install-user-and-group: .FORCE
	@if /usr/sbin/pw groupshow "${RPKI_GROUP}" 2>/dev/null; \
	then \
	    echo "You already have a group \"${RPKI_GROUP}\", so I will use it."; \
	elif /usr/sbin/pw groupadd ${RPKI_GROUP}; \
	then \
	    echo "Added group \"${RPKI_GROUP}\"."; \
	else \
	    echo "Adding group \"${RPKI_GROUP}\" failed..."; \
	    echo "Please create it, then try again."; \
	    exit 1; \
	fi
	@if /usr/sbin/pw usershow "${RPKI_USER}" 2>/dev/null; \
	then \
	    echo "You already have a user \"${RPKI_USER}\", so I will use it."; \
	elif /usr/sbin/pw useradd ${RPKI_USER} -g ${RPKI_GROUP} -h - -d /nonexistant -s /usr/sbin/nologin -c "${RPKI_GECOS}"; \
	then \
	    echo "Added user \"${RPKI_USER}\"."; \
	else \
	    echo "Adding user \"${RPKI_USER}\" failed..."; \
	    echo "Please create it, then try again."; \
	    exit 1; \
	fi

# We use static compilation on FreeBSD, so no need for shared libraries

install-shared-libraries: 
	@true

install-rc-scripts:
	${INSTALL} -m 555 -o root -g wheel -p rc-scripts/freebsd/rc.d.rcynic ${DESTDIR}/usr/local/etc/rc.d/rcynic
