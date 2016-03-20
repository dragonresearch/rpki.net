# $Id$

install-user-and-group: .FORCE
	@if getent group ${RPKI_GROUP} >/dev/null; \
	then \
	    echo "You already have a group \"${RPKI_GROUP}\", so I will use it."; \
	elif /usr/sbin/groupadd ${RPKI_GROUP}; \
	then \
	    echo "Added group \"${RPKI_GROUP}\"."; \
	else \
	    echo "Adding group \"${RPKI_GROUP}\" failed..."; \
	    echo "Please create it, then try again."; \
	    exit 1; \
	fi
	@nogroup='-N'; \
	if test -f /etc/redhat-release; then read vendor release version < /etc/redhat-release; if test $$vendor = CentOS; then nogroup='-n'; fi; fi; \
	if getent passwd ${RPKI_USER} >/dev/null; \
	then \
	    echo "You already have a user \"${RPKI_USER}\", so I will use it."; \
	elif /usr/sbin/useradd -g ${RPKI_GROUP} -M $$nogroup -d "${DESTDIR}${RCYNIC_DIR}" -s /sbin/nologin -c "${RPKI_GECOS}" ${RPKI_USER}; \
	then \
	    echo "Added user \"${RPKI_USER}\"."; \
	else \
	    echo "Adding user \"${RPKI_USER}\" failed..."; \
	    echo "Please create it, then try again."; \
	    exit 1; \
	fi
