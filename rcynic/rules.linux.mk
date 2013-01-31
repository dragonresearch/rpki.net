# $Id$

create-rcynic-user-and-group: .FORCE
	if ${AWK} -F: 'BEGIN {status = 1} $$1 == ${RCYNIC_GROUP} {status = 0} END {exit status}' /etc/group; \
	then \
	    echo "You already have a group \"${RCYNIC_GROUP}\", so I will use it."; \
	elif /usr/sbin/groupadd ${RCYNIC_GROUP}; \
	then \
	    echo "Added group \"${RCYNIC_GROUP}\"."; \
	else \
	    echo "Adding group \"${RCYNIC_GROUP}\" failed..."; \
	    echo "Please create it, then try again."; \
	    exit 1; \
	fi
	nogroup='-N'; \
	if test -f /etc/redhat-release; then; read vendor release version < /etc/redhat-release; if test $$vendor = CentOS; then; nogroup='-n'; fi; fi; \
	if ${AWK} -F: 'BEGIN {status = 1} $$1 == ${RCYNIC_USER} {status = 0} END {exit status}' /etc/passwd; \
	then \
	    echo "You already have a user \"${RCYNIC_USER}\", so I will use it." \
	elif /usr/sbin/useradd -g ${RCYNIC_GROUP} -M $$nogroup -d "${RCYNIC_DIR}" -s /sbin/nologin -c "${RCYNIC_GECOS}" ${RCYNIC_USER}; \
	then \
	    echo "Added user \"${RCYNIC_USER}\"."; \
	else \
	    echo "Adding user \"${RCYNIC_USER}\" failed..."; \
	    echo "Please create it, then try again."; \
	    exit 1; \
	fi
