# $Id$

install-user-and-group: .FORCE
	@if getent group ${RCYNIC_GROUP} >/dev/null; \
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
	@nogroup='-N'; \
	if test -f /etc/redhat-release; then read vendor release version < /etc/redhat-release; if test $$vendor = CentOS; then nogroup='-n'; fi; fi; \
	if getent passwd ${RCYNIC_USER} >/dev/null; \
	then \
	    echo "You already have a user \"${RCYNIC_USER}\", so I will use it."; \
	elif /usr/sbin/useradd -g ${RCYNIC_GROUP} -M $$nogroup -d "${RCYNIC_DIR}" -s /sbin/nologin -c "${RCYNIC_GECOS}" ${RCYNIC_USER}; \
	then \
	    echo "Added user \"${RCYNIC_USER}\"."; \
	else \
	    echo "Adding user \"${RCYNIC_USER}\" failed..."; \
	    echo "Please create it, then try again."; \
	    exit 1; \
	fi
	@if getent group ${RPKIRTR_GROUP} >/dev/null; \
	then \
	    echo "You already have a group \"${RPKIRTR_GROUP}\", so I will use it."; \
	elif /usr/sbin/groupadd ${RPKIRTR_GROUP}; \
	then \
	    echo "Added group \"${RPKIRTR_GROUP}\"."; \
	else \
	    echo "Adding group \"${RPKIRTR_GROUP}\" failed..."; \
	    echo "Please create it, then try again."; \
	    exit 1; \
	fi
	@nogroup='-N'; \
	if test -f /etc/redhat-release; then read vendor release version < /etc/redhat-release; if test $$vendor = CentOS; then nogroup='-n'; fi; fi; \
	if getent passwd ${RPKIRTR_USER} >/dev/null; \
	then \
	    echo "You already have a user \"${RPKIRTR_USER}\", so I will use it."; \
	elif /usr/sbin/useradd -g ${RPKIRTR_GROUP} -M $$nogroup -d "${RPKIRTR_DIR}" -s /sbin/nologin -c "${RPKIRTR_GECOS}" ${RPKIRTR_USER}; \
	then \
	    echo "Added user \"${RPKIRTR_USER}\"."; \
	else \
	    echo "Adding user \"${RPKIRTR_USER}\" failed..."; \
	    echo "Please create it, then try again."; \
	    exit 1; \
	fi
	usermod -a -G ${RPKIRTR_GROUP} ${RCYNIC_USER}

install-shared-libraries: .FORCE
	@echo "Copying required shared libraries" 
	@if test -d /lib64; then libdir=/lib64; else libdir=/lib; fi; \
	shared_libraries="${RCYNIC_DIR}/bin/rcynic ${RCYNIC_DIR}/bin/rsync $$(/usr/bin/find $${libdir} -name 'libnss*.so*' -print)"; \
	while true; \
	do \
		closure="$$(/usr/bin/ldd $${shared_libraries} | \
			    ${AWK} ' \
				{ sub(/:$/, "") } \
				$$0 == "${RCYNIC_DIR}/bin/rcynic" { next } \
				$$0 == "${RCYNIC_DIR}/bin/rsync"  { next } \
				$$1 ~ /\/ld-linux\.so/		  { next } \
				{ for (i = 1; i <= NF; i++) if ($$i ~ /^\//) print $$i } \
			    ' | \
			    ${SORT} -u)"; \
		if test "X$$shared_libraries" = "X$$closure"; \
		then \
			break; \
		else \
			shared_libraries="$$closure"; \
		fi; \
	done; \
	if test -f $${libdir}/libresolv.so.2; \
	then \
		shared_libraries="$${shared_libraries} $${libdir}/libresolv.so.2";
	fi; \
	for shared in $${libdir}/*ld*.so* $$shared_libraries; \
	do \
		if test ! -r "${RCYNIC_DIR}/$${shared}"; \
		then \
			${INSTALL} -m 555 -d `dirname "${RCYNIC_DIR}$${shared}"` && \
			${INSTALL} -m 555 -p "$${shared}" "${RCYNIC_DIR}$${shared}"; \
		fi; \
	done

# No devfs, so no rc script

install-rc-scripts:
	@true
