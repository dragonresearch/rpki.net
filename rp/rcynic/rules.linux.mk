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
	elif /usr/sbin/useradd -g ${RPKI_GROUP} -M $$nogroup -d "${RCYNIC_DIR}" -s /sbin/nologin -c "${RPKI_GECOS}" ${RPKI_USER}; \
	then \
	    echo "Added user \"${RPKI_USER}\"."; \
	else \
	    echo "Adding user \"${RPKI_USER}\" failed..."; \
	    echo "Please create it, then try again."; \
	    exit 1; \
	fi

# This all looks like a relic of the days when we still tried to support rcynic running in a chroot jail, which
# never really worked properly except on FreeBSD, and has since been overtaken by many other events.  Do we
# still need this, even assuming anybody uses this installation instead of Debian packaging?
#
# Cleanup left for another day, but this looks pretty iffy.

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
