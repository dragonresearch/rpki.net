# $Id$

create-rcynic-user-and-group: .FORCE
	@if /usr/bin/dscl . -read "/Groups/${RCYNIC_GROUP}" >/dev/null 2>&1; \
	then \
	    echo "You already have a group \"${RCYNIC_GROUP}\", so I will use it."; \
	elif gid="$$(/usr/bin/dscl . -list /Groups PrimaryGroupID | /usr/bin/awk 'BEGIN {gid = 501} $$2 >= gid {gid = 1 + $$2} END {print gid}')" && \
	    /usr/bin/dscl . -create "/Groups/${RCYNIC_GROUP}" && \
	    /usr/bin/dscl . -create "/Groups/${RCYNIC_GROUP}" RealName "${RCYNIC_GECOS}" && \
	    /usr/bin/dscl . -create "/Groups/${RCYNIC_GROUP}" PrimaryGroupID "$$gid" && \
	    /usr/bin/dscl . -create "/Groups/${RCYNIC_GROUP}" GeneratedUID "$$(/usr/bin/uuidgen)" && \
	    /usr/bin/dscl . -create "/Groups/${RCYNIC_GROUP}" Password "*"; \
	then \
	    echo "Added group \"${RCYNIC_GROUP}\"."; \
	else \
	    echo "Adding group \"${RCYNIC_GROUP}\" failed..."; \
	    echo "Please create it, then try again."; \
	    exit 1; \
	fi; \
	if /usr/bin/dscl . -read "/Users/${RCYNIC_USER}" >/dev/null 2>&1; \
	then \
	    echo "You already have a user \"${RCYNIC_USER}\", so I will use it."; \
	elif uid="$$(/usr/bin/dscl . -list /Users UniqueID | /usr/bin/awk 'BEGIN {uid = 501} $$2 >= uid {uid = 1 + $$2} END {print uid}')" && \
	    /usr/bin/dscl . -create "/Users/${RCYNIC_USER}" && \
	    /usr/bin/dscl . -create "/Users/${RCYNIC_USER}" UserShell "/usr/bin/false" && \
	    /usr/bin/dscl . -create "/Users/${RCYNIC_USER}" RealName "${RCYNIC_GECOS}" && \
	    /usr/bin/dscl . -create "/Users/${RCYNIC_USER}" UniqueID "$$uid" && \
	    /usr/bin/dscl . -create "/Users/${RCYNIC_USER}" PrimaryGroupID "$$gid" && \
	    /usr/bin/dscl . -create "/Users/${RCYNIC_USER}" NFSHomeDirectory "/var/empty" && \
	    /usr/bin/dscl . -create "/Users/${RCYNIC_USER}" GeneratedUID "$$(/usr/bin/uuidgen)" && \
	    /usr/bin/dscl . -create "/Users/${RCYNIC_USER}" Password "*"; \
	then \
	    echo "Added user \"${RCYNIC_USER}\"."; \
	else \
	    echo "Adding user \"${RCYNIC_USER}\" failed..."; \
	    echo "Please create it, then try again."; \
	    exit 1; \
	fi


install-shared-libraries: .FORCE
	@echo "Copying required shared libraries" 
	@shared_libraries="${RCYNIC_DIR}/bin/rcynic ${RCYNIC_DIR}/bin/rsync"; \
	while true; \
	do \
	    closure="$$(/usr/bin/otool -L $${shared_libraries} | /usr/bin/awk '/:$$/ {next} {print $$1}' | /usr/bin/sort -u)"; \
	    if test "x$$shared_libraries" = "x$$closure"; 
	    then \
		break; \
	    else \
		shared_libraries="$$closure"; \
	    fi; \
	done; \
	for shared in /usr/lib/dyld $$shared_libraries; \
	do \
	    if /bin/test -r "${RCYNIC_DIR}/$${shared}"; \
	    then \
		echo "You already have a \"${RCYNIC_DIR}/$${shared}\", so I will use it"; \
	    elif /usr/bin/install -m 555 -o root -g wheel -p "$${shared}" "${RCYNIC_DIR}/$${shared}"; \
	    then \
		echo "Copied $${shared} into ${RCYNIC_DIR}"; \
	    else \
		echo "Unable to copy $${shared} into ${RCYNIC_DIR}"; \
		exit 1; \
	    fi; \
	done

install-rc-scripts:
	${INSTALL} -o root -g wheel -d ${DESTDIR}/Library/StartupItems/RCynic
	${INSTALL} -o root -g wheel -m 555 \
		rc-scripts/darwin/RCynic \
		rc-scripts/darwin/StartupParameters.plist \
		${DESTDIR}/Library/Startup/RCynic
