# $Id$

install-user-and-group: .FORCE
	@if /usr/bin/dscl . -read "/Groups/${RPKI_GROUP}" >/dev/null 2>&1; \
	then \
	    echo "You already have a group \"${RPKI_GROUP}\", so I will use it."; \
	elif gid="$$(/usr/bin/dscl . -list /Groups PrimaryGroupID | /usr/bin/awk 'BEGIN {gid = 501} $$2 >= gid {gid = 1 + $$2} END {print gid}')" && \
	    /usr/bin/dscl . -create "/Groups/${RPKI_GROUP}" && \
	    /usr/bin/dscl . -create "/Groups/${RPKI_GROUP}" RealName "${RPKI_GECOS}" && \
	    /usr/bin/dscl . -create "/Groups/${RPKI_GROUP}" PrimaryGroupID "$$gid" && \
	    /usr/bin/dscl . -create "/Groups/${RPKI_GROUP}" GeneratedUID "$$(/usr/bin/uuidgen)" && \
	    /usr/bin/dscl . -create "/Groups/${RPKI_GROUP}" Password "*"; \
	then \
	    echo "Added group \"${RPKI_GROUP}\"."; \
	else \
	    echo "Adding group \"${RPKI_GROUP}\" failed..."; \
	    echo "Please create it, then try again."; \
	    exit 1; \
	fi; \
	if /usr/bin/dscl . -read "/Users/${RPKI_USER}" >/dev/null 2>&1; \
	then \
	    echo "You already have a user \"${RPKI_USER}\", so I will use it."; \
	elif uid="$$(/usr/bin/dscl . -list /Users UniqueID | /usr/bin/awk 'BEGIN {uid = 501} $$2 >= uid {uid = 1 + $$2} END {print uid}')" && \
	    /usr/bin/dscl . -create "/Users/${RPKI_USER}" && \
	    /usr/bin/dscl . -create "/Users/${RPKI_USER}" UserShell "/usr/bin/false" && \
	    /usr/bin/dscl . -create "/Users/${RPKI_USER}" RealName "${RPKI_GECOS}" && \
	    /usr/bin/dscl . -create "/Users/${RPKI_USER}" UniqueID "$$uid" && \
	    /usr/bin/dscl . -create "/Users/${RPKI_USER}" PrimaryGroupID "$$gid" && \
	    /usr/bin/dscl . -create "/Users/${RPKI_USER}" NFSHomeDirectory "/var/empty" && \
	    /usr/bin/dscl . -create "/Users/${RPKI_USER}" GeneratedUID "$$(/usr/bin/uuidgen)" && \
	    /usr/bin/dscl . -create "/Users/${RPKI_USER}" Password "*"; \
	then \
	    echo "Added user \"${RPKI_USER}\"."; \
	else \
	    echo "Adding user \"${RPKI_USER}\" failed..."; \
	    echo "Please create it, then try again."; \
	    exit 1; \
	fi
