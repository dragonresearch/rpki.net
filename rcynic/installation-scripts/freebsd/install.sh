#!/bin/sh -
# $Id$
#
# Create a chroot jail for rcynic.
#
# This is approximately what a pkg-install script might do if this were
# a FreeBSD port.  Perhaps some day it will be.

: ${jaildir="${DESTDIR}/var/rcynic"}
: ${jailuser="rcynic"}
: ${jailgroup="rcynic"}
: ${setupcron="NO"}

echo "Setting up \"${jaildir}\" as a chroot jail for rcynic."

if /usr/sbin/pw groupshow "${jailgroup}" 2>/dev/null; then
    echo "You already have a group \"${jailgroup}\", so I will use it."
elif /usr/sbin/pw groupadd ${jailgroup}; then
    echo "Added group \"${jailgroup}\"."
else
    echo "Adding group \"${jailgroup}\" failed..."
    echo "Please create it, then try again."
    exit 1
fi

if /usr/sbin/pw usershow "${jailuser}" 2>/dev/null; then
    echo "You already have a user \"${jailuser}\", so I will use it."
elif /usr/sbin/pw useradd ${jailuser} -g ${jailgroup} -h - -d /nonexistant -s /usr/sbin/nologin -c "RPKI validation system"; then
    echo "Added user \"${jailuser}\"."
else
    echo "Adding user \"${jailuser}\" failed..."
    echo "Please create it, then try again."
    exit 1
fi

if ! /bin/test -d "${jaildir}"; then
    /bin/mkdir -p "${jaildir}"
fi

if /usr/bin/install -m 555 -o root -g wheel -p rc.d.rcynic ${DESTDIR}/usr/local/etc/rc.d/rcynic; then
    echo "Installed rc.d.rcynic as ${DESTDIR}/usr/local/etc/rc.d/rcynic"
else
    echo "Installing ${DESTDIR}/usr/local/etc/rc.d/rcynic failed"
    exit 1
fi

echo "Running /usr/local/etc/rc.d/rcynic to set up directories"

if ! rcynic_jaildir="$jaildir" rcynic_user="$jailuser" rcynic_group="$jailgroup" /bin/sh /usr/local/etc/rc.d/rcynic start; then
    echo "Directory setup failed"
    exit 1
fi

if /usr/bin/install -m 444 -o root -g wheel -p ../sample-rcynic.conf "${jaildir}/etc/rcynic.conf.sample"; then
    echo "Installed minimal ${jaildir}/etc/rcynic.conf.sample, adding SAMPLE trust anchors"
    for i in ../../sample-trust-anchors/*.tal; do
	j="$jaildir/etc/trust-anchors/${i##*/}"
	/bin/test -r "$i" || continue
	/bin/test -r "$j" && continue
	echo "Installing $i as $j"
	/usr/bin/install -m 444 -o root -g wheel -p "$i" "$j"
    done
    j=1
    for i in $jaildir/etc/trust-anchors/*.tal; do
	echo >>"${jaildir}/etc/rcynic.conf.sample" "trust-anchor-locator.$j	= /etc/trust-anchors/${i##*/}"
	j=$((j+1))
    done
else
    echo "Installing minimal ${jaildir}/etc/rcynic.conf.sample failed"
    exit 1
fi

if /bin/test -r "$jaildir/etc/rcynic.conf"; then
    echo "You already have config file \"${jaildir}/etc/rcynic.conf\", so I will use it."
elif /bin/cp -p "$jaildir/etc/rcynic.conf.sample" "$jaildir/etc/rcynic.conf"
    echo "Installed minimal ${jaildir}/etc/rcynic.conf"
else
    echo "Installing minimal ${jaildir}/etc/rcynic.conf failed"
    exit 1
fi

echo "Installing rcynic as ${jaildir}/bin/rcynic"

/usr/bin/install -m 555 -o root -g wheel -p ../../rcynic "${jaildir}/bin/rcynic"

if /bin/test ! -x "$jaildir/bin/rsync" -a ! -x ../../static-rsync/rsync; then
    echo "Building static rsync for jail, this may take a little while"
    (cd ../../static-rsync && exec make)
fi

if /bin/test -x "$jaildir/bin/rsync"; then
    echo "You already have an executable \"$jaildir/bin/rsync\", so I will use it"
elif /usr/bin/install -m 555 -o root -g wheel -p ../../static-rsync/rsync "${jaildir}/bin/rsync"; then
    echo "Installed static rsync as \"${jaildir}/bin/rsync\""
else
    echo "Installing static rsync failed"
    exit 1
fi

if /usr/bin/install -m 555 -o root -g wheel -p ../../rcynic-html "${jaildir}/bin/rcynic-html"; then
    echo "Installed rcynic.py as \"${jaildir}/bin/rcynic-html\""
else
    echo "Installing rcynic-html failed"
    exit 1
fi

echo "Setting up root's crontab to run jailed rcynic"

case "$setupcron" in
YES|yes)
    /usr/bin/crontab -l -u root 2>/dev/null |
    /usr/bin/awk -v "jailuser=$jailuser" -v "jailgroup=$jailgroup" -v "jaildir=$jaildir" '
	BEGIN {
	    cmd = "exec /usr/sbin/chroot -u " jailuser " -g " jailgroup " " jaildir;
	    cmd = cmd " /bin/rcynic -c /etc/rcynic.conf";
	}
	$0 !~ cmd {
	    print;
	}
	END {
	    "/usr/bin/hexdump -n 2 -e \"\\\"%u\\\\\\n\\\"\" /dev/random" | getline;
	    printf "%u * * * *\t%s\n", $1 % 60, cmd;
	}' |
    /usr/bin/crontab -u root -
    /bin/cat <<EOF

	crontab is set up to run rcynic hourly, at a randomly selected
	minute (to spread load on the rsync servers).  Please do NOT
	adjust this to run on the hour.  In particular please do NOT
	adjust this to run at midnight UTC.
EOF
    ;;

*)
    /bin/cat <<EOF

	You'll need to add a crontab entry running the following command as root:

	    /usr/sbin/chroot -u $jailuser -g $jailgroup $jaildir /bin/rcynic -c /etc/rcynic.conf

	Please try to pick a random time for this, don't just run it on the hour,
	or at local midnight, or, worst of all, at midnight UTC.

EOF
    ;;

esac

/bin/cat <<EOF

	Jail set up. You may need to customize $jaildir/etc/rcynic.conf.
	If you did not install your own trust anchors, a default set
	of SAMPLE trust anchors may have been installed for you, but
	you, the relying party, are the only one who can decide
	whether you trust those anchors.  rcynic will not do anything
	useful without good trust anchors.

EOF
