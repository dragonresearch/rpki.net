#!/bin/sh -
# $Id$
#
# Create a chroot jail for rcynic.
#
# This is approximately what a pkg-install script might do if this were
# a FreeBSD port.  Perhaps some day it will be.

: ${jaildir="/var/rcynic"}
: ${jailuser="rcynic"}
: ${jailgroup="rcynic"}

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
    /bin/mkdir "${jaildir}"
fi

if /usr/bin/install -m 555 -o root -g wheel -p rc.d.rcynic /usr/local/etc/rc.d/rcynic; then
    echo "Installed rc.d.rcynic as /usr/local/etc/rc.d/rcynic"
else
    echo "Installing /usr/local/etc/rc.d/rcynic failed"
    exit 1
fi

echo "Running /usr/local/etc/rc.d/rcynic to set up directories"

if ! rcynic_jaildir="$jaildir" rcynic_user="$jailuser" rcynic_group="$jailgroup" /bin/sh /usr/local/etc/rc.d/rcynic start; then
    echo "Directory setup failed"
    exit 1
fi

if /bin/test -r "$jaildir/etc/rcynic.conf"; then
    echo "You already have config file \"${jaildir}/etc/rcynic.conf\", so I will use it."
elif /usr/bin/install -m 444 -o root -g wheel -p rcynic.conf "${jaildir}/etc/rcynic.conf"; then
    echo "Installed minimal ${jaildir}/etc/rcynic.conf, adding SAMPLE trust anchors"
    for i in ../../sample-trust-anchors/*.cer; do
	j="$jaildir/etc/trust-anchors/${i##*/}"
	/bin/test -r "$i" || continue
	/bin/test -r "$j" && continue
	echo "Installing $i as $j"
	/usr/bin/install -m 444 -o root -g wheel -p "$i" "$j"
    done
    j=1
    for i in $jaildir/etc/trust-anchors/*.cer; do
	echo >>"${jaildir}/etc/rcynic.conf" "trust-anchor.$j		= /etc/trust-anchors/${i##*/}"
	j=$((j+1))
    done
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

echo "Setting up root's crontab to run jailed rcynic"

/usr/bin/crontab -l -u root 2>/dev/null |
/usr/bin/awk '
    BEGIN {
	cmd = "exec /usr/sbin/chroot -u rcynic -g rcynic /var/rcynic";
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

	Jail is set up, and crontab is set up to run rcynic hourly, at
	a randomly selected minute (to spread load on the rsync
	servers).  Please do NOT adjust this to run on the hour.  In
	particular please do NOT adjust this to run at midnight UTC.

	You may need to customize $jaildir/etc/rcynic.conf.  If you
	did not install your own trust anchors, a default set of
	SAMPLE trust anchors may have been installed for you, but you,
	the relying party, are the only one who can decide whether you
	trust those anchors.  rcynic will not do anything useful
	without good trust anchors.

EOF
