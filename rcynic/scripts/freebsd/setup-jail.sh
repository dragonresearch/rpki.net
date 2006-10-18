#!/bin/sh -
# $Id$
#
# Create a chroot jail for rcynic.  You need to build staticly linked
# rcynic and rsync binaries and install them in the jail yourself, and
# you need to configure trust anchors.
#
# This is approximately what a pkg-install script would do if this were
# a FreeBSD port.  Perhaps some day it will be.

: ${jaildir="/var/rcynic"}
: ${jailuser="rcynic"}
: ${jailgroup="rcynic"}

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

# Should we install default trust anchors?   Probably.
#
#for i in trust-anchors/*.cer; do
#    j="$jaildir/etc/trust-anchors/${i##*/}"
#    /bin/test -r "$i" || continue
#    /bin/test -r "$j" && continue
#    echo "Installing $i as $j"
#    /usr/bin/install -m 444 -o root -g wheel -p "$i" "$j"
#done

if /bin/test -r "$jaildir/etc/rcynic.conf"; then
    echo "You already have config file \"${jaildir}/etc/rcynic.conf\", so I will use it."
elif /usr/bin/install -m 444 -o root -g wheel -p rcynic.conf "${jaildir}/etc/rcynic.conf"; then
    echo "Installed minimal ${jaildir}/etc/rcynic.conf"
    j=1
    for i in $jaildir/etc/trust-anchors/*.cer; do
	echo >>"${jaildir}/etc/rcynic.conf" "trust-anchor.$j		= /etc/trust-anchors/${i##*/}"
	j=$((j+1))
    done
else
    echo "Installing minimal ${jaildir}/etc/rcynic.conf failed"
    exit 1
fi

echo "Setting up root's crontab to run jailed rcynic"

/usr/bin/crontab -l -u root |
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

	Jail is set up.  Crontab should be set up to run rcynic hourly, at a
	randomly selected minute (to spread load on the rsync servers).  Please
	do NOT adjust this to run on the hour, in particular please do NOT
	adjust this to run at midnight UTC.

	You still need to build staticly-linked copies of rcynic and rsync
	(see the rcynic README) and install them in $jaildir/bin.

	You may also need to customize $jaildir/etc/rcynic.conf, particularly
	if you have not already specified trust anchors for rcynic to use
	(rcynic will not do anything useful without trust anchors).

EOF
