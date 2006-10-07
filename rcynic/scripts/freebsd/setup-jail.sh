#!/bin/sh -
# $Id$
#
# Create a chroot jail for rcynic.  You need to build staticly linked
# rcynic and rsync binaries and install them in the jail yourself.
#
# Cobbled together from bits and pieces of existing system scripts,
# mostly /usr/ports/mail/postfix/pkg-install and /etc/rc.d/named.

jaildir="/var/rcynic"
jailuser="rcynic"
jailgroup="rcynic"

if /usr/sbin/pw groupshow "${jailgroup}" 2>/dev/null; then
    echo "You already have a group \"${jailgroup}\", so I will use it."
elif /usr/sbin/pw groupadd ${jailgroup}; then
    echo "Added group \"${jailgroup}\"."
else
    echo "Adding group \"${jailgroup}\" failed..."
    echo "Please create it, and try again."
    exit 1
fi

if /usr/sbin/pw usershow "${jailuser}" 2>/dev/null; then
    echo "You already have a user \"${jailuser}\", so I will use it."
elif /usr/sbin/pw useradd ${jailuser} -g ${jailgroup} -h - -d /nonexistant -s /usr/sbin/nologin -c "RPKI validation system"; then
    echo "Added user \"${jailuser}\"."
else
    echo "Adding user \"${jailuser}\" failed..."
    echo "Please create it, and try again."
    exit 1
fi

if ! /bin/test -d "${jaildir}"; then
    /bin/mkdir "${jaildir}"
fi

/usr/sbin/mtree -deU -p "${jaildir}" <<EOF

    /set type=dir uname=root gname=wheel mode=0555
    .
	bin
	..
	dev
	..
	etc
	    trust-anchors
	    ..
	..
	var
	    run
	    ..
	..
	data	uname=$jailuser gname=$jailgroup mode=0755
	..
    ..

EOF

/sbin/umount "${jaildir}/dev" 2>/dev/null
if ! /sbin/mount -t devfs dev "${jaildir}/dev"; then
    echo "Mounting devfs on ${jaildir}/dev failed..."
    exit 1
fi
/sbin/devfs -m "${jaildir}/dev" rule apply hide
/sbin/devfs -m "${jaildir}/dev" rule apply path null unhide
/sbin/devfs -m "${jaildir}/dev" rule apply path random unhide

for i in /etc/localtime /etc/resolv.conf; do
    j="${jaildir}${i}"
    if /bin/test -r "$i" && ! /usr/bin/cmp -s "$i" "$j"; then
	/bin/cp -p "$i" "$j"
	/usr/sbin/chown root:wheel "$j"
	/bin/chmod 444 "$j"
    fi
done

if /bin/test -d trust-anchors; then
    for i in trust-anchors/*.cer; do
	j="$jaildir/etc/trust-anchors/${i##*/}"
	/bin/test -r "$j" && continue
	echo "Copying $i to $j"
	/bin/cp -p "$i" "$j"
	/usr/sbin/chown root:wheel "$j"
	/bin/chmod 444 "$j"
    done
fi

if /bin/test -r "$jaildir/etc/rcynic.conf"; then
    echo "You already have config file \"${jaildir}/etc/rcynic.conf\", so I will use it."
else
    echo "Creating minmal ${jaildir}/etc/rcynic.conf"
    /bin/cat >"${jaildir}/etc/rcynic.conf" <<-EOF
	[rcynic]
	rsync-program		= /bin/rsync
	authenticated		= /data/authenticated
	old-authenticated	= /data/authenticated.old
	unauthenticated		= /data/unauthenticated
	lockfile		= /data/lock
	EOF
    j=1
    for i in $jaildir/etc/trust-anchors/*.cer; do
	echo >>"${jaildir}/etc/rcynic.conf" "trust-anchor.$j		= /etc/trust-anchors/${i##*/}"
	j=$((j+1))
    done
fi

/usr/sbin/chown root:wheel "${jaildir}/etc/rcynic.conf"
/bin/chmod 444 "${jaildir}/etc/rcynic.conf"

