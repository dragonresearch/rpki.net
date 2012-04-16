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
: ${jailname="RPKI Validation System"}
: ${setupcron="NO"}

echo "Setting up \"${jaildir}\" as a chroot jail for rcynic."

if /usr/bin/dscl . -read "/Groups/${jailgroup}" >/dev/null 2>&1
then
    echo "You already have a group \"${jailgroup}\", so I will use it."
elif gid="$(/usr/bin/dscl . -list /Groups PrimaryGroupID | /usr/bin/awk 'BEGIN {gid = 501} $2 >= gid {gid = 1 + $2} END {print gid}')" &&
    /usr/bin/dscl . -create "/Groups/${jailgroup}" &&
    /usr/bin/dscl . -create "/Groups/${jailgroup}" RealName "${jailname}" &&
    /usr/bin/dscl . -create "/Groups/${jailgroup}" PrimaryGroupID "$gid" &&
    /usr/bin/dscl . -create "/Groups/${jailgroup}" GeneratedUID "$(/usr/bin/uuidgen)" &&
    /usr/bin/dscl . -create "/Groups/${jailgroup}" Password "*"
then
    echo "Added group \"${jailgroup}\"."
else
    echo "Adding group \"${jailgroup}\" failed..."
    echo "Please create it, then try again."
    exit 1
fi

if /usr/bin/dscl . -read "/Users/${jailuser}" >/dev/null 2>&1
then
    echo "You already have a user \"${jailuser}\", so I will use it."
elif uid="$(/usr/bin/dscl . -list /Users UniqueID | /usr/bin/awk 'BEGIN {uid = 501} $2 >= uid {uid = 1 + $2} END {print uid}')" &&
    /usr/bin/dscl . -create "/Users/${jailuser}" &&
    /usr/bin/dscl . -create "/Users/${jailuser}" UserShell "/usr/bin/false" &&
    /usr/bin/dscl . -create "/Users/${jailuser}" RealName "${jailname}" &&
    /usr/bin/dscl . -create "/Users/${jailuser}" UniqueID "$uid" &&
    /usr/bin/dscl . -create "/Users/${jailuser}" PrimaryGroupID "$gid" &&
    /usr/bin/dscl . -create "/Users/${jailuser}" NFSHomeDirectory "/var/empty" &&
    /usr/bin/dscl . -create "/Users/${jailuser}" GeneratedUID "$(/usr/bin/uuidgen)" &&
    /usr/bin/dscl . -create "/Users/${jailuser}" Password "*"
then
    echo "Added user \"${jailuser}\"."
else
    echo "Adding user \"${jailuser}\" failed..."
    echo "Please create it, then try again."
    exit 1
fi

if ! /bin/test -d "${jaildir}"; then
    /bin/mkdir "${jaildir}"
fi

if /usr/bin/install -o root -g wheel -d ${DESTDIR}/Library/StartupItems/RCynic &&
   /usr/bin/install -o root -g wheel -m 555 RCynic/RCynic RCynic/StartupParameters.plist ${DESTDIR}/Library/StartupItems/RCynic; then
    echo "Installed ${DESTDIR}/Library/StartupItems/RCynic"
else
    echo "Installing ${DESTDIR}/Library/StartupItems/RCynic failed"
    exit 1
fi

echo "Running ${DESTDIR}/Library/StartupItems/RCynic/RCynic to set up directories"

if ! rcynic_jaildir="$jaildir" rcynic_user="$jailuser" rcynic_group="$jailgroup"  /Library/StartupItems/RCynic/RCynic start; then
    echo "Directory setup failed"
    exit 1
fi

if /bin/test -r "$jaildir/etc/rcynic.conf"; then
    echo "You already have config file \"${jaildir}/etc/rcynic.conf\", so I will use it."
elif /usr/bin/install -m 444 -o root -g wheel -p ../sample-rcynic.conf "${jaildir}/etc/rcynic.conf"; then
    echo "Installed minimal ${jaildir}/etc/rcynic.conf, adding SAMPLE trust anchors"
    for i in ../../sample-trust-anchors/*.tal; do
	j="$jaildir/etc/trust-anchors/${i##*/}"
	/bin/test -r "$i" || continue
	/bin/test -r "$j" && continue
	echo "Installing $i as $j"
	/usr/bin/install -m 444 -o root -g wheel -p "$i" "$j"
    done
    j=1
    for i in $jaildir/etc/trust-anchors/*.tal; do
	echo >>"${jaildir}/etc/rcynic.conf" "trust-anchor-locator.$j	= /etc/trust-anchors/${i##*/}"
	j=$((j+1))
    done
else
    echo "Installing minimal ${jaildir}/etc/rcynic.conf failed"
    exit 1
fi

echo "Installing rcynic as ${jaildir}/bin/rcynic"

/usr/bin/install -m 555 -o root -g wheel -p ../../rcynic "${jaildir}/bin/rcynic"

if /bin/test -x "$jaildir/bin/rsync"; then
    echo "You already have an executable \"$jaildir/bin/rsync\", so I will use it"
elif /usr/bin/install -m 555 -o root -g wheel -p /usr/bin/rsync "${jaildir}/bin/rsync"; then
    echo "Installed ${jaildir}/bin/rsync"
else
    echo "Installing ${jaildir}/bin/rsync failed"
    exit 1
fi

echo "Copying required shared libraries" 

shared_libraries="${jaildir}/bin/rcynic ${jaildir}/bin/rsync"
while true
do
    closure="$(/usr/bin/otool -L ${shared_libraries} | /usr/bin/awk '/:$/ {next} {print $1}' | /usr/bin/sort -u)"
    if test "x$shared_libraries" = "x$closure"
    then
	break
    else
	shared_libraries="$closure"
    fi
done

for shared in /usr/lib/dyld $shared_libraries
do
    if /bin/test -r "${jaildir}/${shared}"
    then
	echo "You already have a \"${jaildir}/${shared}\", so I will use it"
    elif /usr/bin/install -m 555 -o root -g wheel -p "${shared}" "${jaildir}/${shared}"
    then
	echo "Copied ${shared} into ${jaildir}"
    else
        echo "Unable to copy ${shared} into ${jaildir}"
	exit 1
    fi
done

if /usr/bin/install -m 444 -o root -g wheel -p ../../rcynic.py "${jaildir}/etc/rcynic.py"; then
    echo "Installed rcynic.py as \"${jaildir}/etc/rcynic.py\""
else
    echo "Installing rcynic.py failed"
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
