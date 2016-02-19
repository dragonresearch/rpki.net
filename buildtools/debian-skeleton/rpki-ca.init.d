#!/bin/sh
### BEGIN INIT INFO
# Provides:          rpki-ca
# Required-Start:    $local_fs $network $remote_fs $syslog postgresql
# Required-Stop:     $local_fs $network $remote_fs $syslog postgresql
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: RPKI CA Servers
### END INIT INFO

# Author: Rob Austein <sra@hactrn.net>

# PATH should only include /usr/* if it runs after the mountnfs.sh script
PATH=/sbin:/usr/sbin:/bin:/usr/bin
DESC="rpki-ca"
NAME=rpki-ca
STARTER=/usr/sbin/rpki-start-servers
STARTER_OPTS="--log-level warning --log-directory /var/log/rpki --log-rotating-file-hours 3 --log-backup-count 56"
PIDDIR=/var/run/rpki
SCRIPTNAME=/etc/init.d/$NAME

# Exit if the package is not installed
test -x "$STARTER" || exit 0

# Read configuration variable file if it is present
test -r /etc/default/$NAME && . /etc/default/$NAME

# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.2-14) to ensure that this file is present
# and status_of_proc is working.
. /lib/lsb/init-functions

#
# Extract list of enabled RPKI daemons from config file.
#

enabled_daemons()
{
    python -c 'if True:
        import rpki.config
        cfg = rpki.config.parser(section = "myrpki")
        enabled = [name for name in ("rpkid", "irdbd", "pubd", "rootd")
                   if cfg.getboolean("run_{}".format("rpkid" if name == "irdbd" else name))]
        for name in sorted(enabled):
            print name
    '
}

#
# Figure out which daemons are actually running at the moment.
#

running_daemons()
{
    for pidfile in $PIDDIR/*.pid
    do
	test -f "$pidfile" || continue
	cmdline=/proc/$(cat $pidfile)/cmdline
	name=${pidfile##*/}
	test -f $cmdline &&
	awk -v name=${name%.pid} 'BEGIN {FS="\0"} $2 ~ ("/" name "$") {print name}' $cmdline
    done
}

#
# Function that starts the daemon/service
#
do_start()
{
    # Return
    #   0 if daemon has been started
    #   1 if daemon was already running
    #   2 if daemon could not be started

    test -f /etc/rpki.conf || return 2

    enabled="$(enabled_daemons)"
    running="$(running_daemons)"

    test "X$enabled" = "X" && return 0
    test "X$enabled" = "X$running" && return 1

    test -d $PIDDIR || install -d -u rpki -g rpki $PIDDIR || return 2

    test -f /usr/share/rpki/bpki/ca.cer   || return 2
    test -f /usr/share/rpki/bpki/irbe.cer || return 2

    case $enabled in
	*rpkid*)
	    test -f /usr/share/rpki/bpki/irdbd.cer || return 2
	    test -f /usr/share/rpki/bpki/rpkid.cer || return 2
	    test -f /usr/share/rpki/bpki/rpkid.key || return 2
    esac

    case $enabled in
	*pubd*)
	    test -f /usr/share/rpki/bpki/pubd.cer || return 2
	    test -f /usr/share/rpki/bpki/pubd.key || return 2

	    for dir in /usr/share/rpki/publication /usr/share/rpki/rrdp-publication
	    do
		test -d $dir || install -d -u rpki -g rpki $dir || return 2
	    done
    esac

    case $enabled in
	*rootd*)
	    test -f /usr/share/rpki/bpki/rootd.cer || return 2
	    test -f /usr/share/rpki/bpki/rootd.key || return 2
	    test -f /usr/share/rpki/root.cer       || return 2
	    test -f /usr/share/rpki/root.key       || return 2
    esac

    $STARTER $STARTER_OPTS || return 2
}

#
# Function that stops the daemon/service
#
do_stop()
{
    # Return
    #   0 if daemon has been stopped
    #   1 if daemon was already stopped
    #   2 if daemon could not be stopped
    #   other if a failure occurred

    running="$(running_daemons)"

    test "X$running" = "X" && return 1

    for name in $running
    do
	kill $(cat $PIDDIR/$name.pid)
    done
    return 0
}

case "$1" in
    start)
	test "$VERBOSE" != no && log_daemon_msg "Starting $DESC" "$NAME"
	do_start
	case "$?" in
	    0|1) test "$VERBOSE" != no && log_end_msg 0 ;;
	    2)   test "$VERBOSE" != no && log_end_msg 1 ;;
	esac
	;;
    stop)
	test "$VERBOSE" != no && log_daemon_msg "Stopping $DESC" "$NAME"
	do_stop
	case "$?" in
	    0|1) test "$VERBOSE" != no && log_end_msg 0 ;;
	    2)   test "$VERBOSE" != no && log_end_msg 1 ;;
	esac
	;;
    status)
	enabled="$(enabled_daemons)"
	running="$(running_daemons)"
	if test "X$running" = "X"
	then
	    log_success_msg "rpki-ca is not running"
	    exit 3
	elif test "X$running" = "X$enabled"
	then
	    log_success_msg "rpki-ca is running"
	    exit 0
	else
	    log_success_msg "some rpki-ca daemons are running"
	    exit 4
	fi
	;;
    restart|force-reload)
	log_daemon_msg "Restarting $DESC" "$NAME"
	do_stop
	case "$?" in
	    0|1)
		do_start
		case "$?" in
		    0) log_end_msg 0 ;;
		    1) log_end_msg 1 ;; # Old process is still running
		    *) log_end_msg 1 ;; # Failed to start
		esac
		;;
	    *)
		# Failed to stop
		log_end_msg 1
		;;
	esac
	;;
    *)
	echo "Usage: $SCRIPTNAME {start|stop|status|restart|force-reload}" >&2
	exit 3
	;;
esac

:
