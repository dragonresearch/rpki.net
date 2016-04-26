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

PATH=/sbin:/usr/sbin:/bin:/usr/bin
DESC="rpki-ca"
NAME=rpki-nanny
PIDDIR=/var/run/rpki
LOGDIR=/var/log/rpki
DAEMON=/usr/lib/rpki/$NAME
SCRIPTNAME=/etc/init.d/rpki-ca
PIDFILE=$PIDDIR/$NAME.pid

# Exit if the package is not installed
test -x "$DAEMON" || exit 0

# Read configuration variable file if it is present
test -r /etc/default/rpki-ca && . /etc/default/rpki-ca

# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.2-14) to ensure that this file is present
# and status_of_proc is working.
. /lib/lsb/init-functions

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

    for dir in $PIDDIR $LOGDIR /usr/share/rpki/publication /usr/share/rpki/rrdp-publication
    do
	test -d $dir || install -d -o rpki -g rpki $dir || return 2
    done

    start-stop-daemon --start --quiet --pidfile $PIDFILE --startas $DAEMON --name $NAME --test > /dev/null || return 1
    start-stop-daemon --start --quiet --pidfile $PIDFILE --startas $DAEMON --name $NAME -- $DAEMON_ARGS    || return 2
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

    start-stop-daemon --stop --quiet --oknodo --retry=TERM/30/KILL/5 --pidfile $PIDFILE --name $NAME
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
	status_of_proc "$DAEMON" "$NAME" && exit 0 || exit $?
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
