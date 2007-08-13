#!/bin/sh -
# $Id$
#
# Generate Doxygen manual for RPKI code.
#
# At the moment this is just for the Python libraries.

lock=cronjob.lock

target=/usr/local/www/data/www.hactrn.net/rpki-dox

cd `/usr/bin/dirname $0` || exit

case "$1" in

locked)
    exec >cronjob.log 2>&1
    set -x
    cd rpki || exit
    /usr/local/bin/svn update --quiet
    /bin/rm -rf html
    /usr/local/bin/doxygen
    /usr/local/bin/rsync --archive --itemize-changes --delete-after html/ $target/
    ;;

*)
    exec /usr/bin/lockf -s -t 0 $lock "$0" locked
    ;;

esac
