#!/bin/sh -
# $Id$

lock=cronjob.lock
script=$HOME/subvert-rpki.hactrn.net/trunk/buildtools/pull-doc-from-wiki.py

cd `/usr/bin/dirname $0` || exit

case "$1" in

locked)
    exec >cronjob.log 2>&1
    set -x
    export PATH=/bin:/usr/bin:/usr/local/bin
    /usr/local/bin/svn update
    /usr/local/bin/python $script
    /usr/local/bin/svn status
    if test -n "$(/usr/local/bin/svn status doc.*)"
    then
	/usr/local/bin/svn add --force doc.* manual.pdf
	/usr/local/bin/svn commit --message 'Automatic pull of documentation from Wiki.' doc.* manual.pdf
    else
	/usr/local/bin/svn revert manual.pdf
    fi
    /usr/local/bin/svn update
    ;;
*)
    exec /usr/bin/lockf -s -t 0 $lock "$0" locked
    ;;

esac
