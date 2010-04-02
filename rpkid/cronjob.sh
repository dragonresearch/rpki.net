#!/bin/sh -
# $Id$

# Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

# Generate Doxygen manual for RPKI code.

lock=cronjob.lock

target=/usr/local/www/data/www.hactrn.net/rpki-dox

cd `/usr/bin/dirname $0` || exit

case "$1" in

locked)
    exec >cronjob.log 2>&1
    set -x
    /usr/local/bin/svn update --quiet
    (cd .. && ./configure)
    /bin/rm -rf doc/html
    PATH=/bin:/usr/bin:/usr/local/bin /usr/bin/make docs </dev/null
    /usr/local/bin/rsync --archive --itemize-changes --delete-after doc/html/ $target/
    ;;

*)
    exec /usr/bin/lockf -s -t 0 $lock "$0" locked
    ;;

esac
