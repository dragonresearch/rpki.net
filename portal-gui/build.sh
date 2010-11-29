#!/bin/sh
# $Id$
#
# Copyright (C) 2010  SPARTA, Inc. dba Cobham Analytic Solutions
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND SPARTA DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL SPARTA BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.


# Since using the configure script to build the portal-gui can be somewhat
# challenging, this script can be used to simplify the process.  You may
# need to tailor the configure command to be run at the end if this script
# doesn't provide a hook for your needs.

### REQUIRED SETTINGS ###
#
# You MUST configure the settings in this section for the portal-gui to be
# installed correctly.

# This is the directory under which the subdirectories for each hosted RPKI
# resource handle live.  Note that is is *not* the directory containing your
# myrpki.conf.
CONFDIR=/usr/local/etc/rpki

# This is the directory containing the myrpki.py command line script.  You
# can either install it somewhere on your system, or just run it out of
# wherever you checked out from the svn repo
MYRPKI_SOURCE_DIR=/usr/local/src/net/subvert-rpki.hactrn.net/rpkid

# The user that the apache process is run as.  This is required to set
# permissions on the directories/files that the portal-gui needs to be able to
# read/write.
WEBUSER=www

### OPTIONAL SETTINGS ###
#
# The configuration in this section allows you to tailor for you local
# environment for some common cases.  You do not need to modify these unless
# you have a specific need.

# Change this path to the location of the sqlite3 database that the portal-gui
# uses to store its settings.
#DBPATH="DATABASE_PATH=/usr/local/etc/rpki/sqlite3"

# If your preferred python interpreter is not in /usr/bin, you need to specify
# the full path here
#PYTHON='--with-python=/usr/local/bin/python'

# If you want to install somehwere other than /usr/local/ uncomment and edit
# the following line
#prefix="--prefix=$HOME/opt/myrpki"

### END OF CONFIGURATION ###

./configure $prefix --with-myrpki=$MYRPKI_SOURCE_DIR WEBUSER=$WEBUSER CONFDIR=$CONFDIR \
	$DBPATH $PYTHON
