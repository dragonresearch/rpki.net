#!/bin/sh
# $Id$
#
# Since using the configure script to build the portal-gui can be somewhat
# challenging, this script can be used to simplify the process.  You may
# need to tailor the configure command to be run at the end.

# Change this path to the location of the sqlite3 database that the portal-gui
# uses to store its settings.
DATABASE_PATH=/usr/local/share/portal-gui/myrpki.db

# This is the directory under which the subdirectories for each hosted RPKI
# resource handle live.  Note that is is *not* the directory containing your
# myrpki.conf.
CONFDIR=/usr/local/etc/rpki

# This is the directory containing the myrpki.py command line script.  You
# can either install it somewhere on your system, or just run it out of
# wherever you checked out from the svn repo
MYRPKI_SOURCE_DIR=/usr/local/src/subvert-rpki.hactrn.net/rpkid

# If your preferred python interpreter is not in /usr/bin, you need to specify
# the full path here
#PYTHON='--with-python=/usr/local/bin/python'

### END OF CONFIGURATION ###

./configure --with-myrpki=$MYRPKI_SOURCE_DIR CONFDIR=$CONFDIR \
	DATABASE_PATH=$DATABASE_PATH $PYTHON
