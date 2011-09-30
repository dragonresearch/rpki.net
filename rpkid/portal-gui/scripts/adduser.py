# $Id$
#
# Copyright (C) 2010, 2011  SPARTA, Inc. dba Cobham Analytic Solutions
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
#
#
# Helper script to quickly set up a new portal-gui user/handle.  This script
# is designed to be safe to run multiple times for the same user.
#
# DO NOT EDIT!  This script is automatically generated from adduser.py

import os
os.environ['DJANGO_SETTINGS_MODULE'] = 'rpki.gui.settings'

from django.contrib.auth.models import User
from rpki.gui.app import settings
from rpki.gui.app.models import Conf

import os
import sys
import getpass
import pwd

# The username that apache runs as.  This is required so that we can chown
# the csv files that the portal-gui needs to write.
web_uid = pwd.getpwnam(settings.WEB_USER)[2]

if __name__ == '__main__':
    if len(sys.argv) < 3:
	print >>sys.stderr, 'usage: adduser <username> <user\'s email> <host handle>'
	sys.exit(1)

    if os.getuid() != 0:
        print >>sys.stderr, 'error: this script must be run as root so it can set file permissions.'
        sys.exit(1)

    username = sys.argv[1]
    email = sys.argv[2]
    host = sys.argv[3]
    print 'username=', username, 'email=', email, 'host=', host

    user_set = User.objects.filter(username=username)
    if user_set:
	print >>sys.stderr, 'user already exists'
	user = user_set[0]
    else:
	print >>sys.stderr, 'creating user'
        password = getpass.getpass()
	user = User.objects.create_user(username, email, password)

    conf_set = Conf.objects.filter(handle=username)
    if conf_set:
	conf = conf_set[0]
    else:
	print >>sys.stderr, 'creating conf'
	conf = Conf.objects.create(handle=username)

    # always try to add the user as owner just in case the Conf object was
    # created previously by the "list_resources" script
    conf.owner.add(user)

    if host != username:
        host_set = Conf.objects.filter(handle=host)
        if not host_set:
            print >>sys.stderr, 'error: Conf object for host %s does not exist!' % host
            sys.exit(1)

        conf.host = host_set[0]
    else:
        print >>sys.stderr, '%s is self-hosted' % username
    conf.save()
    
    myrpki_dir = '%s/%s' % (settings.CONFDIR, username)
    print 'myrpki_dir=', myrpki_dir
    if not os.path.exists(myrpki_dir):
	print 'creating ', myrpki_dir
	os.mkdir(myrpki_dir)
    os.chown(myrpki_dir, web_uid, -1)

# vim:sw=4 ts=8
