#!@PYTHON@
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
#
#
# helper script to quickly set up a new portal-gui user/handle

import os, sys
sys.path.append('@INSTDIR@')
os.environ['DJANGO_SETTINGS_MODULE'] = 'rpkigui.settings'

from django.contrib.auth.models import User
from django.conf import settings
from rpkigui.myrpki.models import Conf

WEB_USER='@WEBUSER@'

import os
import sys
import hashlib
import getpass
import pwd

web_uid = pwd.getpwnam(WEB_USER)[2]

# FIXME: hardcoded for now
realm = 'rpki'

def user_has_password(passfile, username):
    'returns True if username is found in the specified password file'
    if os.path.exists(passfile):
        with open(passfile,'r') as f:
            for line in f:
                if line.split(':')[0] == username:
                    return True
    return False

def update_apache_auth_file(passfile, username, realm, password):
    ha1 = hashlib.md5("%s:%s:%s" % (username, realm, password)).hexdigest()
    with open(passfile, 'a') as f:
        f.write("%s:%s:%s\n" % (username, realm, ha1))

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
	# FIXME: password is absent, assuming that apache auth is used.
	user = User.objects.create_user(username, email)

    conf_set = Conf.objects.filter(handle=username)
    if conf_set:
	conf = conf_set[0]
    else:
	print >>sys.stderr, 'creating conf'
	conf = Conf.objects.create(handle=username)
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
    
    myrpki_dir = '%s/%s' % (settings.MYRPKI_DATA_DIR, username)
    print 'myrpki_dir=', myrpki_dir
    if not os.path.exists(myrpki_dir):
	print 'creating ', myrpki_dir
	os.mkdir(myrpki_dir)
    os.chown(myrpki_dir, web_uid, -1)

    # create stuf rpki.conf enough to fool portal-gui
    myrpki_conf = myrpki_dir + '/rpki.conf'
    if not os.path.exists(myrpki_conf):
	print 'creating ', myrpki_conf
	with open(myrpki_conf, 'w') as f:
	    print >>f, """[myrpki]
run_rpkidemo=true
run_rpkid=false
asn_csv=%(path)s/asns.csv
roa_csv=%(path)s/roas.csv
prefix_csv=%(path)s/prefixes.csv""" % { 'path': myrpki_dir }

    # create empty csv files so portal-gui doesn't barf
    for base in ['roas', 'asns', 'prefixes']:
        fname = '%s/%s.csv' % (myrpki_dir, base)
        if not os.path.exists(fname):
            print 'creating ', fname
            with open(fname, 'w') as f:
                # just create an empty file
                pass
        os.chown(fname, web_uid, -1)

    # add a password for this user to the apache passwd file if not present

    #determine where the passwd file is likely to reside
    # <prefix>/portal-gui/scripts/adduser.py
    path = os.path.realpath(sys.argv[0])
    prefix = '/'.join(path.split('/')[:-2]) # strip trailing components
    passfile = prefix+'/htpasswd'
    print 'passfile=', passfile
    if not user_has_password(passfile, username):
        print 'adding user to apache password file'
        password = getpass.getpass()
        update_apache_auth_file(passfile, username, realm, password)
    else:
        print 'user is already present in apache password file'

# vim:sw=4 ts=8
