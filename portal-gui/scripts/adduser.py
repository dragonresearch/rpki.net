#!/usr/bin/env python
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

from django.contrib.auth.models import User
from django.conf import settings
from rpkigui.myrpki.models import Conf, Parent

import os
import sys

if __name__ == '__main__':
    if len(sys.argv) < 3:
	print >>sys.stderr, 'usage: adduser <name> <email> <parent>'
	sys.exit(1)

    username = sys.argv[1]
    email = sys.argv[2]
    parent = sys.argv[3]
    print 'username=', username, 'email=', email, 'parent=', parent

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
	conf.save()

    parent_set = conf.parents.filter(handle=parent)
    if parent_set:
	print 'parent %s is already present' % parent
    else:
	print "creating %s' parent %s" % (username, parent)
	parent = Parent.objects.create(handle=parent, conf=conf)

    myrpki_dir = '%s/%s' % (settings.MYRPKI_DATA_DIR, username)
    print 'myrpki_dir=', myrpki_dir
    if not os.path.exists(myrpki_dir):
	print 'creating ', myrpki_dir
	os.mkdir(myrpki_dir)

    # create stuf myrpki.conf enough to fool portal-gui
    myrpki_conf = myrpki_dir + '/myrpki.conf'
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
                pass # just create an empty file

# vim:sw=4 ts=8
