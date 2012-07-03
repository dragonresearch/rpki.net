# Copyright (C) 2012  SPARTA, Inc. a Parsons Company
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
# Generate a report of all RPKI certs which are about to expire

__version__ = '$Id$'

from rpki.gui.cacheview.models import Cert
from rpki.gui.cacheview.views import cert_chain
from rpki.gui.app.models import ResourceCert, Conf

import datetime
import sys
from optparse import OptionParser

# check for certs expiring in this many days or less
expire_days = 14

expire_time = datetime.datetime.utcnow() + datetime.timedelta(expire_days)

Verbose = False


def check_expire(handle):
    if Verbose:
        print 'checking rescert expiration for %s' % handle
    # get certs for `handle'
    cert_set = ResourceCert.objects.filter(parent__issuer=handle)
    for cert in cert_set:
        # look up cert in cacheview db
        obj_set = Cert.objects.filter(repo__uri=cert.uri)
        if not obj_set:
            print >>sys.stderr, "Unable to locate rescert %s in rcynic cache" % cert.uri
            continue
        obj = obj_set[0]
        cert_list = cert_chain(obj)
        msg = []
        expired = False
        for n, c in cert_list:
            if c.not_after <= expire_time:
                expired = True
                f = '*'
            else:
                f = ' '
            msg.append("%s  [%d] uri=%s ski=%s name=%s expires=%s" % (f, n, c.repo.uri, c.keyid, c.name, c.not_after))
        if expired:
            print "Warning: resource cert for user %s will expire soon:\n"
        if expired or Verbose:
            print "Certificate chain:"
            print "\n".join(msg)


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-v', '--verbose', help='enable verbose output',
                      action='store_true', dest='verbose',
                      default=False)
    parser.add_option('-V', '--version', help='display script version',
                      action='store_true', dest='version', default=False)
    (options, args) = parser.parse_args()
    if options.version:
        print __version__
        sys.exit(0)
    Verbose = options.verbose

    # check expiration of certs for all handles managed by the web portal
    for h in Conf.objects.all():
        check_expire(h)

    sys.exit(0)
