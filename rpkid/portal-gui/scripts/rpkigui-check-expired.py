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

__version__ = '$Id$'

from rpki.gui.cacheview.models import Cert
from rpki.gui.cacheview.views import cert_chain
from rpki.gui.app.models import Conf, ResourceCert
from rpki.gui.app.glue import list_received_resources, get_email_list
from rpki.irdb import Zookeeper
from rpki.left_right import report_error_elt, list_published_objects_elt
from rpki.x509 import X509

from django.core.mail import send_mail

import datetime
import sys
import socket
from optparse import OptionParser
from cStringIO import StringIO


def check_cert(handle, p, errs):
    """Check the expiration date on the X.509 certificates in each element of
    the list.

    The displayed object name defaults to the class name, but can be overridden
    using the `object_name` argument.

    """
    t = p.certificate.getNotAfter()
    if t <= expire_time:
        e = 'expired' if t <= now else 'will expire'
        errs.write("%(handle)s's %(type)s %(desc)s %(expire)s on %(date)s\n" % {
            'handle': handle, 'type': p.__class__.__name__, 'desc': str(p),
            'expire': e, 'date': t})


def check_cert_list(handle, x, errs):
    for p in x:
        check_cert(handle, p, errs)


def check_expire(conf, errs):
    # get certs for `handle'
    cert_set = ResourceCert.objects.filter(conf=conf)
    for cert in cert_set:
        # look up cert in cacheview db
        obj_set = Cert.objects.filter(repo__uri=cert.uri)
        if not obj_set:
            # since the <list_received_resources/> output is cached, this can
            # occur if the cache is out of date as well..
            errs.write("Unable to locate rescert in rcynic cache: handle=%s uri=%s not_after=%s\n" % (conf.handle, cert.uri, cert.not_after))
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

            # find ghostbuster records attached to this cert
            for gbr in c.ghostbusters.all():
                info = []
                for s in ('full_name', 'organization', 'email_address', 'telephone'):
                    t = getattr(gbr, s, None)
                    if t:
                        info.append(t)

                msg.append("       Contact: " + ", ".join(info))

        if expired:
            errs.write("%s's rescert from parent %s will expire soon:\n" % (
                conf.handle,
                # parent is None for the root cert
                cert.parent.handle if cert.parent else 'self'
            ))
            errs.write("Certificate chain:\n")
            errs.write("\n".join(msg))
            errs.write("\n")


def check_child_certs(conf, errs):
    """Fetch the list of published objects from rpkid, and inspect the issued
    resource certs (uri ending in .cer).

    """
    z = Zookeeper(handle=conf.handle)
    req = list_published_objects_elt.make_pdu(action="list",
                                              tag="list_published_objects",
                                              self_handle=conf.handle)
    pdus = z.call_rpkid(req)
    for pdu in pdus:
        if isinstance(pdu, report_error_elt):
            print >>sys.stderr, "rpkid reported an error: %s" % pdu.error_code
        elif isinstance(pdu, list_published_objects_elt):
            if pdu.uri.endswith('.cer'):
                cert = X509()
                cert.set(Base64=pdu.obj)
                t = cert.getNotAfter()
                if t <= expire_time:
                    e = 'expired' if t <= now else 'will expire'
                    errs.write("%(handle)s's rescert for Child %(child)s %(expire)s on %(date)s uri=%(uri)s subject=%(subject)s\n" % {
                        'handle': conf.handle,
                        'child': pdu.child_handle,
                        'uri': pdu.uri,
                        'subject': cert.getSubject(),
                        'expire': e,
                        'date': t})


# this is not exactly right, since we have no way of knowing what the
# vhost for the web portal running on this machine is
host = socket.getfqdn()

usage = '%prog [ -nV ] [ handle1 handle2... ]'

description = """Generate a report detailing all RPKI/BPKI certificates which
are due for impending expiration.  If no resource handles are specified, a
report about all resource handles hosted by the local rpkid instance will be
generated."""

parser = OptionParser(usage, description=description)
parser.add_option('-V', '--version', help='display script version',
                    action='store_true', dest='version', default=False)
parser.add_option('-f', '--from', metavar='ADDRESS', default='root@' + host,
                  dest='from_email',
                  help='specify the return email address for notifications [default: %default]')
parser.add_option('-n', '--no-email', action='store_false', dest='email', default=True,
                  help='do not send any email reports [default: %default]')
parser.add_option('-t', '--expire-time',
                  dest='expire_days',
                  default=14,
                  metavar='DAYS',
                  help='specify the number of days in the future to check [default: %default]')
(options, args) = parser.parse_args()
if options.version:
    print __version__
    sys.exit(0)
now = datetime.datetime.utcnow()
expire_time = now + datetime.timedelta(int(options.expire_days))
from_email = options.from_email

# if not arguments are given, query all resource holders
qs = Conf.objects.all() if not args else Conf.objects.filter(handle__in=args)

# check expiration of certs for all handles managed by the web portal
for h in qs:
    # Force cache update since several checks require fresh data
    try:
        list_received_resources(sys.stdout, h)
    except socket.error, e:
        sys.exit('Error while talking to rpkid: %s' % e)

    errs = StringIO()

    check_cert(h.handle, h, errs)

    # HostedCA is the ResourceHolderCA cross certified under ServerCA, so check
    # the ServerCA expiration date as well
    check_cert(h.handle, h.hosted_by, errs)
    check_cert(h.handle, h.hosted_by.issuer, errs)

    check_cert_list(h.handle, h.bscs.all(), errs)
    check_cert_list(h.handle, h.parents.all(), errs)
    check_cert_list(h.handle, h.children.all(), errs)
    check_cert_list(h.handle, h.repositories.all(), errs)

    check_expire(h, errs)
    check_child_certs(h, errs)

    # if there was output, display it now
    s = errs.getvalue()
    if s:
        print s

        if options.email:
            notify_emails = get_email_list(h)

            if notify_emails:
                t = """This is an automated notice about the upcoming expiration of RPKI resources for the handle %s on %s.  You are receiving this notification because your email address is either registered in a Ghostbuster record, or as the default email address for the account.\n\n""" % (h.handle, host)

                send_mail(subject='RPKI expiration notice for %s' % h.handle,
                        message=t + s, from_email=from_email, recipient_list=notify_emails)

sys.exit(0)
