# Copyright (C) 2011  SPARTA, Inc. dba Cobham
# Copyright (C) 2012, 2013  SPARTA, Inc. a Parsons Company
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
__all__ = ('import_rcynic_xml')

default_logfile = '/var/rcynic/data/rcynic.xml'
default_root = '/var/rcynic/data'
object_accepted = None  # set by import_rcynic_xml()

import time
import vobject
import logging
import os
from socket import getfqdn
from cStringIO import StringIO

from django.db import transaction
import django.db.models
from django.core.mail import send_mail

import rpki
import rpki.gui.app.timestamp
from rpki.gui.app.models import Conf
from rpki.gui.app.glue import get_email_list
from rpki.gui.cacheview import models
from rpki.rcynic import rcynic_xml_iterator, label_iterator
from rpki.sundial import datetime
from rpki.irdb.zookeeper import Zookeeper

logger = logging.getLogger(__name__)


def rcynic_cert(cert, obj):
    obj.sia = cert.sia_directory_uri

    # object must be saved for the related manager methods below to work
    obj.save()
    # resources can change when a cert is updated
    obj.asns.clear()
    obj.addresses.clear()

    if cert.resources.asn.inherit:
        # FIXME: what happens when the parent's resources change and the child
        # cert is not reissued?
        obj.asns.add(*obj.issuer.asns.all())
    else:
        for asr in cert.resources.asn:
            logger.debug('processing %s' % asr)

            attrs = {'min': asr.min, 'max': asr.max}
            q = models.ASRange.objects.filter(**attrs)
            if not q:
                obj.asns.create(**attrs)
            else:
                obj.asns.add(q[0])

    # obj.issuer is None the first time we process the root cert in the
    # hierarchy, so we need to guard against dereference
    for cls, addr_obj, addrset, parentset in (
        models.AddressRange, obj.addresses, cert.resources.v4,
        obj.issuer.addresses.all() if obj.issuer else []
    ), (
        models.AddressRangeV6, obj.addresses_v6, cert.resources.v6,
        obj.issuer.addresses_v6.all() if obj.issuer else []
    ):
        if addrset.inherit:
            addr_obj.add(*parentset)
        else:
            for rng in addrset:
                logger.debug('processing %s' % rng)

                attrs = {'prefix_min': rng.min, 'prefix_max': rng.max}
                q = cls.objects.filter(**attrs)
                if not q:
                    addr_obj.create(**attrs)
                else:
                    addr_obj.add(q[0])


def rcynic_roa(roa, obj):
    obj.asid = roa.asID
    # object must be saved for the related manager methods below to work
    obj.save()
    obj.prefixes.clear()
    obj.prefixes_v6.clear()
    for pfxset in roa.prefix_sets:
        if pfxset.__class__.__name__ == 'roa_prefix_set_ipv6':
            roa_cls = models.ROAPrefixV6
            prefix_obj = obj.prefixes_v6
        else:
            roa_cls = models.ROAPrefixV4
            prefix_obj = obj.prefixes

        for pfx in pfxset:
            attrs = {'prefix_min': pfx.min(),
                     'prefix_max': pfx.max(),
                     'max_length': pfx.max_prefixlen}
            q = roa_cls.objects.filter(**attrs)
            if not q:
                prefix_obj.create(**attrs)
            else:
                prefix_obj.add(q[0])


def rcynic_gbr(gbr, obj):
    vcard = vobject.readOne(gbr.vcard)
    obj.full_name = vcard.fn.value if hasattr(vcard, 'fn') else None
    obj.email_address = vcard.email.value if hasattr(vcard, 'email') else None
    obj.telephone = vcard.tel.value if hasattr(vcard, 'tel') else None
    obj.organization = vcard.org.value[0] if hasattr(vcard, 'org') else None

LABEL_CACHE = {}

# dict keeping mapping of uri to (handle, old status, new status) for objects
# published by the local rpkid
uris = {}


def save_statuses(inst, statuses):
    valid = False
    for vs in statuses:
        timestamp = datetime.fromXMLtime(vs.timestamp).to_sql()
        status = LABEL_CACHE[vs.status]
        g = models.generations_dict[vs.generation] if vs.generation else None
        inst.statuses.create(generation=g, timestamp=timestamp, status=status)
        valid = valid or status is object_accepted

    # if this object is in our interest set, update with the current validation
    # status
    if inst.uri in uris:
        x, y, z, q = uris[inst.uri]
        uris[inst.uri] = x, y, valid, inst


@transaction.commit_on_success
def process_cache(root, xml_file):
    dispatch = {
        'rcynic_certificate': rcynic_cert,
        'rcynic_roa': rcynic_roa,
        'rcynic_ghostbuster': rcynic_gbr
    }
    model_class = {
        'rcynic_certificate': models.Cert,
        'rcynic_roa': models.ROA,
        'rcynic_ghostbuster': models.Ghostbuster
    }

    last_uri = None
    statuses = []

    logger.info('clearing validation statuses')
    models.ValidationStatus.objects.all().delete()

    logger.info('updating validation status')
    for vs in rcynic_xml_iterator(root, xml_file):
        if vs.uri != last_uri:
            if statuses:
                obj, created = models.RepositoryObject.objects.get_or_create(uri=last_uri)
                save_statuses(obj, statuses)

            statuses = []
            last_uri = vs.uri

        statuses.append(vs)

        if vs.status == 'object_accepted':
            logger.debug('processing %s' % vs.filename)

            cls = model_class[vs.file_class.__name__]
            q = cls.objects.filter(repo__uri=vs.uri)
            if not q:
                repo, created = models.RepositoryObject.objects.get_or_create(uri=vs.uri)
                inst = cls(repo=repo)
            else:
                inst = q[0]

            # determine if the object is changed/new
            mtime = os.stat(vs.filename)[8]
            if mtime != inst.mtime:
                inst.mtime = mtime
                try:
                    obj = vs.obj  # causes object to be lazily loaded
                except Exception, e:
                    logger.warning('Caught %s while processing %s: %s' % (
                        type(e), vs.filename, e))
                    continue

                inst.not_before = obj.notBefore.to_sql()
                inst.not_after = obj.notAfter.to_sql()
                inst.name = obj.subject
                inst.keyid = obj.ski

                # look up signing cert
                if obj.issuer == obj.subject:
                    # self-signed cert (TA)
                    assert(isinstance(inst, models.Cert))
                    inst.issuer = None
                else:
                    # if an object has moved in the repository, the entry for
                    # the old location will still be in the database, but
                    # without any object_accepted in its validtion status
                    qs = models.Cert.objects.filter(
                        keyid=obj.aki,
                        name=obj.issuer,
                        repo__statuses__status=object_accepted
                    )
                    ncerts = len(qs)
                    if ncerts == 0:
                        logger.warning('unable to find signing cert with ski=%s (%s)' % (obj.aki, obj.issuer))
                        continue
                    else:
                        if ncerts > 1:
                            # multiple matching certs, all of which are valid
                            logger.warning('Found multiple certs matching ski=%s sn=%s' % (obj.aki, obj.issuer))
                            for c in qs:
                                logger.warning(c.repo.uri)
                        # just use the first match
                        inst.issuer = qs[0]

                try:
                    # do object-specific tasks
                    dispatch[vs.file_class.__name__](obj, inst)

                    inst.save()  # don't require a save in the dispatch methods

                    # for the root cert, we can't set inst.issuer = inst until
                    # after inst.save() has been called.
                    if inst.issuer is None:
                        inst.issuer = inst
                        inst.save()
                except:
                    logger.error('caught exception while processing rcynic_object:\n'
                                 'vs=' + repr(vs) + '\nobj=' + repr(obj))
                    # .show() writes to stdout
                    obj.show()
                    raise
            else:
                logger.debug('object is unchanged')

            # insert the saved validation statuses now that the object has been
            # created.
            #save_statuses(inst.repo, statuses)
            #statuses = []

    # process any left over statuses for an object that was not ultimately
    # accepted
    if statuses:
        obj, created = models.RepositoryObject.objects.get_or_create(uri=last_uri)
        save_statuses(obj, statuses)

    # garbage collection
    # remove all objects which have no ValidationStatus references, which
    # means they did not appear in the last XML output
    logger.info('performing garbage collection')

    # Delete all objects that have zero validation status elements.
    models.RepositoryObject.objects.annotate(num_statuses=django.db.models.Count('statuses')).filter(num_statuses=0).delete()


@transaction.commit_on_success
def process_labels(xml_file):
    logger.info('updating labels...')

    for label, kind, desc in label_iterator(xml_file):
        logger.debug('label=%s kind=%s desc=%s' % (label, kind, desc))
        if kind:
            q = models.ValidationLabel.objects.filter(label=label)
            if not q:
                obj = models.ValidationLabel(label=label)
            else:
                obj = q[0]

            obj.kind = models.kinds_dict[kind]
            obj.status = desc
            obj.save()

            LABEL_CACHE[label] = obj


def fetch_published_objects():
    """Query rpkid for all objects published by local users, and look up the
    current validation status of each object.  The validation status is used
    later to send alerts for objects which have transitioned to invalid.

    """
    logger.info('querying for published objects')

    handles = [conf.handle for conf in Conf.objects.all()]
    req = [rpki.left_right.list_published_objects_elt.make_pdu(action='list', self_handle=h, tag=h) for h in handles]
    z = Zookeeper()
    pdus = z.call_rpkid(*req)
    for pdu in pdus:
        if isinstance(pdu, rpki.left_right.list_published_objects_elt):
            # Look up the object in the rcynic cache
            qs = models.RepositoryObject.objects.filter(uri=pdu.uri)
            if qs:
                # get the current validity state
                valid = qs[0].statuses.filter(status=object_accepted).exists()
                uris[pdu.uri] = (pdu.self_handle, valid, False, None)
                logger.debug('adding ' + pdu.uri)
            else:
                # this object is not in the cache.  it was either published
                # recently, or disappared previously.  if it disappeared
                # previously, it has already been alerted.  in either case, we
                # omit the uri from the list since we are interested only in
                # objects which were valid and are no longer valid
                pass
        elif isinstance(pdu, rpki.left_right.report_error_elt):
            logging.error('rpkid reported an error: %s' % pdu.error_code)


class Handle(object):
    def __init__(self):
        self.invalid = []
        self.missing = []

    def add_invalid(self, v):
        self.invalid.append(v)

    def add_missing(self, v):
        self.missing.append(v)


def notify_invalid():
    """Send email alerts to the addresses registered in ghostbuster records for
    any invalid objects that were published by users of this system.

    """

    logger.info('sending notifications for invalid objects')

    # group invalid objects by user
    notify = {}
    for uri, v in uris.iteritems():
        handle, old_status, new_status, obj = v

        if obj is None:
            # object went missing
            n = notify.get(handle, Handle())
            n.add_missing(uri)
        # only select valid->invalid
        elif old_status and not new_status:
            n = notify.get(handle, Handle())
            n.add_invalid(obj)

    for handle, v in notify.iteritems():
        conf = Conf.objects.get(handle)
        emails = get_email_list(conf)

        msg = StringIO()
        msg.write('This is an alert about problems with objects published by '
                  'the resource handle %s.\n\n' % handle)

        if v.invalid:
            msg.write('The following objects were previously valid, but are '
                      'now invalid:\n')

            for o in v.invalid:
                msg.write('\n')
                msg.write(o.repo.uri)
                msg.write('\n')
                for s in o.statuses.all():
                    msg.write('\t')
                    msg.write(s.status.label)
                    msg.write(': ')
                    msg.write(s.status.status)
                    msg.write('\n')

        if v.missing:
            msg.write('The following objects were previously valid but are no '
                      'longer in the cache:\n')

            for o in v.missing:
                msg.write(o)
                msg.write('\n')

        msg.write("""--
You are receiving this email because your address is published in a Ghostbuster
record, or is the default email address for this resource holder account on
%s.""" % getfqdn())

        from_email = 'root@' + getfqdn()
        subj = 'invalid RPKI object alert for resource handle %s' % conf.handle
        send_mail(subj, msg.getvalue(), from_email, emails)


def import_rcynic_xml(root=default_root, logfile=default_logfile):
    """Load the contents of rcynic.xml into the rpki.gui.cacheview database."""

    global object_accepted

    start = time.time()
    process_labels(logfile)
    object_accepted = LABEL_CACHE['object_accepted']
    fetch_published_objects()
    process_cache(root, logfile)
    notify_invalid()

    rpki.gui.app.timestamp.update('rcynic_import')

    stop = time.time()
    logger.info('elapsed time %d seconds.' % (stop - start))
