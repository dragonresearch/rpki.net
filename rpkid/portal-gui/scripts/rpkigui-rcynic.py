# $Id$
# Copyright (C) 2011  SPARTA, Inc. dba Cobham Analytic Solutions
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

from __future__ import with_statement

default_logfile = '/var/rcynic/data/summary.xml'
default_root = '/var/rcynic/data'

import os, sys, time, vobject
os.environ['DJANGO_SETTINGS_MODULE'] = 'rpki.gui.settings'

from rpki.gui.cacheview import models
from rpki.rcynic import rcynic_xml_iterator, label_iterator
from rpki.sundial import datetime
from django.db import transaction

debug = False

class TransactionManager(object):
    """
    Context manager wrapper around the Django transaction API.
    """
    def __enter__(self):
        transaction.enter_transaction_management()
        transaction.managed()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            transaction.commit()
        else:
            transaction.set_clean()
        transaction.leave_transaction_management()
        return False

def process_object(obj, model_class):
    """
    do initial processing on a rcynic_object instance.

    return value is a tuple: first element is a boolean value indicating whether
    the object is changed/new since the last time we processed it.  second
    element is the db instance.
    """
    if debug:
        print 'processing %s at %s' % (obj.__class__.__name__, obj.uri)

    q = model_class.objects.filter(uri=obj.uri)
    if not q:
        if debug:
            print 'creating new db instance'
        inst = model_class(uri=obj.uri)
    else:
        inst = q[0]

    # metadata that is updated on every run, regardless of whether the object
    # has changed
    inst.ok = obj.ok
    inst.status = models.ValidationStatus.objects.get(label=obj.status)
    inst.timestamp = datetime.fromXMLtime(obj.timestamp).to_sql()

    # determine if the object is changed/new
    mtime = os.stat(obj.filename)[8]
    if mtime != inst.mtime:
        inst.mtime = mtime
        inst.not_before = obj.notBefore.to_sql()
        inst.not_after = obj.notAfter.to_sql()
        if debug:
            sys.stderr.write('name=%s ski=%s\n' % (obj.subject, obj.ski))
        inst.name = obj.subject
        inst.keyid = obj.ski

        # look up signing cert
        if obj.issuer == obj.subject:
            # self-signed cert (TA)
            inst.cert = inst
        else:
            q = models.Cert.objects.filter(keyid=obj.aki)
            if q:
                inst.issuer = q[0]
            else:
                sys.stderr.write('warning: unable to find signing cert with ski=%s (%s)\n' % (obj.aki, obj.issuer))

        return True, inst
    elif debug:
        print 'object is unchanged'

    # metadata has changed, so a save is required
    inst.save()

    return False, inst

def process_rescert(cert):
    """
    Process a RPKI resource certificate.
    """

    refresh, obj = process_object(cert, models.Cert)

    if refresh:
        obj.save()

        # resources can change when a cert is updated
        obj.asns.clear()
        obj.addresses.clear()

        with TransactionManager():
            for asr in cert.resources.asn:
                if debug:
                    sys.stderr.write('processing %s\n' % asr)

                attrs = { 'min': asr.min, 'max': asr.max }
                q = models.ASRange.objects.filter(**attrs)
                if not q:
                    obj.asns.create(**attrs)
                else:
                    obj.asns.add(q[0])

            for family, addrset in (4, cert.resources.v4), (6, cert.resources.v6):
                for rng in addrset:
                    if debug:
                        sys.stderr.write('processing %s\n' % rng)

                    attrs = { 'family': family, 'min': str(rng.min), 'max': str(rng.max) }
                    q = models.AddressRange.objects.filter(**attrs)
                    if not q:
                        obj.addresses.create(**attrs)
                    else:
                        obj.addresses.add(q[0])

    if debug:
        print 'finished processing rescert at %s' % cert.uri

    return obj

def process_ghostbuster(gbr):
    refresh, obj = process_object(gbr, models.Ghostbuster)

    if refresh:
        vcard = vobject.readOne(gbr.vcard)
        if debug:
            vcard.prettyPrint()
        obj.full_name = vcard.fn.value if hasattr(vcard, 'fn') else None
        obj.email_address = vcard.email.value if hasattr(vcard, 'email') else None
        obj.telephone = vcard.tel.value if hasattr(vcard, 'tel') else None
        obj.organization = vcard.org.value[0] if hasattr(vcard, 'org') else None
        obj.save()

fam_map = { 'roa_prefix_set_ipv6': 6, 'roa_prefix_set_ipv4': 4 }

def process_roa(roa):
    refresh, obj = process_object(roa, models.ROA)

    if refresh:
        obj.asid = roa.asID
        obj.save()
        with TransactionManager():
            obj.prefixes.clear()
            for pfxset in roa.prefix_sets:
                family = fam_map[pfxset.__class__.__name__]
                for pfx in pfxset:
                    attrs = { 'family' : family,
                              'prefix': str(pfx.prefix),
                              'bits' : pfx.prefixlen,
                              'max_length': pfx.max_prefixlen }
                    q = models.ROAPrefix.objects.filter(**attrs)
                    if not q:
                        obj.prefixes.create(**attrs)
                    else:
                        obj.prefixes.add(q[0])

    return obj

def trydelete(seq):
    """
    iterate over a sequence and attempt to delete each item.  safely
    ignore IntegrityError since the object may be referenced elsewhere.
    """
    for o in seq:
        try:
            o.delete()
        except IntegrityError:
            pass

def garbage_collect(ts):
    """
    rcynic's XML output file tells us what is currently in the cache,
    but not what has been removed.  we save the timestamp from the first
    entry in the XML file, and remove all objects which are older.
    """
    if debug:
        print 'doing garbage collection'

    for roa in models.ROA.objects.filter(timestamp__lt=ts):
        if debug:
            sys.stderr.write('removing %s\n' % roa.uri)
        trydelete(roa.prefixes.all())
        roa.delete()

    for cert in models.Cert.objects.filter(timestamp__lt=ts):
        if debug:
            sys.stderr.write('removing %s\n' % cert.uri)
        trydelete(cert.asns.all())
        trydelete(cert.addresses.all())
        cert.delete()

    for gbr in models.Ghostbuster.objects.filter(timestamp__lt=ts):
        if debug:
            sys.stderr.write('removing %s\n' % gbr.uri)
        gbr.delete()

def process_cache(root, xml_file):
    start = time.time()

    # the timestamp from the first element in the rcynic xml file is saved
    # to perform garbage collection of stale db entries
    ts = 0

    dispatch = {
      'rcynic_certificate': process_rescert,
      'rcynic_roa'        : process_roa,
      'rcynic_ghostbuster': process_ghostbuster
    }

    # loop over all rcynic objects and dispatch based on the returned
    # rcynic_object subclass
    for obj in rcynic_xml_iterator(root, xml_file):
        r = dispatch[obj.__class__.__name__](obj)
        if not ts:
            ts = r.timestamp
    garbage_collect(ts)

    if debug:
        stop = time.time()
        sys.stdout.write('elapsed time %d seconds.\n' % (stop - start))

def process_labels(xml_file):
    if debug:
        sys.stderr.write('updating labels...\n')

    with TransactionManager():
        kinds = { 'good': 0, 'warn': 1, 'bad': 2 }
        for label, kind, desc in label_iterator(xml_file):
            if debug:
                sys.stderr.write('label=%s kind=%s desc=%s\n' % (label, kind, desc))
            if kind:
                q = models.ValidationStatus.objects.filter(label=label)
                if not q:
                    obj = models.ValidationStatus(label=label)
                else:
                    obj = q[0]

                obj.kind = kinds[kind]
                obj.status = desc
                obj.save()

if __name__ == '__main__':
    import optparse

    parser = optparse.OptionParser()
    parser.add_option("-d", "--debug", action="store_true",
            help="enable debugging message")
    parser.add_option("-f", "--file", dest="logfile",
            help="specify the rcynic XML file to parse [default: %default]",
            default=default_logfile)
    parser.add_option("-r", "--root",
            help="specify the chroot directory for the rcynic jail [default: %default]",
            metavar="DIR", default=default_root)
    options, args = parser.parse_args(sys.argv)
    if options.debug:
        debug = True

    process_labels(options.logfile)
    process_cache(options.root, options.logfile)

# vim:sw=4 ts=8
