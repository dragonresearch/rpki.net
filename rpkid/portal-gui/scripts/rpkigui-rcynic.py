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

import os, sys, time
os.environ['DJANGO_SETTINGS_MODULE'] = 'rpki.gui.settings'

from rpki.gui.cacheview import models
from rpki.rcynic import rcynic_xml_iterator
from rpki.sundial import datetime
import vobject

debug = True

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

    inst.ok = obj.ok
    inst.status = obj.status
    inst.timestamp = datetime.fromXMLtime(obj.timestamp).to_sql()

    mtime = os.stat(obj.filename)[8]
    if mtime != inst.mtime:
        inst.mtime = mtime
        inst.not_before = obj.notBefore.to_sql()
        inst.not_after = obj.notAfter.to_sql()

        # look up signing cert
        q = models.Cert.objects.filter(keyid=obj.aki)
        if q:
            inst.issuer = q[0]
        else:
            sys.stderr.write('warning: unable to find signing cert with ski=%s (%s)\n' % (obj.aki, obj.issuer))

        return True, inst
    elif debug:
        print 'object is unchanged'

    inst.save()

    return False, inst

def process_rescert(cert):
    """
    Process a RPKI resource certificate.
    """

    refresh, obj = process_object(cert, models.Cert)

    if refresh:
        obj.name = cert.subject
        obj.keyid = cert.ski
        obj.save()

        # resources can change when a cert is updated
        obj.asns.clear()
        obj.addresses.clear()

        for asr in cert.resources.asn:
            if debug:
                sys.stderr.write('processing %s\n' % asr)

            q = models.ASRange.objects.filter(min=asr.min, max=asr.max)
            if not q:
                obj.asns.create(min=asr.min, max=asr.max)
            else:
                obj.asns.add(q[0])

        for family, addrset in (4, cert.resources.v4), (6, cert.resources.v6):
            for rng in addrset:
                if debug:
                    sys.stderr.write('processing %s\n' % rng)

                minaddr = str(rng.min)
                maxaddr = str(rng.max)
                q = models.AddressRange.objects.filter(family=family, min=minaddr, max=maxaddr)
                if not q:
                    obj.addresses.create(family=family, min=minaddr, max=maxaddr)
                else:
                    obj.addresses.add(q[0])

    if debug:
        print 'finished processing rescert at %s' % cert.uri

    return obj

def process_ghostbuster(gbr):
    refresh, obj = process_object(gbr, models.Ghostbuster)

    if True:
    #if refresh:
        vcard = vobject.readOne(gbr.vcard)
        if debug:
            vcard.prettyPrint()
        if hasattr(vcard, 'fn'):
            obj.full_name = vcard.fn.value
        if hasattr(vcard, 'email'):
            obj.email_address = vcard.email.value
        if hasattr(vcard, 'tel'):
            obj.telephone = vcard.tel.value
        if hasattr(vcard, 'org'):
            obj.organization = vcard.org.value[0]
        obj.save()

fam_map = { 'roa_prefix_set_ipv6': 6, 'roa_prefix_set_ipv4': 4 }

def process_roa(roa):
    refresh, obj = process_object(roa, models.ROA)

    if refresh:
        obj.asid = roa.asID
        obj.save()
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
    else:
        obj.save()

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
        trydelete(roa.prefixes)
        roa.delete()

    for cert in models.Cert.objects.filter(timestamp__lt=ts):
        trydelete(cert.asns)
        trydelete(cert.addresses)
        cert.delete()

    for gbr in models.Ghostbuster.objects.filter(timestamp__lt=ts):
        gbr.delete()

dispatch = {
  'rcynic_certificate': process_rescert,
  'rcynic_roa'        : process_roa,
  'rcynic_ghostbuster': process_ghostbuster
}

def process_cache(root='/var/rcynic/data', xml_file='/var/rcynic/data/rcynic.xml'):
    start = time.time()

    first = True
    ts = datetime.now()
    for obj in rcynic_xml_iterator(root, xml_file):
        r = dispatch[obj.__class__.__name__](obj)
        if first:
            first = False
            ts = r.timestamp
    garbage_collect(ts)

    if debug:
        stop = time.time()
        sys.stdout.write('elapsed time %d seconds.\n' % (stop - start))

if __name__ == '__main__':
    process_cache()

# vim:sw=4 ts=8
