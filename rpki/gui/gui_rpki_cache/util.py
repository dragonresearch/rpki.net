# Copyright (C) 2011  SPARTA, Inc. dba Cobham
# Copyright (C) 2012, 2013, 2016  SPARTA, Inc. a Parsons Company
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

__version__ = '$Id: util.py 6335 2016-03-29 03:09:13Z sra $'

import logging
import time
import vobject
from socket import getfqdn
from cStringIO import StringIO

if __name__ == '__main__':
    import os
    logging.basicConfig(level=logging.DEBUG)
    os.environ.update(DJANGO_SETTINGS_MODULE='rpki.django_settings.gui')
    import django
    django.setup()

import os.path

logger = logging.getLogger(__name__)

from django.db import transaction
import django.db.models

import rpki
import rpki.resource_set
import rpki.left_right
import rpki.gui.app.timestamp
from rpki.gui.app.models import Conf, Alert
from rpki.gui.gui_rpki_cache import models
from rpki.irdb.zookeeper import Zookeeper

from lxml.etree import Element, SubElement


def process_certificate(auth, obj):
    cert = models.Cert.objects.filter(ski=obj.ski).first()
    if cert:
        logger.debug('cache hit for CA cert uri=%s ski=%s' % (cert.uri, cert.ski))
        return cert # cache hit

    logger.debug('parsing cert at %s' % (obj.uri,))

    """Process Resource CA Certificates"""
    x509 = rpki.POW.X509.derRead(obj.der)

    # ensure this is a resource CA Certificate (ignore Router certs)
    bc = x509.getBasicConstraints()
    is_ca = bc is not None and bc[0]
    if not is_ca:
	return

    # locate the parent certificate
    if obj.aki and obj.aki != obj.ski:
        try:
            issuer = models.Cert.objects.get(ski=obj.aki)
        except models.Cert.DoesNotExist:
            # process parent cert first
            issuer = process_certificate(auth, rpki.rcynicdb.models.RPKIObject.objects.get(ski=obj.aki, authenticated=auth))
    else:
        issuer = None # root

    asns, v4, v6 = x509.getRFC3779()

    cert = models.Cert.objects.create(
	uri=obj.uri,
	ski=obj.ski,
        not_before=x509.getNotBefore(),
        not_after=x509.getNotAfter(),
        issuer=issuer
    )

    if issuer is None:
	cert.issuer = cert  # self-signed
	cert.save()

    if asns == 'inherit':
        cert.asns.add(issuer.asns.all())
    elif asns:
	for asmin, asmax in asns:
	    asr, _ = models.ASRange.objects.get_or_create(min=asmin, max=asmax)
	    cert.asns.add(asr)

    if v4 == 'inherit':
        cert.addresses.add(issuer.addresses.all())
    elif v4:
	for v4min, v4max in v4:
	    pfx, _ = models.AddressRange.objects.get_or_create(prefix_min=v4min, prefix_max=v4max)
	    cert.addresses.add(pfx)

    if v6 == 'inherit':
        cert.addresses_v6.add(issuer.addresses_v6.all())
    elif v6:
	for v6min, v6max in v6:
	    pfx, _ = models.AddressRangeV6.objects.get_or_create(prefix_min=v6min, prefix_max=v6max)
	    cert.addresses_v6.add(pfx)

    return cert

def process_roa(auth, obj):
    logger.debug('parsing roa at %s' % (obj.uri,))

    r = rpki.POW.ROA.derRead(obj.der)
    r.verify() # required in order to extract asID
    ee = r.certs()[0] # rpki.POW.X509
    aki = ee.getAKI().encode('hex')

    logger.debug('looking for ca cert with ski=%s' % (aki,))

    # Locate the Resource CA cert that issued the EE that signed this ROA
    issuer = models.Cert.objects.get(ski=aki)

    roa = models.ROA.objects.create(
	    uri=obj.uri,
	    asid=r.getASID(),
	    not_before=ee.getNotBefore(),
	    not_after=ee.getNotAfter(),
	    issuer=issuer)

    prefixes = r.getPrefixes()
    if prefixes[0]: # v4
	for p in prefixes[0]:
	    v = rpki.resource_set.roa_prefix_ipv4(*p)
	    roapfx, _ = models.ROAPrefixV4.objects.get_or_create(prefix_min=v.min(), prefix_max=v.max(), max_length=v.max_prefixlen)
	    roa.prefixes.add(roapfx)
    if prefixes[1]: # v6
	for p in prefixes[1]:
	    v = rpki.resource_set.roa_prefix_ipv6(*p)
	    roapfx, _ = models.ROAPrefixV6.objects.get_or_create(prefix_min=v.min(), prefix_max=v.max(), max_length=v.max_prefixlen)
	    roa.prefixes_v6.add(roapfx)

    return roa

def process_ghostbuster(auth, obj):
    logger.debug('parsing ghostbuster at %s' % (obj.uri,))
    g = rpki.POW.CMS.derRead(obj.der)
    ee = g.certs()[0] # rpki.POW.X509
    aki = ee.getAKI().encode('hex')
    vcard = vobject.readOne(g.verify())

    # Locate the Resource CA cert that issued the EE that signed this ROA
    issuer = models.Cert.objects.get(ski=aki)

    gbr = models.Ghostbuster.objects.create(
	    uri=obj.uri,
	    issuer=issuer, 
	    not_before=ee.getNotBefore(),
	    not_after=ee.getNotAfter(),
	    full_name = vcard.fn.value if hasattr(vcard, 'fn') else None,
	    email_address = vcard.email.value if hasattr(vcard, 'email') else None,
	    telephone = vcard.tel.value if hasattr(vcard, 'tel') else None,
	    organization = vcard.org.value[0] if hasattr(vcard, 'org') else None
	    )

    return gbr

@transaction.atomic
def process_cache():
    logger.info('processing rpki cache')

    # foreign key constraints should cause all other objects to be removed
    models.Cert.objects.all().delete()

    # certs must be processed first in order to build proper foreign keys for roa/gbr
    dispatch = {
	    '.cer': process_certificate,
	    '.gbr': process_ghostbuster,
	    '.roa': process_roa
	    }

    auth = rpki.rcynicdb.models.Authenticated.objects.order_by('started').first()

    # Resource CA Certs are processed first in order to attach ROAs and Ghostbusters
    for suffix in ('.cer', '.roa', '.gbr'):
        cb = dispatch[suffix]

        for rpkiobj in auth.rpkiobject_set.filter(uri__endswith=suffix):
            cb(auth, rpkiobj)

    # Garbage collection - remove M2M relations for certs/ROAs which no longer exist
    models.ASRange.objects.annotate(num_certs=django.db.models.Count('certs')).filter(num_certs=0).delete()
    models.AddressRange.objects.annotate(num_certs=django.db.models.Count('certs')).filter(num_certs=0).delete()
    models.AddressRangeV6.objects.annotate(num_certs=django.db.models.Count('certs')).filter(num_certs=0).delete()

    models.ROAPrefixV4.objects.annotate(num_roas=django.db.models.Count('roas')).filter(num_roas=0).delete()
    models.ROAPrefixV6.objects.annotate(num_roas=django.db.models.Count('roas')).filter(num_roas=0).delete()


# dict mapping resource handle to list of published objects, use for notifying objects which have become invalid
uris = {}
model_map = { '.cer': models.Cert, '.roa': models.ROA, '.gbr': models.Ghostbuster }

def fetch_published_objects():
    """Query rpkid for all objects published by local users, and look up the
    current validation status of each object.  The validation status is used
    later to send alerts for objects which have transitioned to invalid.
    """
    logger.info('querying for published objects')

    handles = [conf.handle for conf in Conf.objects.all()]
    q_msg = Element(rpki.left_right.tag_msg, nsmap = rpki.left_right.nsmap,
                    type = "query", version = rpki.left_right.version)
    for h in handles:
        SubElement(q_msg, rpki.left_right.tag_list_published_objects, tenant_handle=h, tag=h)
    try:
        z = Zookeeper()
        r_msg = z.call_rpkid(q_msg)
    except Exception as err:
        logger.error('Unable to connect to rpkid to fetch list of published objects')
        logger.exception(err)
        # Should be safe to continue processing the rcynic cache, we just don't do any notifications
        return

    for r_pdu in r_msg:
        if r_pdu.tag == rpki.left_right.tag_list_published_objects:
            # Look up the object in the rcynic cache
            uri = r_pdu.get('uri')
            ext = os.path.splitext(uri)[1]
	    if ext in model_map:
		model = model_map[ext]
		handle = r_pdu.get('tenant_handle')

		if model.objects.filter(uri=uri).exists():
		    v = uris.setdefault(handle, [])
		    v.append(uri)
		    logger.debug('adding %s', uri)
		#else:
		    # this object is not in the cache.  it was either published
		    # recently, or disappared previously.  if it disappeared
		    # previously, it has already been alerted.  in either case, we
		    # omit the uri from the list since we are interested only in
		    # objects which were valid and are no longer valid
	    else:
		logger.debug('skipping object ext=%s uri=%s' % (ext, uri))

        elif r_pdu.tag == rpki.left_right.tag_report_error:
            logging.error('rpkid reported an error: %s', r_pdu.get("error_code"))


def notify_invalid():
    """Send email alerts to the addresses registered in ghostbuster records for
    any invalid objects that were published by users of this system.
    """

    logger.info('sending notifications for invalid objects')

    for handle, published_objects in uris.iteritems():
        missing = []
        for u in published_objects:
            ext = os.path.splitext(u)[1]
            model = model_map[ext]
            if not model.objects.filter(uri=u).exists():
                missing.append(u)

        if missing:
            conf = Conf.objects.get(handle)

            msg = StringIO()
            msg.write('This is an alert about problems with objects published by '
                      'the resource handle %s.\n\n' % handle)

            msg.write('The following objects were previously valid, but are '
                      'now invalid:\n')

            for u in missing:
                msg.write('\n')
                msg.write(u)
                msg.write('\n')

            msg.write("""--
You are receiving this email because your address is published in a Ghostbuster
record, or is the default email address for this resource holder account on
%s.""" % getfqdn())

            from_email = 'root@' + getfqdn()
            subj = 'invalid RPKI object alert for resource handle %s' % conf.handle
            conf.send_alert(subj, msg.getvalue(), from_email, severity=Alert.ERROR)


def update_cache():
    """Cache information from the current rcynicdb for display by the gui"""

    start = time.time()
    fetch_published_objects()
    process_cache()
    notify_invalid()

    rpki.gui.app.timestamp.update('rcynic_import')

    stop = time.time()
    logger.info('elapsed time %d seconds.', (stop - start))


if __name__ == '__main__':
    process_cache()
