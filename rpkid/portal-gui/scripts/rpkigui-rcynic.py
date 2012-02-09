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

__version__ = '$Id$'

default_logfile = '/var/rcynic/data/summary.xml'
default_root = '/var/rcynic/data'

import time
import vobject
import logging

from django.db import transaction
import django.db.models

import rpki
import rpki.gui.app.timestamp
from rpki.gui.cacheview import models
from rpki.rcynic import rcynic_xml_iterator, label_iterator
from rpki.sundial import datetime

logger = logging.getLogger(__name__)


class rcynic_object(object):
    def __call__(self, vs):
        """Do initial processing on a rcynic_object instance."""
        logger.debug('processing %s at %s' % (vs.file_class.__name__, vs.uri))

        # rcynic will generation <validation_status/> elements for objects
        # listed in the manifest but not found on disk
        if os.path.exists(vs.filename):
            q = self.model_class.objects.filter(uri=vs.uri)
            if not q:
                logger.debug('creating new db instance')
                inst = self.model_class(uri=vs.uri)
            else:
                inst = q[0]

            # determine if the object is changed/new
            mtime = os.stat(vs.filename)[8]
            if mtime != inst.mtime:
                inst.mtime = mtime
                try:
                    obj = vs.obj  # causes object to be lazily loaded
                except rpki.POW._der.DerError, e:
                    logger.warning('Caught %s while processing %s: %s' % (type(e), vs.filename, e))
                    return True

                inst.not_before = obj.notBefore.to_sql()
                inst.not_after = obj.notAfter.to_sql()
                logger.debug('name=%s ski=%s' % (obj.subject, obj.ski))
                inst.name = obj.subject
                inst.keyid = obj.ski

                # look up signing cert
                if obj.issuer == obj.subject:
                    # self-signed cert (TA)
                    inst.cert = inst
                else:
                    q = models.Cert.objects.filter(keyid=obj.aki, name=obj.issuer)
                    if q:
                        inst.issuer = q[0]
                    else:
                        logger.warning('unable to find signing cert with ski=%s (%s)' % (obj.aki, obj.issuer))
                        return None

                self.callback(obj, inst)
            else:
                logger.debug('object is unchanged')

            # save required to create new ValidationStatus object refering to
            # it
            inst.save()
            inst.statuses.create(generation=models.generations_dict[vs.generation] if vs.generation else None,
                    timestamp=datetime.fromXMLtime(vs.timestamp).to_sql(),
                    status=models.ValidationLabel.objects.get(label=vs.status))

            return inst
        else:
            logger.warning('file is missing: %s' % vs.filename)

        return True


class rcynic_cert(rcynic_object):
    model_class = models.Cert

    def callback(self, cert, obj):
        """
        Process a RPKI resource certificate.
        """

        obj.sia = cert.sia_directory_uri
        obj.save()

        # resources can change when a cert is updated
        obj.asns.clear()
        obj.addresses.clear()

        for asr in cert.resources.asn:
            logger.debug('processing %s' % asr)

            attrs = {'min': asr.min, 'max': asr.max}
            q = models.ASRange.objects.filter(**attrs)
            if not q:
                obj.asns.create(**attrs)
            else:
                obj.asns.add(q[0])

        for cls, addr_obj, addrset in (models.AddressRange, obj.addresses, cert.resources.v4), (models.AddressRangeV6, obj.addresses_v6, cert.resources.v6):
            for rng in addrset:
                logger.debug('processing %s' % rng)

                attrs = {'prefix_min': rng.min, 'prefix_max': rng.max}
                q = cls.objects.filter(**attrs)
                if not q:
                    addr_obj.create(**attrs)
                else:
                    addr_obj.add(q[0])

        logger.debug('finished processing rescert at %s' % cert.uri)


class rcynic_roa(rcynic_object):
    model_class = models.ROA

    def callback(self, roa, obj):
        obj.asid = roa.asID
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


class rcynic_gbr(rcynic_object):
    model_class = models.Ghostbuster

    def callback(self, gbr, obj):
        vcard = vobject.readOne(gbr.vcard)
        logger.debug(vcard.prettyPrint())
        obj.full_name = vcard.fn.value if hasattr(vcard, 'fn') else None
        obj.email_address = vcard.email.value if hasattr(vcard, 'email') else None
        obj.telephone = vcard.tel.value if hasattr(vcard, 'tel') else None
        obj.organization = vcard.org.value[0] if hasattr(vcard, 'org') else None


def process_cache(root, xml_file):
    start = time.time()

    dispatch = {
      'rcynic_certificate': rcynic_cert(),
      'rcynic_roa': rcynic_roa(),
      'rcynic_ghostbuster': rcynic_gbr()
    }

    # remove all existing ValidationStatus_* entries
    logger.info('removing existing validation status')
    models.ValidationStatus_Cert.objects.all().delete()
    models.ValidationStatus_ROA.objects.all().delete()
    models.ValidationStatus_Ghostbuster.objects.all().delete()

    logger.info('updating validation status')
    elts = rcynic_xml_iterator(root, xml_file)
    for vs in elts:
        with transaction.commit_on_success():
            dispatch[vs.file_class.__name__](vs)

    # garbage collection
    # remove all objects which have no ValidationStatus references, which
    # means they did not appear in the last XML output
    logger.info('performing garbage collection')

    # trying to .delete() the querysets directly results in a "too many sql
    # variables" exception
    for qs in (models.Cert.objects.annotate(num_statuses=django.db.models.Count('statuses')).filter(num_statuses=0),
            models.Ghostbuster.objects.annotate(num_statuses=django.db.models.Count('statuses')).filter(num_statuses=0),
            models.ROA.objects.annotate(num_statuses=django.db.models.Count('statuses')).filter(num_statuses=0)):
        for e in qs:
            e.delete()

    stop = time.time()
    logger.info('elapsed time %d seconds.' % (stop - start))


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


if __name__ == '__main__':
    import optparse

    parser = optparse.OptionParser()
    parser.add_option("-l", "--level", dest="log_level", default='INFO',
                      help="specify the logging level [default: %default]")
    parser.add_option("-f", "--file", dest="logfile",
                      help="specify the rcynic XML file to parse [default: %default]",
                      default=default_logfile)
    parser.add_option("-r", "--root",
                      help="specify the chroot directory for the rcynic jail [default: %default]",
                      metavar="DIR", default=default_root)
    options, args = parser.parse_args(sys.argv)

    v = getattr(logging, options.log_level.upper())
    logger.setLevel(v)
    logging.basicConfig()
    logger.info('log level set to %s' % logging.getLevelName(v))

    process_labels(options.logfile)
    process_cache(options.root, options.logfile)

    rpki.gui.app.timestamp.update('rcynic_import')

    logging.shutdown()
