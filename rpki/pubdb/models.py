# $Id$
#
# Copyright (C) 2014 Dragon Research Labs ("DRL")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL DRL BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
Django ORM models for pubd.
"""

from __future__ import unicode_literals
from django.db import models
from rpki.fields import CertificateField, SundialField
from lxml.etree import Element, SubElement, ElementTree, xmlfile as XMLFile

import os
import logging
import rpki.exceptions
import rpki.relaxng
import rpki.x509
import rpki.POW

logger = logging.getLogger(__name__)


# pylint: disable=W5101

# Some of this probably ought to move into a rpki.rrdp module.

rrdp_xmlns   = rpki.relaxng.rrdp.xmlns
rrdp_nsmap   = rpki.relaxng.rrdp.nsmap
rrdp_version = "1"

rrdp_tag_delta        = rrdp_xmlns + "delta"
rrdp_tag_notification = rrdp_xmlns + "notification"
rrdp_tag_publish      = rrdp_xmlns + "publish"
rrdp_tag_snapshot     = rrdp_xmlns + "snapshot"
rrdp_tag_withdraw     = rrdp_xmlns + "withdraw"


# This would probably be useful to more than just this module, not
# sure quite where to put it at the moment.

def DERSubElement(elt, name, der, attrib = None, **kwargs):
    """
    Convenience wrapper around SubElement for use with Base64 text.
    """

    se = SubElement(elt, name, attrib, **kwargs)
    se.text = rpki.x509.base64_with_linebreaks(der)
    se.tail = "\n"
    return se


def sha256_file(f):
    """
    Read data from a file-like object, return hex-encoded sha256 hash.
    """

    h = rpki.POW.Digest(rpki.POW.SHA256_DIGEST)
    while True:
        x = f.read(8192)
        if len(x) == 0:
            return h.digest().encode("hex")
        h.update(x)


class Client(models.Model):
    client_handle = models.CharField(unique = True, max_length = 255)
    base_uri = models.TextField()
    bpki_cert = CertificateField()
    bpki_glue = CertificateField(null = True)
    last_cms_timestamp = SundialField(blank = True, null = True)


    def check_allowed_uri(self, uri):
        """
        Make sure that a target URI is within this client's allowed URI space.
        """

        if not uri.startswith(self.base_uri):
            raise rpki.exceptions.ForbiddenURI


class Session(models.Model):
    uuid = models.CharField(unique = True, max_length=36)
    serial = models.BigIntegerField()


    def new_delta(self, expires):
        """
        Construct a new delta associated with this session.
        """

        # pylint: disable=W0201

        delta = Delta(session = self,
                      serial = self.serial + 1,
                      expires = expires)
        delta.xml = Element(rrdp_tag_delta,
                            nsmap = rrdp_nsmap,
                            version = rrdp_version,
                            session_id = self.uuid,
                            serial = str(delta.serial))
        return delta


    def expire_deltas(self):
        """
        Delete deltas whose expiration date has passed.
        """

        self.delta_set.filter(expires__lt = rpki.sundial.now()).delete()


    @property
    def snapshot_fn(self):
        return "%s/snapshot/%s.xml" % (self.uuid, self.serial)


    @property
    def notification_fn(self):
        return "notify.xml"


    @staticmethod
    def _rrdp_filename_to_uri(fn, rrdp_base_uri):
        return "%s/%s" % (rrdp_base_uri.rstrip("/"), fn)


    def write_snapshot_file(self, rrdp_publication_base):
        fn = os.path.join(rrdp_publication_base, self.snapshot_fn)
        tn = fn + ".%s.tmp" % os.getpid()
        dn = os.path.dirname(fn)
        if not os.path.isdir(dn):
            os.makedirs(dn)
        with open(tn, "wb+") as f:
            with XMLFile(f) as xf:
                with xf.element(rrdp_tag_snapshot, nsmap = rrdp_nsmap,
                                version = rrdp_version, session_id = self.uuid, serial = str(self.serial)):
                    xf.write("\n")
                    for obj in self.publishedobject_set.all():
                        e = Element(rrdp_tag_publish, nsmap = rrdp_nsmap, uri = obj.uri)
                        e.text = rpki.x509.base64_with_linebreaks(obj.der)
                        xf.write(e, pretty_print = True)
            f.seek(0)
            h = sha256_file(f)
        os.rename(tn, fn)
        return h


    def write_notification_xml(self, rrdp_base_uri, snapshot_hash, rrdp_publication_base):
        xml = Element(rrdp_tag_notification, nsmap = rrdp_nsmap,
                      version = rrdp_version,
                      session_id = self.uuid,
                      serial = str(self.serial))
        SubElement(xml, rrdp_tag_snapshot,
                   uri = self._rrdp_filename_to_uri(self.snapshot_fn, rrdp_base_uri),
                   hash = snapshot_hash)
        for delta in self.delta_set.all():
            SubElement(xml, rrdp_tag_delta,
                       uri = self._rrdp_filename_to_uri(delta.fn, rrdp_base_uri),
                       hash =  delta.hash,
                       serial = str(delta.serial))
        rpki.relaxng.rrdp.assertValid(xml)
        fn = os.path.join(rrdp_publication_base, self.notification_fn)
        tn = fn + ".%s.tmp" % os.getpid()
        ElementTree(xml).write(file = tn, pretty_print = True)
        os.rename(tn, fn)


    def synchronize_rrdp_files(self, rrdp_publication_base, rrdp_base_uri):
        """
        Write current RRDP files to disk, clean up old files and directories.
        """

        if os.path.isdir(rrdp_publication_base):
            current_filenames = set(fn for fn in os.listdir(rrdp_publication_base)
                                    if fn.endswith(".cer") or fn.endswith(".tal"))
        else:
            current_filenames = set()

        snapshot_hash = self.write_snapshot_file(rrdp_publication_base)
        current_filenames.add(self.snapshot_fn)

        for delta in self.delta_set.all():
            current_filenames.add(delta.fn)

        self.write_notification_xml(rrdp_base_uri, snapshot_hash, rrdp_publication_base),
        current_filenames.add(self.notification_fn)

        for root, dirs, files in os.walk(rrdp_publication_base, topdown = False):
            for fn in files:
                fn = os.path.join(root, fn)
                if fn[len(rrdp_publication_base):].lstrip("/") not in current_filenames:
                    os.remove(fn)
            for dn in dirs:
                try:
                    os.rmdir(os.path.join(root, dn))
                except OSError:
                    pass


class Delta(models.Model):
    serial = models.BigIntegerField()
    hash = models.CharField(max_length = 64)
    expires = SundialField()
    session = models.ForeignKey(Session)


    @staticmethod
    def _uri_to_filename(uri, publication_base):
        if not uri.startswith("rsync://"):
            raise rpki.exceptions.BadURISyntax(uri)
        path = uri.split("/")[4:]
        path.insert(0, publication_base.rstrip("/"))
        filename = "/".join(path)
        if "/../" in filename or filename.endswith("/.."):
            raise rpki.exceptions.BadURISyntax(filename)
        return filename


    @property
    def fn(self):
        return "%s/deltas/%s.xml" % (self.session.uuid, self.serial)


    def activate(self, rrdp_publication_base):
        rpki.relaxng.rrdp.assertValid(self.xml)
        fn = os.path.join(rrdp_publication_base, self.fn)
        tn = fn + ".%s.tmp" % os.getpid()
        dn = os.path.dirname(fn)
        if not os.path.isdir(dn):
            os.makedirs(dn)
        with open(tn, "wb+") as f:
            ElementTree(self.xml).write(file = f, pretty_print = True)
            f.flush()
            f.seek(0)
            self.hash = sha256_file(f)
        os.rename(tn, fn)
        self.save()
        self.session.serial += 1
        self.session.save()


    def publish(self, client, der, uri, obj_hash):
        try:
            obj = client.publishedobject_set.get(session = self.session, uri = uri)
            if obj.hash == obj_hash:
                obj.delete()
            elif obj_hash is None:
                raise rpki.exceptions.ExistingObjectAtURI("Object already published at %s" % uri)
            else:
                raise rpki.exceptions.DifferentObjectAtURI("Found different object at %s (old %s, new %s)" % (uri, obj.hash, obj_hash))
        except rpki.pubdb.models.PublishedObject.DoesNotExist:
            pass
        logger.debug("Publishing %s", uri)
        PublishedObject.objects.create(session = self.session, client = client, der = der, uri = uri,
                                       hash = rpki.x509.sha256(der).encode("hex"))
        se = DERSubElement(self.xml, rrdp_tag_publish, der = der, uri = uri)
        if obj_hash is not None:
            se.set("hash", obj_hash)
        rpki.relaxng.rrdp.assertValid(self.xml)


    def withdraw(self, client, uri, obj_hash):
        try:
            obj = client.publishedobject_set.get(session = self.session, uri = uri)
        except rpki.pubdb.models.PublishedObject.DoesNotExist:
            raise rpki.exceptions.NoObjectAtURI("No published object found at %s" % uri)
        if obj.hash != obj_hash:
            raise rpki.exceptions.DifferentObjectAtURI("Found different object at %s (old %s, new %s)" % (uri, obj.hash, obj_hash))
        logger.debug("Withdrawing %s", uri)
        obj.delete()
        SubElement(self.xml, rrdp_tag_withdraw, uri = uri, hash = obj_hash).tail = "\n"
        rpki.relaxng.rrdp.assertValid(self.xml)


    def update_rsync_files(self, publication_base):
        from errno import ENOENT
        min_path_len = len(publication_base.rstrip("/"))
        for pdu in self.xml:
            assert pdu.tag in (rrdp_tag_publish, rrdp_tag_withdraw)
            fn = self._uri_to_filename(pdu.get("uri"), publication_base)
            if pdu.tag == rrdp_tag_publish:
                tn = fn + ".tmp"
                dn = os.path.dirname(fn)
                if not os.path.isdir(dn):
                    os.makedirs(dn)
                with open(tn, "wb") as f:
                    f.write(pdu.text.decode("base64"))
                os.rename(tn, fn)
            else:
                try:
                    os.remove(fn)
                except OSError, e:
                    if e.errno != ENOENT:
                        raise
                dn = os.path.dirname(fn)
                while len(dn) > min_path_len:
                    try:
                        os.rmdir(dn)
                    except OSError:
                        break
                    else:
                        dn = os.path.dirname(dn)
        del self.xml


class PublishedObject(models.Model):
    uri = models.CharField(max_length = 255)
    der = models.BinaryField()
    hash = models.CharField(max_length = 64)
    client = models.ForeignKey(Client)
    session = models.ForeignKey(Session)

    class Meta:
        unique_together = (("session", "hash"),
                           ("session", "uri"))
