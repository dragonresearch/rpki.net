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
from rpki.fields import BlobField, CertificateField, SundialField
from lxml.etree import Element, SubElement, tostring as ElementToString

import os
import logging
import rpki.exceptions
import rpki.relaxng

logger = logging.getLogger(__name__)


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
  snapshot = models.TextField(blank = True)
  hash = models.CharField(max_length = 64, blank = True)

  ## @var keep_all_rrdp_files
  # Debugging flag to prevent expiration of old RRDP files.
  # This simplifies debugging delta code.  Need for this
  # may go away once RRDP is fully integrated into rcynic.
  keep_all_rrdp_files = False

  def new_delta(self, expires):
    """
    Construct a new delta associated with this session.
    """

    delta = Delta(session = self,
                  serial = self.serial + 1,
                  expires = expires)
    delta.elt = Element(rrdp_tag_delta,
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


  def generate_snapshot(self):
    """
    Generate an XML snapshot of this session.
    """

    xml = Element(rrdp_tag_snapshot, nsmap = rrdp_nsmap,
                  version = rrdp_version,
                  session_id = self.uuid,
                  serial = str(self.serial))
    xml.text = "\n"
    for obj in self.publishedobject_set.all():
      DERSubElement(xml, rrdp_tag_publish,
                    der = obj.der,
                    uri = obj.uri)
    rpki.relaxng.rrdp.assertValid(xml)
    self.snapshot = ElementToString(xml, pretty_print = True)
    self.hash = rpki.x509.sha256(self.snapshot).encode("hex")
    self.save()


  @property
  def snapshot_fn(self):
    return "%s/snapshot/%s.xml" % (self.uuid, self.serial)


  @property
  def notification_fn(self):
    return "notify.xml"


  @staticmethod
  def _write_rrdp_file(fn, text, rrdp_publication_base, overwrite = False):
    if overwrite or not os.path.exists(os.path.join(rrdp_publication_base, fn)):
      tn = os.path.join(rrdp_publication_base, fn + ".%s.tmp" % os.getpid())
      if not os.path.isdir(os.path.dirname(tn)):
        os.makedirs(os.path.dirname(tn))
      with open(tn, "w") as f:
        f.write(text)
      os.rename(tn, os.path.join(rrdp_publication_base, fn))


  @staticmethod
  def _rrdp_filename_to_uri(fn, rrdp_uri_base):
    return "%s/%s" % (rrdp_uri_base.rstrip("/"), fn)


  def _generate_update_xml(self, rrdp_uri_base):
    xml = Element(rrdp_tag_notification, nsmap = rrdp_nsmap,
                  version = rrdp_version,
                  session_id = self.uuid,
                  serial = str(self.serial))
    SubElement(xml, rrdp_tag_snapshot,
               uri = self._rrdp_filename_to_uri(self.snapshot_fn, rrdp_uri_base),
               hash = self.hash)
    for delta in self.delta_set.all():
      SubElement(xml, rrdp_tag_delta,
                 uri = self._rrdp_filename_to_uri(delta.fn, rrdp_uri_base),
                 hash =  delta.hash,
                 serial = str(delta.serial))
    rpki.relaxng.rrdp.assertValid(xml)
    return ElementToString(xml, pretty_print = True)


  def synchronize_rrdp_files(self, rrdp_publication_base, rrdp_uri_base):
    """
    Write current RRDP files to disk, clean up old files and directories.
    """

    current_filenames = set()

    for delta in self.delta_set.all():
      self._write_rrdp_file(delta.fn, delta.xml, rrdp_publication_base)
      current_filenames.add(delta.fn)

    self._write_rrdp_file(self.snapshot_fn, self.snapshot, rrdp_publication_base)
    current_filenames.add(self.snapshot_fn)

    self._write_rrdp_file(self.notification_fn, self._generate_update_xml(rrdp_uri_base),
                          rrdp_publication_base, overwrite = True)
    current_filenames.add(self.notification_fn)

    if not self.keep_all_rrdp_files:
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
  xml = models.TextField()
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


  def activate(self):
    rpki.relaxng.rrdp.assertValid(self.elt)
    self.xml = ElementToString(self.elt, pretty_print = True)
    self.hash = rpki.x509.sha256(self.xml).encode("hex")
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
    se = DERSubElement(self.elt, rrdp_tag_publish, der = der, uri = uri)
    if obj_hash is not None:
      se.set("hash", obj_hash)
    rpki.relaxng.rrdp.assertValid(self.elt)


  def withdraw(self, client, uri, obj_hash):
    obj = client.publishedobject_set.get(session = self.session, uri = uri)
    if obj.hash != obj_hash:
      raise rpki.exceptions.DifferentObjectAtURI("Found different object at %s (old %s, new %s)" % (uri, obj.hash, obj_hash))
    logger.debug("Withdrawing %s", uri)
    obj.delete()
    SubElement(self.elt, rrdp_tag_withdraw, uri = uri, hash = obj_hash).tail = "\n"
    rpki.relaxng.rrdp.assertValid(self.elt)


  def update_rsync_files(self, publication_base):
    from errno import ENOENT
    min_path_len = len(publication_base.rstrip("/"))
    for pdu in self.elt:
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
    del self.elt


class PublishedObject(models.Model):
  uri = models.CharField(max_length = 255)
  der = BlobField()
  hash = models.CharField(max_length = 64)
  client = models.ForeignKey(Client)
  session = models.ForeignKey(Session)

  class Meta:                           # pylint: disable=C1001,W0232
    unique_together = (("session", "hash"),
                       ("session", "uri"))
