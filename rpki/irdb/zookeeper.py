# $Id$
#
# Copyright (C) 2013--2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2009--2012  Internet Systems Consortium ("ISC")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL AND ISC DISCLAIM ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL DRL OR
# ISC BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
# DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA
# OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
# TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
Management code for the IRDB.
"""

# pylint: disable=W0612,C0325

import os
import copy
import types
import rpki.config
import rpki.sundial
import rpki.oids
import rpki.http_simple
import rpki.resource_set
import rpki.relaxng
import rpki.left_right
import rpki.x509
import rpki.irdb
import rpki.publication_control
import django.db.transaction

from lxml.etree import (Element, SubElement, ElementTree,
                        tostring as ElementToString)

from rpki.csv_utils import csv_reader

# XML namespace and protocol version for OOB setup protocol.  The name
# is historical and may change before we propose this as the basis for
# a standard.

myrpki_xmlns   = rpki.relaxng.myrpki.xmlns
myrpki_version = rpki.relaxng.myrpki.version

# XML namespace and protocol version for router certificate requests.
# We probably ought to be pulling this sort of thing from the schema,
# with an assertion to make sure that we understand the current
# protocol version number, but just copy what we did for myrpki until
# I'm ready to rewrite the rpki.relaxng code.

routercert_xmlns   = rpki.relaxng.router_certificate.xmlns
routercert_version = rpki.relaxng.router_certificate.version

myrpki_section = "myrpki"
irdbd_section  = "irdbd"
rpkid_section  = "rpkid"
pubd_section   = "pubd"
rootd_section  = "rootd"

# A whole lot of exceptions

class HandleNotSet(Exception):          "Handle not set."
class MissingHandle(Exception):         "Missing handle."
class CouldntTalkToDaemon(Exception):   "Couldn't talk to daemon."
class BadXMLMessage(Exception):         "Bad XML message."
class PastExpiration(Exception):        "Expiration date has already passed."
class CantRunRootd(Exception):          "Can't run rootd."


def B64Element(e, tag, obj, **kwargs):
  """
  Create an XML element containing Base64 encoded data taken from a
  DER object.
  """

  if e is None:
    se = Element(tag, **kwargs)
  else:
    se = SubElement(e, tag, **kwargs)
  if e is not None and e.text is None:
    e.text = "\n"
  se.text = "\n" + obj.get_Base64()
  se.tail = "\n"
  return se

class PEM_writer(object):
  """
  Write PEM files to disk, keeping track of which ones we've already
  written and setting the file mode appropriately.

  Comparing the old file with what we're about to write serves no real
  purpose except to calm users who find repeated messages about
  writing the same file confusing.
  """

  def __init__(self, logstream = None):
    self.wrote = set()
    self.logstream = logstream

  def __call__(self, filename, obj, compare = True):
    filename = os.path.realpath(filename)
    if filename in self.wrote:
      return
    tempname = filename
    pem = obj.get_PEM()
    if not filename.startswith("/dev/"):
      try:
        if compare and pem == open(filename, "r").read():
          return
      except:                           # pylint: disable=W0702
        pass
      tempname += ".%s.tmp" % os.getpid()
    mode = 0400 if filename.endswith(".key") else 0444
    if self.logstream is not None:
      self.logstream.write("Writing %s\n" % filename)
    f = os.fdopen(os.open(tempname, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode), "w")
    f.write(pem)
    f.close()
    if tempname != filename:
      os.rename(tempname, filename)
    self.wrote.add(filename)


def etree_read(filename):
  """
  Read an etree from a file, verifying then stripping XML namespace
  cruft.
  """

  e = ElementTree(file = filename).getroot()
  rpki.relaxng.myrpki.assertValid(e)
  for i in e.getiterator():
    if i.tag.startswith(myrpki_xmlns):
      i.tag = i.tag[len(myrpki_xmlns):]
    else:
      raise BadXMLMessage("XML tag %r is not in namespace %r" % (i.tag, myrpki_xmlns[1:-1]))
  return e


class etree_wrapper(object):
  """
  Wrapper for ETree objects so we can return them as function results
  without requiring the caller to understand much about them.
  """

  def __init__(self, e, msg = None, debug = False):
    self.msg = msg
    e = copy.deepcopy(e)
    e.set("version", myrpki_version)
    for i in e.getiterator():
      if i.tag[0] != "{":
        i.tag = myrpki_xmlns + i.tag
      assert i.tag.startswith(myrpki_xmlns)
    if debug:
      print ElementToString(e)
    rpki.relaxng.myrpki.assertValid(e)
    self.etree = e

  def __str__(self):
    return ElementToString(self.etree)

  def save(self, filename, logstream = None):
    filename = os.path.realpath(filename)
    tempname = filename
    if not filename.startswith("/dev/"):
      tempname += ".%s.tmp" % os.getpid()
    ElementTree(self.etree).write(tempname)
    if tempname != filename:
      os.rename(tempname, filename)
    if logstream is not None:
      logstream.write("Wrote %s\n" % filename)
      if self.msg is not None:
        logstream.write(self.msg + "\n")

  @property
  def file(self):
    from cStringIO import StringIO
    return StringIO(ElementToString(self.etree))


class Zookeeper(object):

  ## @var show_xml
  # If not None, a file-like object to which to prettyprint XML, for debugging.

  show_xml = None

  def __init__(self, cfg = None, handle = None, logstream = None, disable_signal_handlers = False):

    if cfg is None:
      cfg = rpki.config.parser()

    if handle is None:
      handle = cfg.get("handle", section = myrpki_section)

    self.cfg = cfg

    self.logstream = logstream
    self.disable_signal_handlers = disable_signal_handlers

    self.run_rpkid = cfg.getboolean("run_rpkid", section = myrpki_section)
    self.run_pubd  = cfg.getboolean("run_pubd", section = myrpki_section)
    self.run_rootd = cfg.getboolean("run_rootd", section = myrpki_section)

    if self.run_rootd and (not self.run_pubd or not self.run_rpkid):
      raise CantRunRootd("Can't run rootd unless also running rpkid and pubd")

    self.default_repository = cfg.get("default_repository", "", section = myrpki_section)
    self.pubd_contact_info = cfg.get("pubd_contact_info", "", section = myrpki_section)

    self.rsync_module = cfg.get("publication_rsync_module", section = myrpki_section)
    self.rsync_server = cfg.get("publication_rsync_server", section = myrpki_section)

    self.reset_identity(handle)


  def reset_identity(self, handle):
    """
    Select handle of current resource holding entity.
    """

    if handle is None:
      raise MissingHandle
    self.handle = handle


  def set_logstream(self, logstream):
    """
    Set log stream for this Zookeeper.  The log stream is a file-like
    object, or None to suppress all logging.
    """

    self.logstream = logstream


  def log(self, msg):
    """
    Send some text to this Zookeeper's log stream, if one is set.
    """

    if self.logstream is not None:
      self.logstream.write(msg)
      self.logstream.write("\n")


  @property
  def resource_ca(self):
    """
    Get ResourceHolderCA object associated with current handle.
    """

    if self.handle is None:
      raise HandleNotSet
    return rpki.irdb.models.ResourceHolderCA.objects.get(handle = self.handle)


  @property
  def server_ca(self):
    """
    Get ServerCA object.
    """

    return rpki.irdb.models.ServerCA.objects.get()


  @django.db.transaction.atomic
  def initialize_server_bpki(self):
    """
    Initialize server BPKI portion of an RPKI installation.  Reads the
    configuration file and generates the initial BPKI server
    certificates needed to start daemons.
    """

    if self.run_rpkid or self.run_pubd:
      server_ca, created = rpki.irdb.models.ServerCA.objects.get_or_certify()
      rpki.irdb.models.ServerEE.objects.get_or_certify(issuer = server_ca, purpose = "irbe")

    if self.run_rpkid:
      rpki.irdb.models.ServerEE.objects.get_or_certify(issuer = server_ca, purpose = "rpkid")
      rpki.irdb.models.ServerEE.objects.get_or_certify(issuer = server_ca, purpose = "irdbd")

    if self.run_pubd:
      rpki.irdb.models.ServerEE.objects.get_or_certify(issuer = server_ca, purpose = "pubd")


  @django.db.transaction.atomic
  def initialize_resource_bpki(self):
    """
    Initialize the resource-holding BPKI for an RPKI installation.
    Returns XML describing the resource holder.

    This method is present primarily for backwards compatibility with
    the old combined initialize() method which initialized both the
    server BPKI and the default resource-holding BPKI in a single
    method call.  In the long run we want to replace this with
    something that takes a handle as argument and creates the
    resource-holding BPKI idenity if needed.
    """

    resource_ca, created = rpki.irdb.models.ResourceHolderCA.objects.get_or_certify(handle = self.handle)
    return self.generate_identity()


  def initialize(self):
    """
    Backwards compatibility wrapper: calls initialize_server_bpki()
    and initialize_resource_bpki(), returns latter's result.
    """

    self.initialize_server_bpki()
    return self.initialize_resource_bpki()


  def generate_identity(self):
    """
    Generate identity XML.  Broken out of .initialize() because it's
    easier for the GUI this way.
    """

    e = Element("identity", handle = self.handle)
    B64Element(e, "bpki_ta", self.resource_ca.certificate)
    return etree_wrapper(e, msg = 'This is the "identity" file you will need to send to your parent')


  @django.db.transaction.atomic
  def delete_self(self):
    """
    Delete the ResourceHolderCA object corresponding to the current handle.
    This corresponds to deleting an rpkid <self/> object.

    This code assumes the normal Django cascade-on-delete behavior,
    that is, we assume that deleting the ResourceHolderCA object
    deletes all the subordinate objects that refer to it via foreign
    key relationships.
    """

    resource_ca = self.resource_ca
    if resource_ca is not None:
      resource_ca.delete()
    else:
      self.log("No such ResourceHolderCA \"%s\"" % self.handle)


  @django.db.transaction.atomic
  def configure_rootd(self):

    assert self.run_rpkid and self.run_pubd and self.run_rootd

    rpki.irdb.models.Rootd.objects.get_or_certify(
      issuer = self.resource_ca,
      service_uri = "http://localhost:%s/" % self.cfg.get("rootd_server_port", section = myrpki_section))

    return self.generate_rootd_repository_offer()


  def generate_rootd_repository_offer(self):
    """
    Generate repository offer for rootd.  Split out of
    configure_rootd() because that's easier for the GUI.
    """

    # The following assumes we'll set up the respository manually.
    # Not sure this is a reasonable assumption, particularly if we
    # ever fix rootd to use the publication protocol.

    try:
      self.resource_ca.repositories.get(handle = self.handle)
      return None

    except rpki.irdb.models.Repository.DoesNotExist:
      e = Element("repository", type = "offer", handle = self.handle, parent_handle = self.handle)
      B64Element(e, "bpki_client_ta", self.resource_ca.certificate)
      return etree_wrapper(e, msg = 'This is the "repository offer" file for you to use if you want to publish in your own repository')


  def write_bpki_files(self):
    """
    Write out BPKI certificate, key, and CRL files for daemons that
    need them.
    """

    writer = PEM_writer(self.logstream)

    if self.run_rpkid:
      rpkid = self.server_ca.ee_certificates.get(purpose = "rpkid")
      writer(self.cfg.get("bpki-ta",    section = rpkid_section), self.server_ca.certificate)
      writer(self.cfg.get("rpkid-key",  section = rpkid_section), rpkid.private_key)
      writer(self.cfg.get("rpkid-cert", section = rpkid_section), rpkid.certificate)
      writer(self.cfg.get("irdb-cert",  section = rpkid_section),
             self.server_ca.ee_certificates.get(purpose = "irdbd").certificate)
      writer(self.cfg.get("irbe-cert",  section = rpkid_section),
             self.server_ca.ee_certificates.get(purpose = "irbe").certificate)

    if self.run_pubd:
      pubd = self.server_ca.ee_certificates.get(purpose = "pubd")
      writer(self.cfg.get("bpki-ta",   section = pubd_section), self.server_ca.certificate)
      writer(self.cfg.get("pubd-key",  section = pubd_section), pubd.private_key)
      writer(self.cfg.get("pubd-cert", section = pubd_section), pubd.certificate)
      writer(self.cfg.get("irbe-cert", section = pubd_section),
             self.server_ca.ee_certificates.get(purpose = "irbe").certificate)

    if self.run_rootd:
      try:
        rootd = rpki.irdb.models.ResourceHolderCA.objects.get(handle = self.handle).rootd
        writer(self.cfg.get("bpki-ta",         section = rootd_section), self.server_ca.certificate)
        writer(self.cfg.get("rootd-bpki-crl",  section = rootd_section), self.server_ca.latest_crl)
        writer(self.cfg.get("rootd-bpki-key",  section = rootd_section), rootd.private_key)
        writer(self.cfg.get("rootd-bpki-cert", section = rootd_section), rootd.certificate)
        writer(self.cfg.get("child-bpki-cert", section = rootd_section), rootd.issuer.certificate)
      except rpki.irdb.models.ResourceHolderCA.DoesNotExist:
        self.log("rootd enabled but resource holding entity not yet configured, skipping rootd setup")
      except rpki.irdb.models.Rootd.DoesNotExist:
        self.log("rootd enabled but not yet configured, skipping rootd setup")


  @django.db.transaction.atomic
  def update_bpki(self):
    """
    Update BPKI certificates.  Assumes an existing RPKI installation.

    Basic plan here is to reissue all BPKI certificates we can, right
    now.  In the long run we might want to be more clever about only
    touching ones that need maintenance, but this will do for a start.

    We also reissue CRLs for all CAs.

    Most likely this should be run under cron.
    """

    for model in (rpki.irdb.models.ServerCA,
                  rpki.irdb.models.ResourceHolderCA,
                  rpki.irdb.models.ServerEE,
                  rpki.irdb.models.Referral,
                  rpki.irdb.models.Rootd,
                  rpki.irdb.models.HostedCA,
                  rpki.irdb.models.BSC,
                  rpki.irdb.models.Child,
                  rpki.irdb.models.Parent,
                  rpki.irdb.models.Client,
                  rpki.irdb.models.Repository):
      for obj in model.objects.all():
        self.log("Regenerating BPKI certificate %s" % obj.certificate.getSubject())
        obj.avow()
        obj.save()

    self.log("Regenerating Server BPKI CRL")
    self.server_ca.generate_crl()
    self.server_ca.save()

    for ca in rpki.irdb.models.ResourceHolderCA.objects.all():
      self.log("Regenerating BPKI CRL for Resource Holder %s" % ca.handle)
      ca.generate_crl()
      ca.save()


  @staticmethod
  def _compose_left_right_query():
    """
    Compose top level element of a left-right query.
    """

    return Element(rpki.left_right.tag_msg, nsmap = rpki.left_right.nsmap,
                   type = "query", version = rpki.left_right.version)


  @staticmethod
  def _compose_publication_control_query():
    """
    Compose top level element of a publication-control query.
    """

    return Element(rpki.publication_control.tag_msg, nsmap = rpki.publication_control.nsmap,
                   type = "query", version = rpki.publication_control.version)


  @django.db.transaction.atomic
  def synchronize_bpki(self):
    """
    Synchronize BPKI updates.  This is separate from .update_bpki()
    because this requires rpkid to be running and none of the other
    BPKI update stuff does; there may be circumstances under which it
    makes sense to do the rest of the BPKI update and allow this to
    fail with a warning.
    """

    if self.run_rpkid:
      q_msg = self._compose_left_right_query()

      for ca in rpki.irdb.models.ResourceHolderCA.objects.all():
        q_pdu = SubElement(q_msg, rpki.left_right.tag_self,
                           action = "set",
                           tag = "%s__self" % ca.handle,
                           self_handle = ca.handle)
        SubElement(q_pdu, rpki.left_right.tag_bpki_cert).text = ca.certificate.get_Base64()

      for bsc in rpki.irdb.models.BSC.objects.all():
        q_pdu = SubElement(q_msg, rpki.left_right.tag_bsc,
                           action = "set",
                           tag = "%s__bsc__%s" % (bsc.issuer.handle, bsc.handle),
                           self_handle = bsc.issuer.handle,
                           bsc_handle = bsc.handle)
        SubElement(q_pdu, rpki.left_right.tag_signing_cert).text = bsc.certificate.get_Base64()
        SubElement(q_pdu, rpki.left_right.tag_signing_cert_crl).text = bsc.issuer.latest_crl.get_Base64()

      for repository in rpki.irdb.models.Repository.objects.all():
        q_pdu = SubElement(q_msg, rpki.left_right.tag_repository,
                           action = "set",
                           tag = "%s__repository__%s" % (repository.issuer.handle, repository.handle),
                           self_handle = repository.issuer.handle,
                           repository_handle = repository.handle)
        SubElement(q_pdu, rpki.left_right.tag_bpki_cert).text = repository.certificate.get_Base64()

      for parent in rpki.irdb.models.Parent.objects.all():
        q_pdu = SubElement(q_msg, rpki.left_right.tag_parent,
                           action = "set",
                           tag = "%s__parent__%s" % (parent.issuer.handle, parent.handle),
                           self_handle = parent.issuer.handle,
                           parent_handle = parent.handle)
        SubElement(q_pdu, rpki.left_right.tag_bpki_cms_cert).text = parent.certificate.get_Base64()

      for rootd in rpki.irdb.models.Rootd.objects.all():
        q_pdu = SubElement(q_msg, rpki.left_right.tag_parent,
                           action = "set",
                           tag = "%s__rootd" % rootd.issuer.handle,
                           self_handle = rootd.issuer.handle,
                           parent_handle = rootd.issuer.handle)
        SubElement(q_pdu, rpki.left_right.tag_bpki_cms_cert).text = rootd.certificate.get_Base64()

      for child in rpki.irdb.models.Child.objects.all():
        q_pdu = SubElement(q_msg, rpki.left_right.tag_child,
                           action = "set",
                           tag = "%s__child__%s" % (child.issuer.handle, child.handle),
                           self_handle = child.issuer.handle,
                           child_handle = child.handle)
        SubElement(q_pdu, rpki.left_right.tag_bpki_cert).text = child.certificate.get_Base64()

      if len(q_msg) > 0:
        self.call_rpkid(q_msg)

    if self.run_pubd:
      q_msg = self._compose_publication_control_query()

      for client in self.server_ca.clients.all():
        q_pdu = SubElement(q_msg, rpki.publication_control.tag_client, action = "set", client_handle = client.handle)
        SubElement(q_pdu, rpki.publication_control.tag_bpki_cert).text = client.certificate.get_Base64()

      if len(q_msg) > 0:
        self.call_pubd(q_msg)


  @django.db.transaction.atomic
  def configure_child(self, filename, child_handle = None, valid_until = None):
    """
    Configure a new child of this RPKI entity, given the child's XML
    identity file as an input.  Extracts the child's data from the
    XML, cross-certifies the child's resource-holding BPKI
    certificate, and generates an XML file describing the relationship
    between the child and this parent, including this parent's BPKI
    data and up-down protocol service URI.
    """

    c = etree_read(filename)

    if child_handle is None:
      child_handle = c.get("handle")

    if valid_until is None:
      valid_until = rpki.sundial.now() + rpki.sundial.timedelta(days = 365)
    else:
      valid_until = rpki.sundial.datetime.fromXMLtime(valid_until)
      if valid_until < rpki.sundial.now():
        raise PastExpiration("Specified new expiration time %s has passed" % valid_until)

    self.log("Child calls itself %r, we call it %r" % (c.get("handle"), child_handle))

    child, created = rpki.irdb.models.Child.objects.get_or_certify(
      issuer = self.resource_ca,
      handle = child_handle,
      ta = rpki.x509.X509(Base64 = c.findtext("bpki_ta")),
      valid_until = valid_until)

    return self.generate_parental_response(child), child_handle


  @django.db.transaction.atomic
  def generate_parental_response(self, child):
    """
    Generate parental response XML.  Broken out of .configure_child()
    for GUI.
    """

    service_uri = "http://%s:%s/up-down/%s/%s" % (
      self.cfg.get("rpkid_server_host", section = myrpki_section),
      self.cfg.get("rpkid_server_port", section = myrpki_section),
      self.handle, child.handle)

    e = Element("parent", parent_handle = self.handle, child_handle = child.handle,
                service_uri = service_uri, valid_until = str(child.valid_until))
    B64Element(e, "bpki_resource_ta", self.resource_ca.certificate)
    B64Element(e, "bpki_child_ta", child.ta)

    try:
      if self.default_repository:
        repo = self.resource_ca.repositories.get(handle = self.default_repository)
      else:
        repo = self.resource_ca.repositories.get()
    except rpki.irdb.models.Repository.DoesNotExist:
      repo = None

    if repo is None:
      self.log("Couldn't find any usable repositories, not giving referral")

    elif repo.handle == self.handle:
      SubElement(e, "repository", type = "offer")

    else:
      proposed_sia_base = repo.sia_base + child.handle + "/"
      referral_cert, created = rpki.irdb.models.Referral.objects.get_or_certify(issuer = self.resource_ca)
      auth = rpki.x509.SignedReferral()
      auth.set_content(B64Element(None, myrpki_xmlns + "referral", child.ta,
                                  version = myrpki_version,
                                  authorized_sia_base = proposed_sia_base))
      auth.schema_check()
      auth.sign(referral_cert.private_key, referral_cert.certificate, self.resource_ca.latest_crl)

      r = SubElement(e, "repository", type = "referral")
      B64Element(r, "authorization", auth, referrer = repo.client_handle)
      SubElement(r, "contact_info")

    return etree_wrapper(e, msg = "Send this file back to the child you just configured")


  @django.db.transaction.atomic
  def delete_child(self, child_handle):
    """
    Delete a child of this RPKI entity.
    """

    self.resource_ca.children.get(handle = child_handle).delete()


  @django.db.transaction.atomic
  def configure_parent(self, filename, parent_handle = None):
    """
    Configure a new parent of this RPKI entity, given the output of
    the parent's configure_child command as input.  Reads the parent's
    response XML, extracts the parent's BPKI and service URI
    information, cross-certifies the parent's BPKI data into this
    entity's BPKI, and checks for offers or referrals of publication
    service.  If a publication offer or referral is present, we
    generate a request-for-service message to that repository, in case
    the user wants to avail herself of the referral or offer.
    """

    p = etree_read(filename)

    if parent_handle is None:
      parent_handle = p.get("parent_handle")

    r = p.find("repository")

    repository_type = "none"
    referrer = None
    referral_authorization = None

    if r is not None:
      repository_type = r.get("type")

    if repository_type == "referral":
      a = r.find("authorization")
      referrer = a.get("referrer")
      referral_authorization = rpki.x509.SignedReferral(Base64 = a.text)

    self.log("Parent calls itself %r, we call it %r" % (p.get("parent_handle"), parent_handle))
    self.log("Parent calls us %r" % p.get("child_handle"))

    parent, created = rpki.irdb.models.Parent.objects.get_or_certify(
      issuer = self.resource_ca,
      handle = parent_handle,
      child_handle = p.get("child_handle"),
      parent_handle = p.get("parent_handle"),
      service_uri = p.get("service_uri"),
      ta = rpki.x509.X509(Base64 = p.findtext("bpki_resource_ta")),
      repository_type = repository_type,
      referrer = referrer,
      referral_authorization = referral_authorization)

    return self.generate_repository_request(parent), parent_handle


  def generate_repository_request(self, parent):
    """
    Generate repository request for a given parent.
    """

    e = Element("repository", handle = self.handle,
                parent_handle = parent.handle, type = parent.repository_type)
    if parent.repository_type == "referral":
      B64Element(e, "authorization", parent.referral_authorization, referrer = parent.referrer)
      SubElement(e, "contact_info")
    B64Element(e, "bpki_client_ta", self.resource_ca.certificate)
    return etree_wrapper(e, msg = "This is the file to send to the repository operator")


  @django.db.transaction.atomic
  def delete_parent(self, parent_handle):
    """
    Delete a parent of this RPKI entity.
    """

    self.resource_ca.parents.get(handle = parent_handle).delete()


  @django.db.transaction.atomic
  def delete_rootd(self):
    """
    Delete rootd associated with this RPKI entity.
    """

    self.resource_ca.rootd.delete()


  @django.db.transaction.atomic
  def configure_publication_client(self, filename, sia_base = None, flat = False):
    """
    Configure publication server to know about a new client, given the
    client's request-for-service message as input.  Reads the client's
    request for service, cross-certifies the client's BPKI data, and
    generates a response message containing the repository's BPKI data
    and service URI.
    """

    client = etree_read(filename)

    client_ta = rpki.x509.X509(Base64 = client.findtext("bpki_client_ta"))

    if sia_base is None and flat:
      self.log("Flat publication structure forced, homing client at top-level")
      sia_base = "rsync://%s/%s/%s/" % (self.rsync_server, self.rsync_module, client.get("handle"))

    if sia_base is None and client.get("type") == "referral":
      self.log("This looks like a referral, checking")
      try:
        auth = client.find("authorization")
        referrer = self.server_ca.clients.get(handle = auth.get("referrer"))
        referral_cms = rpki.x509.SignedReferral(Base64 = auth.text)
        referral_xml = referral_cms.unwrap(ta = (referrer.certificate, self.server_ca.certificate))
        if rpki.x509.X509(Base64 = referral_xml.text) != client_ta:
          raise BadXMLMessage("Referral trust anchor does not match")
        sia_base = referral_xml.get("authorized_sia_base")
      except rpki.irdb.models.Client.DoesNotExist:
        self.log("We have no record of the client (%s) alleged to have made this referral" % auth.get("referrer"))

    if sia_base is None and client.get("type") == "offer":
      self.log("This looks like an offer, checking")
      try:
        parent = rpki.irdb.models.ResourceHolderCA.objects.get(children__ta__exact = client_ta)
        if "/" in parent.repositories.get(ta = self.server_ca.certificate).client_handle:
          self.log("Client's parent is not top-level, this is not a valid offer")
        else:
          self.log("Found client and its parent, nesting")
          sia_base = "rsync://%s/%s/%s/%s/" % (self.rsync_server, self.rsync_module,
                                                 parent.handle, client.get("handle"))
      except rpki.irdb.models.Repository.DoesNotExist:
        self.log("Found client's parent, but repository isn't set, this shouldn't happen!")
      except rpki.irdb.models.ResourceHolderCA.DoesNotExist:
        try:
          rpki.irdb.models.Rootd.objects.get(issuer__certificate__exact = client_ta)
        except rpki.irdb.models.Rootd.DoesNotExist:
          self.log("We don't host this client's parent, so we didn't make this offer")
        else:
          self.log("This client's parent is rootd")

    if sia_base is None:
      self.log("Don't know where to nest this client, defaulting to top-level")
      sia_base = "rsync://%s/%s/%s/" % (self.rsync_server, self.rsync_module, client.get("handle"))

    if not sia_base.startswith("rsync://"):
      raise BadXMLMessage("Malformed sia_base parameter %r, should start with 'rsync://'" % sia_base)

    client_handle = "/".join(sia_base.rstrip("/").split("/")[4:])

    parent_handle = client.get("parent_handle")

    self.log("Client calls itself %r, we call it %r" % (client.get("handle"), client_handle))
    self.log("Client says its parent handle is %r" % parent_handle)

    client, created = rpki.irdb.models.Client.objects.get_or_certify(
      issuer = self.server_ca,
      handle = client_handle,
      parent_handle = parent_handle,
      ta = client_ta,
      sia_base = sia_base)

    return self.generate_repository_response(client), client_handle


  def generate_repository_response(self, client):
    """
    Generate repository response XML to a given client.
    """

    service_uri = "http://%s:%s/client/%s" % (
      self.cfg.get("pubd_server_host", section = myrpki_section),
      self.cfg.get("pubd_server_port", section = myrpki_section),
      client.handle)

    e = Element("repository", type = "confirmed",
                client_handle = client.handle,
                parent_handle = client.parent_handle,
                sia_base = client.sia_base,
                service_uri = service_uri)

    B64Element(e, "bpki_server_ta", self.server_ca.certificate)
    B64Element(e, "bpki_client_ta", client.ta)
    SubElement(e, "contact_info").text = self.pubd_contact_info
    return etree_wrapper(e, msg = "Send this file back to the publication client you just configured")


  @django.db.transaction.atomic
  def delete_publication_client(self, client_handle):
    """
    Delete a publication client of this RPKI entity.
    """

    self.server_ca.clients.get(handle = client_handle).delete()


  @django.db.transaction.atomic
  def configure_repository(self, filename, parent_handle = None):
    """
    Configure a publication repository for this RPKI entity, given the
    repository's response to our request-for-service message as input.
    Reads the repository's response, extracts and cross-certifies the
    BPKI data and service URI, and links the repository data with the
    corresponding parent data in our local database.
    """

    r = etree_read(filename)

    if parent_handle is None:
      parent_handle = r.get("parent_handle")

    self.log("Repository calls us %r" % (r.get("client_handle")))
    self.log("Repository response associated with parent_handle %r" % parent_handle)

    try:
      if parent_handle == self.handle:
        turtle = self.resource_ca.rootd
      else:
        turtle = self.resource_ca.parents.get(handle = parent_handle)

    except (rpki.irdb.models.Parent.DoesNotExist, rpki.irdb.models.Rootd.DoesNotExist):
      self.log("Could not find parent %r in our database" % parent_handle)

    else:
      rpki.irdb.models.Repository.objects.get_or_certify(
        issuer = self.resource_ca,
        handle = parent_handle,
        client_handle = r.get("client_handle"),
        service_uri = r.get("service_uri"),
        sia_base = r.get("sia_base"),
        ta = rpki.x509.X509(Base64 = r.findtext("bpki_server_ta")),
        turtle = turtle)


  @django.db.transaction.atomic
  def delete_repository(self, repository_handle):
    """
    Delete a repository of this RPKI entity.
    """

    self.resource_ca.repositories.get(handle = repository_handle).delete()


  @django.db.transaction.atomic
  def renew_children(self, child_handle, valid_until = None):
    """
    Update validity period for one child entity or, if child_handle is
    None, for all child entities.
    """

    if child_handle is None:
      children = self.resource_ca.children.all()
    else:
      children = self.resource_ca.children.filter(handle = child_handle)

    if valid_until is None:
      valid_until = rpki.sundial.now() + rpki.sundial.timedelta(days = 365)
    else:
      valid_until = rpki.sundial.datetime.fromXMLtime(valid_until)
      if valid_until < rpki.sundial.now():
        raise PastExpiration("Specified new expiration time %s has passed" % valid_until)

    self.log("New validity date %s" % valid_until)

    for child in children:
      child.valid_until = valid_until
      child.save()


  @django.db.transaction.atomic
  def load_prefixes(self, filename, ignore_missing_children = False):
    """
    Whack IRDB to match prefixes.csv.
    """

    grouped4 = {}
    grouped6 = {}

    for handle, prefix in csv_reader(filename, columns = 2):
      grouped = grouped6 if ":" in prefix else grouped4
      if handle not in grouped:
        grouped[handle] = []
      grouped[handle].append(prefix)

    primary_keys = []

    for version, grouped, rset in ((4, grouped4, rpki.resource_set.resource_set_ipv4),
                                   (6, grouped6, rpki.resource_set.resource_set_ipv6)):
      for handle, prefixes in grouped.iteritems():
        try:
          child = self.resource_ca.children.get(handle = handle)
        except rpki.irdb.models.Child.DoesNotExist:
          if not ignore_missing_children:
            raise
        else:
          for prefix in rset(",".join(prefixes)):
            obj, created = rpki.irdb.models.ChildNet.objects.get_or_create(
              child    = child,
              start_ip = str(prefix.min),
              end_ip   = str(prefix.max),
              version  = version)
            primary_keys.append(obj.pk)

    q = rpki.irdb.models.ChildNet.objects
    q = q.filter(child__issuer__exact = self.resource_ca)
    q = q.exclude(pk__in = primary_keys)
    q.delete()


  @django.db.transaction.atomic
  def load_asns(self, filename, ignore_missing_children = False):
    """
    Whack IRDB to match asns.csv.
    """

    grouped = {}

    for handle, asn in csv_reader(filename, columns = 2):
      if handle not in grouped:
        grouped[handle] = []
      grouped[handle].append(asn)

    primary_keys = []

    for handle, asns in grouped.iteritems():
      try:
        child = self.resource_ca.children.get(handle = handle)
      except rpki.irdb.models.Child.DoesNotExist:
        if not ignore_missing_children:
          raise
      else:
        for asn in rpki.resource_set.resource_set_as(",".join(asns)):
          obj, created = rpki.irdb.models.ChildASN.objects.get_or_create(
            child    = child,
            start_as = str(asn.min),
            end_as   = str(asn.max))
          primary_keys.append(obj.pk)

    q = rpki.irdb.models.ChildASN.objects
    q = q.filter(child__issuer__exact = self.resource_ca)
    q = q.exclude(pk__in = primary_keys)
    q.delete()


  @django.db.transaction.atomic
  def load_roa_requests(self, filename):
    """
    Whack IRDB to match roa.csv.
    """

    grouped = {}

    # format:  p/n-m asn group
    for pnm, asn, group in csv_reader(filename, columns = 3):
      key = (asn, group)
      if key not in grouped:
        grouped[key] = []
      grouped[key].append(pnm)

    # Deleting and recreating all the ROA requests is inefficient,
    # but rpkid's current representation of ROA requests is wrong
    # (see #32), so it's not worth a lot of effort here as we're
    # just going to have to rewrite this soon anyway.

    self.resource_ca.roa_requests.all().delete()

    for key, pnms in grouped.iteritems():
      asn, group = key

      roa_request = self.resource_ca.roa_requests.create(asn = asn)

      for pnm in pnms:
        if ":" in pnm:
          p = rpki.resource_set.roa_prefix_ipv6.parse_str(pnm)
          v = 6
        else:
          p = rpki.resource_set.roa_prefix_ipv4.parse_str(pnm)
          v = 4
        roa_request.prefixes.create(
          version       = v,
          prefix        = str(p.prefix),
          prefixlen     = int(p.prefixlen),
          max_prefixlen = int(p.max_prefixlen))


  @django.db.transaction.atomic
  def load_ghostbuster_requests(self, filename, parent = None):
    """
    Whack IRDB to match ghostbusters.vcard.

    This accepts one or more vCards from a file.
    """

    self.resource_ca.ghostbuster_requests.filter(parent = parent).delete()

    vcard = []

    for line in open(filename, "r"):
      if not vcard and not line.upper().startswith("BEGIN:VCARD"):
        continue
      vcard.append(line)
      if line.upper().startswith("END:VCARD"):
        self.resource_ca.ghostbuster_requests.create(vcard = "".join(vcard), parent = parent)
        vcard = []


  def call_rpkid(self, q_msg, suppress_error_check = False):
    """
    Issue a call to rpkid, return result.
    """

    url = "http://%s:%s/left-right" % (
      self.cfg.get("rpkid_server_host", section = myrpki_section),
      self.cfg.get("rpkid_server_port", section = myrpki_section))

    rpkid = self.server_ca.ee_certificates.get(purpose = "rpkid")
    irbe  = self.server_ca.ee_certificates.get(purpose = "irbe")

    r_msg = rpki.http_simple.client(
      proto_cms_msg = rpki.left_right.cms_msg,
      client_key    = irbe.private_key,
      client_cert   = irbe.certificate,
      server_ta     = self.server_ca.certificate,
      server_cert   = rpkid.certificate,
      url           = url,
      q_msg         = q_msg,
      debug         = self.show_xml)

    if not suppress_error_check:
      self.check_error_report(r_msg)
    return r_msg


  def _rpkid_self_control(self, *bools):
    assert all(isinstance(b, str) for b in bools)
    q_msg = self._compose_left_right_query()
    q_pdu = SubElement(q_msg, rpki.left_right.tag_self, action = "set", self_handle = self.handle)
    for b in bools:
      q_pdu.set(b, "yes")
    return self.call_rpkid(q_msg)


  def run_rpkid_now(self):
    """
    Poke rpkid to immediately run the cron job for the current handle.

    This method is used by the GUI when a user has changed something in the
    IRDB (ghostbuster, roa) which does not require a full synchronize() call,
    to force the object to be immediately issued.
    """

    return self._rpkid_self_control("run_now")


  def publish_world_now(self):
    """
    Poke rpkid to (re)publish everything for the current handle.
    """

    return self._rpkid_self_control("publish_world_now")


  def reissue(self):
    """
    Poke rpkid to reissue everything for the current handle.
    """

    return self._rpkid_self_control("reissue")


  def rekey(self):
    """
    Poke rpkid to rekey all RPKI certificates received for the current
    handle.
    """

    return self._rpkid_self_control("rekey")


  def revoke(self):
    """
    Poke rpkid to revoke old RPKI keys for the current handle.
    """

    return self._rpkid_self_control("revoke")


  def revoke_forgotten(self):
    """
    Poke rpkid to revoke old forgotten RPKI keys for the current handle.
    """

    return self._rpkid_self_control("revoke_forgotten")


  def clear_all_sql_cms_replay_protection(self):
    """
    Tell rpkid and pubd to clear replay protection for all SQL-based
    entities.  This is a fairly blunt instrument, but as we don't
    expect this to be necessary except in the case of gross
    misconfiguration, it should suffice.
    """

    if self.run_rpkid:
      q_msg = self._compose_left_right_query()
      for ca in rpki.irdb.models.ResourceHolderCA.objects.all():
        SubElement(q_msg, rpki.left_right.tag_self, action = "set",
                   self_handle = ca.handle, clear_replay_protection = "yes")
      self.call_rpkid(q_msg)

    if self.run_pubd:
      q_msg = self._compose_publication_control_query()
      for client in self.server_ca.clients.all():
        SubElement(q_msg, rpki.publication_control.tag_client, action = "set",
                   client_handle = client.handle, clear_reply_protection = "yes")
      self.call_pubd(q_msg)


  def call_pubd(self, q_msg):
    """
    Issue a call to pubd, return result.
    """

    url = "http://%s:%s/control" % (
      self.cfg.get("pubd_server_host", section = myrpki_section),
      self.cfg.get("pubd_server_port", section = myrpki_section))

    pubd = self.server_ca.ee_certificates.get(purpose = "pubd")
    irbe = self.server_ca.ee_certificates.get(purpose = "irbe")

    r_msg = rpki.http_simple.client(
      proto_cms_msg = rpki.publication_control.cms_msg,
      client_key    = irbe.private_key,
      client_cert   = irbe.certificate,
      server_ta     = self.server_ca.certificate,
      server_cert   = pubd.certificate,
      url           = url,
      q_msg         = q_msg,
      debug         = self.show_xml)

    self.check_error_report(r_msg)
    return r_msg


  def check_error_report(self, r_msg):
    """
    Check a response from rpkid or pubd for error_report PDUs, log and
    throw exceptions as needed.
    """

    if any(r_pdu.tag in (rpki.left_right.tag_report_error,
                         rpki.publication_control.tag_report_error)
           for r_pdu in r_msg):
      for r_pdu in r_msg:
        if r_pdu.tag == rpki.left_right.tag_report_error:
          self.log("rpkid reported failure: %s" % r_pdu.get("error_code"))
        elif r_pdu.tag == rpki.publication_control.tag_report_error:
          self.log("pubd reported failure: %s" % r_pdu.get("error_code"))
        else:
          continue
        if r_pdu.text:
          self.log(r_pdu.text)
      raise CouldntTalkToDaemon


  @django.db.transaction.atomic
  def synchronize(self, *handles_to_poke):
    """
    Configure RPKI daemons with the data built up by the other
    commands in this program.  Commands which modify the IRDB and want
    to whack everything into sync should call this when they're done,
    but be warned that this can be slow with a lot of CAs.

    Any arguments given are handles of CAs which should be poked with a
    <self run_now="yes"/> operation.
    """

    for ca in rpki.irdb.models.ResourceHolderCA.objects.all():
      self.synchronize_rpkid_one_ca_core(ca, ca.handle in handles_to_poke)
    self.synchronize_pubd_core()
    self.synchronize_rpkid_deleted_core()


  @django.db.transaction.atomic
  def synchronize_ca(self, ca = None, poke = False):
    """
    Synchronize one CA.  Most commands which modify a CA should call
    this.  CA to synchronize defaults to the current resource CA.
    """

    if ca is None:
      ca = self.resource_ca
    self.synchronize_rpkid_one_ca_core(ca, poke)


  @django.db.transaction.atomic
  def synchronize_deleted_ca(self):
    """
    Delete CAs which are present in rpkid's database but not in the
    IRDB.
    """

    self.synchronize_rpkid_deleted_core()


  @django.db.transaction.atomic
  def synchronize_pubd(self):
    """
    Synchronize pubd.  Most commands which modify pubd should call this.
    """

    self.synchronize_pubd_core()


  def synchronize_rpkid_one_ca_core(self, ca, poke = False):
    """
    Synchronize one CA.  This is the core synchronization code.  Don't
    call this directly, instead call one of the methods that calls
    this inside a Django commit wrapper.

    This method configures rpkid with data built up by the other
    commands in this program.  Most commands which modify IRDB values
    related to rpkid should call this when they're done.

    If poke is True, we append a left-right run_now operation for this
    CA to the end of whatever other commands this method generates.
    """

    # We can use a single BSC for everything -- except BSC key
    # rollovers.  Drive off that bridge when we get to it.

    bsc_handle = "bsc"

    # A default RPKI CRL cycle time of six hours seems sane.  One
    # might make a case for a day instead, but we've been running with
    # six hours for a while now and haven't seen a lot of whining.

    self_crl_interval = self.cfg.getint("self_crl_interval", 6 * 60 * 60, section = myrpki_section)

    # regen_margin now just controls how long before RPKI certificate
    # expiration we should regenerate; it used to control the interval
    # before RPKI CRL staleness at which to regenerate the CRL, but
    # using the same timer value for both of these is hopeless.
    #
    # A default regeneration margin of two weeks gives enough time for
    # humans to react.  We add a two hour fudge factor in the hope
    # that this will regenerate certificates just *before* the
    # companion cron job warns of impending doom.

    self_regen_margin = self.cfg.getint("self_regen_margin", 14 * 24 * 60 * 60 + 2 * 60, section = myrpki_section)

    # See what rpkid already has on file for this entity.

    q_msg = self._compose_left_right_query()
    SubElement(q_msg, rpki.left_right.tag_self,       action = "get",  self_handle = ca.handle)
    SubElement(q_msg, rpki.left_right.tag_bsc,        action = "list", self_handle = ca.handle)
    SubElement(q_msg, rpki.left_right.tag_repository, action = "list", self_handle = ca.handle)
    SubElement(q_msg, rpki.left_right.tag_parent,     action = "list", self_handle = ca.handle)
    SubElement(q_msg, rpki.left_right.tag_child,      action = "list", self_handle = ca.handle)

    r_msg = self.call_rpkid(q_msg, suppress_error_check = True)

    if r_msg[0].tag == rpki.left_right.tag_self:
      self.check_error_report(r_msg)
      self_pdu = r_msg[0]
    else:
      self_pdu = None

    bsc_pdus        = dict((r_pdu.get("bsc_handle"), r_pdu)
                           for r_pdu in r_msg
                           if r_pdu.tag == rpki.left_right.tag_bsc)
    repository_pdus = dict((r_pdu.get("repository_handle"), r_pdu)
                           for r_pdu in r_msg
                           if r_pdu.tag == rpki.left_right.tag_repository)
    parent_pdus     = dict((r_pdu.get("parent_handle"), r_pdu)
                           for r_pdu in r_msg
                           if r_pdu.tag == rpki.left_right.tag_parent)
    child_pdus      = dict((r_pdu.get("child_handle"), r_pdu)
                           for r_pdu in r_msg
                           if r_pdu.tag == rpki.left_right.tag_child)

    q_msg = self._compose_left_right_query()

    self_cert, created = rpki.irdb.models.HostedCA.objects.get_or_certify(
      issuer = self.server_ca,
      hosted = ca)

    # There should be exactly one <self/> object per hosted entity, by definition

    if (self_pdu is None or
        self_pdu.get("crl_interval") != str(self_crl_interval) or
        self_pdu.get("regen_margin") != str(self_regen_margin) or
        self_pdu.findtext(rpki.left_right.tag_bpki_cert, "").decode("base64") != self_cert.certificate.get_DER()):
      q_pdu = SubElement(q_msg, rpki.left_right.tag_self,
                         action = "create" if self_pdu is None else "set",
                         tag = "self",
                         self_handle = ca.handle,
                         crl_interval = str(self_crl_interval),
                         regen_margin = str(self_regen_margin))
      SubElement(q_pdu, rpki.left_right.tag_bpki_cert).text = ca.certificate.get_Base64()

    # In general we only need one <bsc/> per <self/>.  BSC objects
    # are a little unusual in that the keypair and PKCS #10
    # subelement are generated by rpkid, so complete setup requires
    # two round trips.

    bsc_pdu = bsc_pdus.pop(bsc_handle, None)

    if bsc_pdu is None or bsc_pdu.find(rpki.left_right.tag_pkcs10_request) is None:
      SubElement(q_msg, rpki.left_right.tag_bsc,
                 action = "create" if bsc_pdu is None else "set",
                 tag = "bsc",
                 self_handle = ca.handle,
                 bsc_handle = bsc_handle,
                 generate_keypair = "yes")

    for bsc_handle in bsc_pdus:
      SubElement(q_msg, rpki.left_right.tag_bsc,
                 action = "destroy", self_handle = ca.handle, bsc_handle = bsc_handle)

    # If we've already got actions queued up, run them now, so we
    # can finish setting up the BSC before anything tries to use it.

    if len(q_msg) > 0:
      SubElement(q_msg, rpki.left_right.tag_bsc, action = "list", tag = "bsc", self_handle = ca.handle)
      r_msg = self.call_rpkid(q_msg)
      bsc_pdus = dict((r_pdu.get("bsc_handle"), r_pdu)
                      for r_pdu in r_msg
                      if r_pdu.tag == rpki.left_right.tag_bsc and r_pdu.get("action") == "list")
      bsc_pdu = bsc_pdus.pop(bsc_handle, None)

    q_msg = self._compose_left_right_query()

    bsc_pkcs10 = bsc_pdu.find(rpki.left_right.tag_pkcs10_request)
    assert bsc_pkcs10 is not None

    bsc, created = rpki.irdb.models.BSC.objects.get_or_certify(
      issuer = ca,
      handle = bsc_handle,
      pkcs10 = rpki.x509.PKCS10(Base64 = bsc_pkcs10.text))

    if (bsc_pdu.findtext(rpki.left_right.tag_signing_cert,     "").decode("base64") != bsc.certificate.get_DER() or
        bsc_pdu.findtext(rpki.left_right.tag_signing_cert_crl, "").decode("base64") != ca.latest_crl.get_DER()):
      q_pdu = SubElement(q_msg, rpki.left_right.tag_bsc,
                         action = "set",
                         tag = "bsc",
                         self_handle = ca.handle,
                         bsc_handle = bsc_handle)
      SubElement(q_pdu, rpki.left_right.tag_signing_cert).text = bsc.certificate.get_Base64()
      SubElement(q_pdu, rpki.left_right.tag_signing_cert_crl).text = ca.latest_crl.get_Base64()

    # At present we need one <repository/> per <parent/>, not because
    # rpkid requires that, but because pubd does.  pubd probably should
    # be fixed to support a single client allowed to update multiple
    # trees, but for the moment the easiest way forward is just to
    # enforce a 1:1 mapping between <parent/> and <repository/> objects

    for repository in ca.repositories.all():

      repository_pdu = repository_pdus.pop(repository.handle, None)

      if (repository_pdu is None or
          repository_pdu.get("bsc_handle") != bsc_handle or
          repository_pdu.get("peer_contact_uri") != repository.service_uri or
          repository_pdu.findtext(rpki.left_right.tag_bpki_cert, "").decode("base64") != repository.certificate.get_DER()):
        q_pdu = SubElement(q_msg, rpki.left_right.tag_repository,
                           action = "create" if repository_pdu is None else "set",
                           tag = repository.handle,
                           self_handle = ca.handle,
                           repository_handle = repository.handle,
                           bsc_handle = bsc_handle,
                           peer_contact_uri = repository.service_uri)
        SubElement(q_pdu, rpki.left_right.tag_bpki_cert).text = repository.certificate.get_Base64()

    for repository_handle in repository_pdus:
      SubElement(q_msg, rpki.left_right.tag_repository, action = "destroy",
                 self_handle = ca.handle, repository_handle = repository_handle)

    # <parent/> setup code currently assumes 1:1 mapping between
    # <repository/> and <parent/>, and further assumes that the handles
    # for an associated pair are the identical (that is:
    # parent.repository_handle == parent.parent_handle).
    #
    # If no such repository exists, our choices are to ignore the
    # parent entry or throw an error.  For now, we ignore the parent.

    for parent in ca.parents.all():

      try:
        parent_pdu = parent_pdus.pop(parent.handle, None)

        if (parent_pdu is None or
            parent_pdu.get("bsc_handle") != bsc_handle or
            parent_pdu.get("repository_handle") != parent.handle or
            parent_pdu.get("peer_contact_uri") != parent.service_uri or
            parent_pdu.get("sia_base") != parent.repository.sia_base or
            parent_pdu.get("sender_name") != parent.child_handle or
            parent_pdu.get("recipient_name") != parent.parent_handle or
            parent_pdu.findtext(rpki.left_right.tag_bpki_cms_cert, "").decode("base64") != parent.certificate.get_DER()):
          q_pdu = SubElement(q_msg, rpki.left_right.tag_parent,
                             action = "create" if parent_pdu is None else "set",
                             tag = parent.handle,
                             self_handle = ca.handle,
                             parent_handle = parent.handle,
                             bsc_handle = bsc_handle,
                             repository_handle = parent.handle,
                             peer_contact_uri = parent.service_uri,
                             sia_base = parent.repository.sia_base,
                             sender_name = parent.child_handle,
                             recipient_name = parent.parent_handle)
          SubElement(q_pdu, rpki.left_right.tag_bpki_cms_cert).text = parent.certificate.get_Base64()

      except rpki.irdb.models.Repository.DoesNotExist:
        pass

    try:

      parent_pdu = parent_pdus.pop(ca.handle, None)

      if (parent_pdu is None or
          parent_pdu.get("bsc_handle") != bsc_handle or
          parent_pdu.get("repository_handle") != ca.handle or
          parent_pdu.get("peer_contact_uri") != ca.rootd.service_uri or
          parent_pdu.get("sia_base") != ca.rootd.repository.sia_base or
          parent_pdu.get("sender_name") != ca.handle or
          parent_pdu.get("recipient_name") != ca.handle or
          parent_pdu.findtext(rpki.left_right.tag_bpki_cms_cert).decode("base64") != ca.rootd.certificate.get_DER()):
        q_pdu = SubElement(q_msg, rpki.left_right.tag_parent,
                           action = "create" if parent_pdu is None else "set",
                           tag = ca.handle,
                           self_handle = ca.handle,
                           parent_handle = ca.handle,
                           bsc_handle = bsc_handle,
                           repository_handle = ca.handle,
                           peer_contact_uri = ca.rootd.service_uri,
                           sia_base = ca.rootd.repository.sia_base,
                           sender_name = ca.handle,
                           recipient_name = ca.handle)
        SubElement(q_pdu, rpki.left_right.tag_bpki_cms_cert).text = ca.rootd.certificate.get_Base64()

    except rpki.irdb.models.Rootd.DoesNotExist:
      pass

    for parent_handle in parent_pdus:
      SubElement(q_msg, rpki.left_right.tag_parent, action = "destroy",
                 self_handle = ca.handle, parent_handle = parent_handle)

    # Children are simpler than parents, because they call us, so no URL
    # to construct and figuring out what certificate to use is their
    # problem, not ours.

    for child in ca.children.all():

      child_pdu = child_pdus.pop(child.handle, None)

      if (child_pdu is None or
          child_pdu.get("bsc_handle") != bsc_handle or
          child_pdu.findtext(rpki.left_right.tag_bpki_cert).decode("base64") != child.certificate.get_DER()):
        q_pdu = SubElement(q_msg, rpki.left_right.tag_child,
                           action = "create" if child_pdu is None else "set",
                           tag = child.handle,
                           self_handle = ca.handle,
                           child_handle = child.handle,
                           bsc_handle = bsc_handle)
        SubElement(q_pdu, rpki.left_right.tag_bpki_cert).text = child.certificate.get_Base64()

    for child_handle in child_pdus:
      SubElement(q_msg, rpki.left_right.tag_child, action = "destroy",
                 self_handle = ca.handle, child_handle = child_handle)

    # If caller wants us to poke rpkid, add that to the very end of the message

    if poke:
      SubElement(q_msg, rpki.left_right.tag_self, action = "set", self_handle = ca.handle, run_now = "yes")

    # If we changed anything, ship updates off to rpkid.

    if len(q_msg) > 0:
      self.call_rpkid(q_msg)


  def synchronize_pubd_core(self):
    """
    Configure pubd with data built up by the other commands in this
    program.  This is the core synchronization code.  Don't call this
    directly, instead call a methods that calls this inside a Django
    commit wrapper.

    This method configures pubd with data built up by the other
    commands in this program.  Commands which modify IRDB fields
    related to pubd should call this when they're done.
    """

    # If we're not running pubd, the rest of this is a waste of time

    if not self.run_pubd:
      return

    # See what pubd already has on file

    q_msg = self._compose_publication_control_query()
    SubElement(q_msg, rpki.publication_control.tag_client, action = "list")
    r_msg = self.call_pubd(q_msg)
    client_pdus = dict((r_pdu.get("client_handle"), r_pdu)
                       for r_pdu in r_msg)

    # Check all clients

    q_msg = self._compose_publication_control_query()

    for client in self.server_ca.clients.all():

      client_pdu = client_pdus.pop(client.handle, None)

      if (client_pdu is None or
          client_pdu.get("base_uri") != client.sia_base or
          client_pdu.findtext(rpki.publication_control.tag_bpki_cert, "").decode("base64") != client.certificate.get_DER()):
        q_pdu = SubElement(q_msg, rpki.publication_control.tag_client,
                           action = "create" if client_pdu is None else "set",
                           client_handle = client.handle,
                           base_uri = client.sia_base)
        SubElement(q_pdu, rpki.publication_control.tag_bpki_cert).text = client.certificate.get_Base64()

    # rootd instances are also a weird sort of client

    for rootd in rpki.irdb.models.Rootd.objects.all():

      client_handle = rootd.issuer.handle + "-root"
      client_pdu = client_pdus.pop(client_handle, None)
      sia_base = "rsync://%s/%s/%s/" % (self.rsync_server, self.rsync_module, client_handle)

      if (client_pdu is None or
          client_pdu.get("base_uri") != sia_base or
          client_pdu.findtext(rpki.publication_control.tag_bpki_cert, "").decode("base64") != rootd.issuer.certificate.get_DER()):
        q_pdu = SubElement(q_msg, rpki.publication_control.tag_client,
                           action = "create" if client_pdu is None else "set",
                           client_handle = client_handle,
                           base_uri = sia_base)
        SubElement(q_pdu, rpki.publication_control.tag_bpki_cert).text = rootd.issuer.certificate.get_Base64()

    # Delete any unknown clients

    for client_handle in client_pdus:
      SubElement(q_msg, rpki.publication_control.tag_client, action = "destroy", client_handle = client_handle)

    # If we changed anything, ship updates off to pubd

    if len(q_msg) > 0:
      self.call_pubd(q_msg)


  def synchronize_rpkid_deleted_core(self):
    """
    Remove any <self/> objects present in rpkid's database but not
    present in the IRDB.  This is the core synchronization code.
    Don't call this directly, instead call a methods that calls this
    inside a Django commit wrapper.
    """

    q_msg = self._compose_left_right_query()
    SubElement(q_msg, rpki.left_right.tag_self, action = "list")
    self.call_rpkid(q_msg)

    self_handles = set(s.get("self_handle") for s in r_msg)
    ca_handles   = set(ca.handle for ca in rpki.irdb.models.ResourceHolderCA.objects.all())
    assert ca_handles <= self_handles

    q_msg = self._compose_left_right_query()
    for handle in (self_handles - ca_handles):
      SubElement(q_msg, rpki.left_right.tag_self, action = "destroy", self_handle = handle)

    if len(q_msg) > 0:
      self.call_rpkid(q_msg)


  @django.db.transaction.atomic
  def add_ee_certificate_request(self, pkcs10, resources):
    """
    Check a PKCS #10 request to see if it complies with the
    specification for a RPKI EE certificate; if it does, add an
    EECertificateRequest for it to the IRDB.

    Not yet sure what we want for update and delete semantics here, so
    for the moment this is straight addition.  See methods like
    .load_asns() and .load_prefixes() for other strategies.
    """

    pkcs10.check_valid_request_ee()
    ee_request = self.resource_ca.ee_certificate_requests.create(
      pkcs10      = pkcs10,
      gski        = pkcs10.gSKI(),
      valid_until = resources.valid_until)
    for r in resources.asn:
      ee_request.asns.create(start_as = str(r.min), end_as = str(r.max))
    for r in resources.v4:
      ee_request.address_ranges.create(start_ip = str(r.min), end_ip = str(r.max), version = 4)
    for r in resources.v6:
      ee_request.address_ranges.create(start_ip = str(r.min), end_ip = str(r.max), version = 6)


  @django.db.transaction.atomic
  def add_router_certificate_request(self, router_certificate_request_xml, valid_until = None):
    """
    Read XML file containing one or more router certificate requests,
    attempt to add request(s) to IRDB.

    Check each PKCS #10 request to see if it complies with the
    specification for a router certificate; if it does, create an EE
    certificate request for it along with the ASN resources and
    router-ID supplied in the XML.
    """

    xml = ElementTree(file = router_certificate_request_xml).getroot()
    rpki.relaxng.router_certificate.assertValid(xml)

    for req in xml.getiterator(routercert_xmlns + "router_certificate_request"):

      pkcs10 = rpki.x509.PKCS10(Base64 = req.text)
      router_id = long(req.get("router_id"))
      asns = rpki.resource_set.resource_set_as(req.get("asn"))
      if not valid_until:
        valid_until = req.get("valid_until")

      if valid_until and isinstance(valid_until, (str, unicode)):
        valid_until = rpki.sundial.datetime.fromXMLtime(valid_until)

      if not valid_until:
        valid_until = rpki.sundial.now() + rpki.sundial.timedelta(days = 365)
      elif valid_until < rpki.sundial.now():
        raise PastExpiration("Specified expiration date %s has already passed" % valid_until)

      pkcs10.check_valid_request_router()

      cn = "ROUTER-%08x" % asns[0].min
      sn = "%08x" % router_id

      ee_request = self.resource_ca.ee_certificate_requests.create(
        pkcs10      = pkcs10,
        gski        = pkcs10.gSKI(),
        valid_until = valid_until,
        cn          = cn,
        sn          = sn,
        eku         = rpki.oids.id_kp_bgpsec_router)

      for r in asns:
        ee_request.asns.create(start_as = str(r.min), end_as = str(r.max))


  @django.db.transaction.atomic
  def delete_router_certificate_request(self, gski):
    """
    Delete a router certificate request from this RPKI entity.
    """

    self.resource_ca.ee_certificate_requests.get(gski = gski).delete()
