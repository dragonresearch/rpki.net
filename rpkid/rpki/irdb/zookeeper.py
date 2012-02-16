"""
Management code for the IRDB.

$Id$

Copyright (C) 2009--2012  Internet Systems Consortium ("ISC")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import subprocess
import csv
import re
import os
import getopt
import sys
import base64
import time
import glob
import copy
import warnings
import rpki.config
import rpki.cli
import rpki.sundial
import rpki.log
import rpki.oids
import rpki.http
import rpki.resource_set
import rpki.relaxng
import rpki.exceptions
import rpki.left_right
import rpki.x509
import rpki.async
import rpki.irdb
import django.db.transaction

from lxml.etree import (Element, SubElement, ElementTree,
                        fromstring as ElementFromString,
                        tostring   as ElementToString)

from rpki.csv_utils import (csv_reader, csv_writer, BadCSVSyntax)



# XML namespace and protocol version for OOB setup protocol.  The name
# is historical and may change before we propose this as the basis for
# a standard.

myrpki_namespace      = "http://www.hactrn.net/uris/rpki/myrpki/"
myrpki_version        = "2"
myrpki_namespaceQName = "{" + myrpki_namespace + "}"

myrpki_section = "myrpki"
irdbd_section  = "irdbd"
rpkid_section  = "rpkid"
pubd_section   = "pubd"
rootd_section  = "rootd"

# A whole lot of exceptions

class MissingHandle(Exception):         "Missing handle"
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
  """

  def __init__(self, logstream = None):
    self.wrote = set()
    self.logstream = logstream

  def __call__(self, filename, obj):
    filename = os.path.realpath(filename)
    if filename in self.wrote:
      return
    tempname = filename
    if not filename.startswith("/dev/"):
      tempname += ".%s.tmp" % os.getpid()
    mode = 0400 if filename.endswith(".key") else 0444
    if self.logstream is not None:
      self.logstream.write("Writing %s\n" % filename)
    f = os.fdopen(os.open(tempname, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode), "w")
    f.write(obj.get_PEM())
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
    if i.tag.startswith(myrpki_namespaceQName):
      i.tag = i.tag[len(myrpki_namespaceQName):]
    else:
      raise BadXMLMessage, "XML tag %r is not in namespace %r" % (i.tag, myrpki_namespace)
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
        i.tag = myrpki_namespaceQName + i.tag
      assert i.tag.startswith(myrpki_namespaceQName)
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



class Zookeeper(object):

  ## @var show_xml
  # Whether to show XML for debugging

  show_xml = False

  def __init__(self, cfg = None, handle = None, logstream = None):

    if cfg is None:
      cfg = rpki.config.parser()

    if handle is None:
      handle = cfg.get("handle", section = myrpki_section)

    self.cfg = cfg

    self.logstream = logstream

    self.run_rpkid = cfg.getboolean("run_rpkid", section = myrpki_section)
    self.run_pubd  = cfg.getboolean("run_pubd", section = myrpki_section)
    self.run_rootd = cfg.getboolean("run_rootd", section = myrpki_section)

    if self.run_rootd and (not self.run_pubd or not self.run_rpkid):
      raise CantRunRootd, "Can't run rootd unless also running rpkid and pubd"

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
    self.handle= handle


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

    assert self.handle is not None
    try:
      return rpki.irdb.ResourceHolderCA.objects.get(handle = self.handle)
    except rpki.irdb.ResourceHolderCA.DoesNotExist:
      return None


  @property
  def server_ca(self):
    """
    Get ServerCA object.
    """

    try:
      return rpki.irdb.ServerCA.objects.get()
    except rpki.irdb.ServerCA.DoesNotExist:
      return None


  @django.db.transaction.commit_on_success
  def initialize(self):
    """
    Initialize an RPKI installation.  Reads the configuration file,
    creates the BPKI and EntityDB directories, generates the initial
    BPKI certificates, and creates an XML file describing the
    resource-holding aspect of this RPKI installation.
    """

    resource_ca, created = rpki.irdb.ResourceHolderCA.objects.get_or_certify(handle = self.handle)

    if self.run_rpkid or self.run_pubd:
      server_ca, created = rpki.irdb.ServerCA.objects.get_or_certify()
      rpki.irdb.ServerEE.objects.get_or_certify(issuer = server_ca, purpose = "irbe")

    if self.run_rpkid:
      rpki.irdb.ServerEE.objects.get_or_certify(issuer = server_ca, purpose = "rpkid")
      rpki.irdb.ServerEE.objects.get_or_certify(issuer = server_ca, purpose = "irdbd")

    if self.run_pubd:
      rpki.irdb.ServerEE.objects.get_or_certify(issuer = server_ca, purpose = "pubd")

    return self.generate_identity()


  def generate_identity(self):
    """
    Generate identity XML.  Broken out of .initialize() because it's
    easier for the GUI this way.
    """

    e = Element("identity", handle = self.handle)
    B64Element(e, "bpki_ta", self.resource_ca.certificate)
    return etree_wrapper(e, msg = 'This is the "identity" file you will need to send to your parent')


  @django.db.transaction.commit_on_success
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


  @django.db.transaction.commit_on_success
  def configure_rootd(self):

    assert self.run_rpkid and self.run_pubd and self.run_rootd

    rpki.irdb.Rootd.objects.get_or_certify(
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

    except rpki.irdb.Repository.DoesNotExist:
      e = Element("repository", type = "offer", handle = self.handle, parent_handle = self.handle)
      B64Element(e, "bpki_client_ta", self.resource_ca.certificate)
      return etree_wrapper(e, msg = 'This is the "repository offer" file for you to use if you want to publish in your own repository')


  def write_bpki_files(self):
    """
    Write out BPKI certificate, key, and CRL files for daemons that
    need them.
    """

    writer = PEM_writer()

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
      rootd = rpki.irdb.ResourceHolderCA.objects.get(handle = self.cfg.get("handle", section = myrpki_section)).rootd
      writer(self.cfg.get("bpki-ta",         section = rootd_section), self.server_ca.certificate)
      writer(self.cfg.get("rootd-bpki-crl",  section = rootd_section), self.server_ca.latest_crl)
      writer(self.cfg.get("rootd-bpki-key",  section = rootd_section), rootd.private_key)
      writer(self.cfg.get("rootd-bpki-cert", section = rootd_section), rootd.certificate)
      writer(self.cfg.get("child-bpki-cert", section = rootd_section), rootd.issuer.certificate)


  @django.db.transaction.commit_on_success
  def update_bpki(self):
    """
    Update BPKI certificates.  Assumes an existing RPKI installation.

    Basic plan here is to reissue all BPKI certificates we can, right
    now.  In the long run we might want to be more clever about only
    touching ones that need maintenance, but this will do for a start.

    We also reissue CRLs for all CAs.

    Most likely this should be run under cron.
    """

    for model in (rpki.irdb.ServerCA,
                  rpki.irdb.ResourceHolderCA,
                  rpki.irdb.ServerEE,
                  rpki.irdb.Referral,
                  rpki.irdb.Rootd,
                  rpki.irdb.HostedCA,
                  rpki.irdb.BSC,
                  rpki.irdb.Child,
                  rpki.irdb.Parent,
                  rpki.irdb.Client,
                  rpki.irdb.Repository):
      for obj in model.objects.all():
        self.log("Regenerating certificate %s" % obj.certificate.getSubject())
        obj.avow()

    self.log("Regenerating Server CRL")
    self.server_ca.generate_crl()
    
    for ca in rpki.irdb.ResourceHolderCA.objects.all():
      self.log("Regenerating CRL for %s" % ca.handle)
      ca.generate_crl()


  @django.db.transaction.commit_on_success
  def configure_child(self, filename, child_handle = None):
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

    valid_until = rpki.sundial.now() + rpki.sundial.timedelta(days = 365)

    self.log("Child calls itself %r, we call it %r" % (c.get("handle"), child_handle))

    child, created = rpki.irdb.Child.objects.get_or_certify(
      issuer = self.resource_ca,
      handle = child_handle,
      ta = rpki.x509.X509(Base64 = c.findtext("bpki_ta")),
      valid_until = valid_until)

    return self.generate_parental_response(child), child_handle


  @django.db.transaction.commit_on_success
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
    except rpki.irdb.Repository.DoesNotExist:
      repo = None

    if repo is None:
      self.log("Couldn't find any usable repositories, not giving referral")

    elif repo.handle == self.handle:
      SubElement(e, "repository", type = "offer")

    else:
      proposed_sia_base = repo.sia_base + child.handle + "/"
      referral_cert, created = rpki.irdb.Referral.objects.get_or_certify(issuer = self.resource_ca)
      auth = rpki.x509.SignedReferral()
      auth.set_content(B64Element(None, myrpki_namespaceQName + "referral", child.ta,
                                  version = myrpki_version,
                                  authorized_sia_base = proposed_sia_base))
      auth.schema_check()
      auth.sign(referral_cert.private_key, referral_cert.certificate, self.resource_ca.latest_crl)

      r = SubElement(e, "repository", type = "referral")
      B64Element(r, "authorization", auth, referrer = repo.client_handle)
      SubElement(r, "contact_info")

    return etree_wrapper(e, msg = "Send this file back to the child you just configured")


  @django.db.transaction.commit_on_success
  def delete_child(self, child_handle):
    """
    Delete a child of this RPKI entity.
    """

    assert child_handle is not None
    try:
      self.resource_ca.children.get(handle = child_handle).delete()
    except rpki.irdb.Child.DoesNotExist:
      self.log("No such child \"%s\"" % arg)


  @django.db.transaction.commit_on_success
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

    parent, created = rpki.irdb.Parent.objects.get_or_certify(
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


  @django.db.transaction.commit_on_success
  def delete_parent(self, parent_handle):
    """
    Delete a parent of this RPKI entity.
    """

    assert parent_handle is not None
    try:
      self.resource_ca.parents.get(handle = parent_handle).delete()
    except rpki.irdb.Parent.DoesNotExist:
      self.log("No such parent \"%s\"" % arg)


  @django.db.transaction.commit_on_success
  def configure_publication_client(self, filename, sia_base = None):
    """
    Configure publication server to know about a new client, given the
    client's request-for-service message as input.  Reads the client's
    request for service, cross-certifies the client's BPKI data, and
    generates a response message containing the repository's BPKI data
    and service URI.
    """

    client = etree_read(filename)

    client_ta = rpki.x509.X509(Base64 = client.findtext("bpki_client_ta"))

    if sia_base is None and client.get("handle") == self.handle and self.resource_ca.certificate == client_ta:
      self.log("This looks like self-hosted publication")
      sia_base = "rsync://%s/%s/%s/" % (self.rsync_server, self.rsync_module, self.handle)

    if sia_base is None and client.get("type") == "referral":
      self.log("This looks like a referral, checking")
      try:
        auth = client.find("authorization")
        referrer = self.server_ca.clients.get(handle = auth.get("referrer"))
        referral_cms = rpki.x509.SignedReferral(Base64 = auth.text)
        referral_xml = referral_cms.unwrap(ta = (referrer.certificate, self.server_ca.certificate))
        if rpki.x509.X509(Base64 = referral_xml.text) != client_ta:
          raise BadXMLMessage, "Referral trust anchor does not match"
        sia_base = referral_xml.get("authorized_sia_base")
      except rpki.irdb.Client.DoesNotExist:
        self.log("We have no record of the client (%s) alleged to have made this referral" % auth.get("referrer"))

    if sia_base is None and client.get("type") == "offer" and client.get("parent_handle") == self.handle:
      self.log("This looks like an offer, client claims to be our child, checking")
      try:
        child = self.resource_ca.children.get(ta = client_ta)
      except rpki.irdb.Child.DoesNotExist:
        self.log("Can't find a child matching this client")
      else:
        sia_base = "rsync://%s/%s/%s/%s/" % (self.rsync_server, self.rsync_module,
                                             self.handle, client.get("handle"))

    # If we still haven't figured out what to do with this client, it
    # gets a top-level tree of its own, no attempt at nesting.

    if sia_base is None:
      self.log("Don't know where to nest this client, defaulting to top-level")
      sia_base = "rsync://%s/%s/%s/" % (self.rsync_server, self.rsync_module, client.get("handle"))
      
    if not sia_base.startswith("rsync://"):
      raise BadXMLMessage, "Malformed sia_base parameter %r, should start with 'rsync://'" % sia_base

    client_handle = "/".join(sia_base.rstrip("/").split("/")[4:])

    parent_handle = client.get("parent_handle")

    self.log("Client calls itself %r, we call it %r" % (client.get("handle"), client_handle))
    self.log("Client says its parent handle is %r" % parent_handle)

    client, created = rpki.irdb.Client.objects.get_or_certify(
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


  @django.db.transaction.commit_on_success
  def delete_publication_client(self, client_handle):
    """
    Delete a publication client of this RPKI entity.
    """

    assert client_handle is not None
    try:
      self.server_ca.clients.get(handle = client_handle).delete()
    except rpki.irdb.Client.DoesNotExist:
      self.log("No such client \"%s\"" % arg)


  @django.db.transaction.commit_on_success
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

    except (rpki.irdb.Parent.DoesNotExist, rpki.irdb.Rootd.DoesNotExist):
      self.log("Could not find parent %r in our database" % parent_handle)

    else:
      rpki.irdb.Repository.objects.get_or_certify(
        issuer = self.resource_ca,
        handle = parent_handle,
        client_handle = r.get("client_handle"),
        service_uri = r.get("service_uri"),
        sia_base = r.get("sia_base"),
        ta = rpki.x509.X509(Base64 = r.findtext("bpki_server_ta")),
        turtle = turtle)


  @django.db.transaction.commit_on_success
  def delete_repository(self, repository_handle):
    """
    Delete a repository of this RPKI entity.
    """

    assert repository_handle is not None
    try:
      self.resource_ca.repositories.get(handle = arg).delete()
    except rpki.irdb.Repository.DoesNotExist:
      self.log("No such repository \"%s\"" % arg)


  @django.db.transaction.commit_on_success
  def renew_children(self, child_handle, valid_until = None):
    """
    Update validity period for one child entity or, if child_handle is
    None, for all child entities.
    """

    if child_handle is None:
      children = self.resource_ca.children
    else:
      children = self.resource_ca.children.filter(handle = child_handle)

    if valid_until is None:
      valid_until = rpki.sundial.now() + rpki.sundial.timedelta(days = 365)
    else:
      valid_until = rpki.sundial.fromXMLtime(valid_until)
      if valid_until < rpki.sundial.now():
        raise PastExpiration, "Specified new expiration time %s has passed" % valid_until

    self.log("New validity date %s" % valid_until)

    for child in children:
      child.valid_until = valid_until
      child.save()


  @django.db.transaction.commit_on_success
  def load_prefixes(self, filename):
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
        child = self.resource_ca.children.get(handle = handle)
        for prefix in rset(",".join(prefixes)):
          obj, created = rpki.irdb.ChildNet.objects.get_or_create(
            child    = child,
            start_ip = str(prefix.min),
            end_ip   = str(prefix.max),
            version  = version)
          primary_keys.append(obj.pk)

    q = rpki.irdb.ChildNet.objects
    q = q.filter(child__issuer__exact = self.resource_ca)
    q = q.exclude(pk__in = primary_keys)
    q.delete()


  @django.db.transaction.commit_on_success
  def load_asns(self, filename):
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
      child = self.resource_ca.children.get(handle = handle)
      for asn in rpki.resource_set.resource_set_as(",".join(asns)):
        obj, created = rpki.irdb.ChildASN.objects.get_or_create(
          child    = child,
          start_as = str(asn.min),
          end_as   = str(asn.max))
        primary_keys.append(obj.pk)

    q = rpki.irdb.ChildASN.objects
    q = q.filter(child__issuer__exact = self.resource_ca)
    q = q.exclude(pk__in = primary_keys)
    q.delete()


  @django.db.transaction.commit_on_success
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


  def call_rpkid(self, *pdus):
    """
    Issue a call to rpkid, return result.

    Implementation is a little silly, constructs a wrapper object,
    invokes it once, then throws it away.  Hard to do better without
    rewriting a bit of the HTTP code, as we want to be sure we're
    using the current BPKI certificate and key objects.
    """

    url = "http://%s:%s/left-right" % (
      self.cfg.get("rpkid_server_host", section = myrpki_section),
      self.cfg.get("rpkid_server_port", section = myrpki_section))

    rpkid = self.server_ca.ee_certificates.get(purpose = "rpkid")
    irbe  = self.server_ca.ee_certificates.get(purpose = "irbe")

    call_rpkid = rpki.async.sync_wrapper(rpki.http.caller(
      proto       = rpki.left_right,
      client_key  = irbe.private_key,
      client_cert = irbe.certificate,
      server_ta   = self.server_ca.certificate,
      server_cert = rpkid.certificate,
      url         = url,
      debug       = self.show_xml))

    return call_rpkid(*pdus)


  def run_rpkid_now(self):
    """
    Poke rpkid to immediately run the cron job for the current handle.

    This method is used by the gui when a user has changed something in the
    IRDB (ghostbuster, roa) which does not require a full synchronize() call,
    to force the object to be immediately issued.
    """

    self.call_rpkid(rpki.left_right.self_elt.make_pdu(
      action = "set", self_handle = self.handle, run_now = "yes"))


  def call_pubd(self, *pdus):
    """
    Issue a call to pubd, return result.

    Implementation is a little silly, constructs a wrapper object,
    invokes it once, then throws it away.  Hard to do better without
    rewriting a bit of the HTTP code, as we want to be sure we're
    using the current BPKI certificate and key objects.
    """

    url = "http://%s:%s/control" % (
      self.cfg.get("pubd_server_host", section = myrpki_section),
      self.cfg.get("pubd_server_port", section = myrpki_section))

    pubd = self.server_ca.ee_certificates.get(purpose = "pubd")
    irbe = self.server_ca.ee_certificates.get(purpose = "irbe")

    call_pubd = rpki.async.sync_wrapper(rpki.http.caller(
      proto       = rpki.publication,
      client_key  = irbe.private_key,
      client_cert = irbe.certificate,
      server_ta   = self.server_ca.certificate,
      server_cert = pubd.certificate,
      url         = url,
      debug       = self.show_xml))

    return call_pubd(*pdus)


  def check_error_report(self, pdus):
    """
    Check a response from rpkid or pubd for error_report PDUs, log and
    throw exceptions as needed.
    """

    if any(isinstance(pdu, (rpki.left_right.report_error_elt, rpki.publication.report_error_elt)) for pdu in pdus):
      for pdu in pdus:
        if isinstance(pdu, rpki.left_right.report_error_elt):
          self.log("rpkid reported failure: %s" % pdu.error_code)
        elif isinstance(pdu, rpki.publication.report_error_elt):
          self.log("pubd reported failure: %s" % pdu.error_code)
        else:
          continue
        if pdu.error_text:
          self.log(pdu.error_text)
      raise CouldntTalkToDaemon


  @django.db.transaction.commit_on_success
  def synchronize(self, *handles_to_poke):
    """
    Configure RPKI daemons with the data built up by the other
    commands in this program.  Most commands which modify the IRDB
    should call this when they're done.

    Any arguments given are handles to be sent to rpkid at the end of
    the synchronization run with a <self run_now="yes"/> operation.
    """

    # We can use a single BSC for everything -- except BSC key
    # rollovers.  Drive off that bridge when we get to it.

    bsc_handle = "bsc"

    # Default values for CRL parameters are low, for testing.  Not
    # quite as low as they once were, too much expired CRL whining.

    self_crl_interval = self.cfg.getint("self_crl_interval", 2 * 60 * 60,
                                        section = myrpki_section)
    self_regen_margin = self.cfg.getint("self_regen_margin", self_crl_interval / 4,
                                        section = myrpki_section)

    # Make sure that pubd's BPKI CRL is up to date.

    if self.run_pubd:
      self.call_pubd(rpki.publication.config_elt.make_pdu(
        action = "set",
        bpki_crl = self.server_ca.latest_crl))

    for ca in rpki.irdb.ResourceHolderCA.objects.all():

      # See what rpkid and pubd already have on file for this entity.

      if self.run_pubd:
        pubd_reply = self.call_pubd(rpki.publication.client_elt.make_pdu(action = "list"))
        client_pdus = dict((x.client_handle, x) for x in pubd_reply if isinstance(x, rpki.publication.client_elt))

      rpkid_reply = self.call_rpkid(
        rpki.left_right.self_elt.make_pdu(      action = "get",  tag = "self",       self_handle = ca.handle),
        rpki.left_right.bsc_elt.make_pdu(       action = "list", tag = "bsc",        self_handle = ca.handle),
        rpki.left_right.repository_elt.make_pdu(action = "list", tag = "repository", self_handle = ca.handle),
        rpki.left_right.parent_elt.make_pdu(    action = "list", tag = "parent",     self_handle = ca.handle),
        rpki.left_right.child_elt.make_pdu(     action = "list", tag = "child",      self_handle = ca.handle))

      self_pdu        = rpkid_reply[0]
      bsc_pdus        = dict((x.bsc_handle, x) for x in rpkid_reply if isinstance(x, rpki.left_right.bsc_elt))
      repository_pdus = dict((x.repository_handle, x) for x in rpkid_reply if isinstance(x, rpki.left_right.repository_elt))
      parent_pdus     = dict((x.parent_handle, x) for x in rpkid_reply if isinstance(x, rpki.left_right.parent_elt))
      child_pdus      = dict((x.child_handle, x) for x in rpkid_reply if isinstance(x, rpki.left_right.child_elt))

      pubd_query = []
      rpkid_query = []

      self_cert, created = rpki.irdb.HostedCA.objects.get_or_certify(
        issuer = self.server_ca,
        hosted = ca)

      # There should be exactly one <self/> object per hosted entity, by definition

      if (isinstance(self_pdu, rpki.left_right.report_error_elt) or
          self_pdu.crl_interval != self_crl_interval or
          self_pdu.regen_margin != self_regen_margin or
          self_pdu.bpki_cert != self_cert.certificate):
        rpkid_query.append(rpki.left_right.self_elt.make_pdu(
          action = "create" if isinstance(self_pdu, rpki.left_right.report_error_elt) else "set",
          tag = "self",
          self_handle = ca.handle,
          bpki_cert = ca.certificate,
          crl_interval = self_crl_interval,
          regen_margin = self_regen_margin))

      # In general we only need one <bsc/> per <self/>.  BSC objects
      # are a little unusual in that the keypair and PKCS #10
      # subelement is generated by rpkid, so complete setup requires
      # two round trips.

      bsc_pdu = bsc_pdus.pop(bsc_handle, None)

      if bsc_pdu is None:
        rpkid_query.append(rpki.left_right.bsc_elt.make_pdu(
          action = "create",
          tag = "bsc",
          self_handle = ca.handle,
          bsc_handle = bsc_handle,
          generate_keypair = "yes"))

      elif bsc_pdu.pkcs10_request is None:
        rpkid_query.append(rpki.left_right.bsc_elt.make_pdu(
          action = "set",
          tag = "bsc",
          self_handle = ca.handle,
          bsc_handle = bsc_handle,
          generate_keypair = "yes"))

      rpkid_query.extend(rpki.left_right.bsc_elt.make_pdu(
        action = "destroy", self_handle = ca.handle, bsc_handle = b) for b in bsc_pdus)

      # If we've already got actions queued up, run them now, so we
      # can finish setting up the BSC before anything tries to use it.

      if rpkid_query:
        rpkid_query.append(rpki.left_right.bsc_elt.make_pdu(action = "list", tag = "bsc", self_handle = ca.handle))
        rpkid_reply = self.call_rpkid(*rpkid_query)
        bsc_pdus = dict((x.bsc_handle, x)
                        for x in rpkid_reply
                        if isinstance(x, rpki.left_right.bsc_elt) and x.action == "list")
        bsc_pdu = bsc_pdus.pop(bsc_handle, None)
        self.check_error_report(rpkid_reply)

      rpkid_query = []

      assert bsc_pdu.pkcs10_request is not None

      bsc, created = rpki.irdb.BSC.objects.get_or_certify(
        issuer = ca,
        handle = bsc_handle,
        pkcs10 = bsc_pdu.pkcs10_request)

      if bsc_pdu.signing_cert != bsc.certificate or bsc_pdu.signing_cert_crl != ca.latest_crl:
        rpkid_query.append(rpki.left_right.bsc_elt.make_pdu(
          action = "set",
          tag = "bsc",
          self_handle = ca.handle,
          bsc_handle = bsc_handle,
          signing_cert = bsc.certificate,
          signing_cert_crl = ca.latest_crl))

      # At present we need one <repository/> per <parent/>, not because
      # rpkid requires that, but because pubd does.  pubd probably should
      # be fixed to support a single client allowed to update multiple
      # trees, but for the moment the easiest way forward is just to
      # enforce a 1:1 mapping between <parent/> and <repository/> objects

      for repository in ca.repositories.all():

        repository_pdu = repository_pdus.pop(repository.handle, None)

        if (repository_pdu is None or
            repository_pdu.bsc_handle != bsc_handle or
            repository_pdu.peer_contact_uri != repository.service_uri or
            repository_pdu.bpki_cert != repository.certificate):
          rpkid_query.append(rpki.left_right.repository_elt.make_pdu(
            action = "create" if repository_pdu is None else "set",
            tag = repository.handle,
            self_handle = ca.handle,
            repository_handle = repository.handle,
            bsc_handle = bsc_handle,
            peer_contact_uri = repository.service_uri,
            bpki_cert = repository.certificate))

      rpkid_query.extend(rpki.left_right.repository_elt.make_pdu(
        action = "destroy", self_handle = ca.handle, repository_handle = r) for r in repository_pdus)

      # <parent/> setup code currently assumes 1:1 mapping between
      # <repository/> and <parent/>, and further assumes that the handles
      # for an associated pair are the identical (that is:
      # parent.repository_handle == parent.parent_handle).

      for parent in ca.parents.all():

        parent_pdu = parent_pdus.pop(parent.handle, None)

        if (parent_pdu is None or
            parent_pdu.bsc_handle != bsc_handle or
            parent_pdu.repository_handle != parent.handle or
            parent_pdu.peer_contact_uri != parent.service_uri or
            parent_pdu.sia_base != parent.repository.sia_base or
            parent_pdu.sender_name != parent.child_handle or
            parent_pdu.recipient_name != parent.parent_handle or
            parent_pdu.bpki_cms_cert != parent.certificate):
          rpkid_query.append(rpki.left_right.parent_elt.make_pdu(
            action = "create" if parent_pdu is None else "set",
            tag = parent.handle,
            self_handle = ca.handle,
            parent_handle = parent.handle,
            bsc_handle = bsc_handle,
            repository_handle = parent.handle,
            peer_contact_uri = parent.service_uri,
            sia_base = parent.repository.sia_base,
            sender_name = parent.child_handle,
            recipient_name = parent.parent_handle,
            bpki_cms_cert = parent.certificate))

      try:

        parent_pdu = parent_pdus.pop(ca.handle, None)

        if (parent_pdu is None or
            parent_pdu.bsc_handle != bsc_handle or
            parent_pdu.repository_handle != ca.handle or
            parent_pdu.peer_contact_uri != ca.rootd.service_uri or
            parent_pdu.sia_base != ca.rootd.repository.sia_base or
            parent_pdu.sender_name != ca.handle or
            parent_pdu.recipient_name != ca.handle or
            parent_pdu.bpki_cms_cert != ca.rootd.certificate):
          rpkid_query.append(rpki.left_right.parent_elt.make_pdu(
            action = "create" if parent_pdu is None else "set",
            tag = ca.handle,
            self_handle = ca.handle,
            parent_handle = ca.handle,
            bsc_handle = bsc_handle,
            repository_handle = ca.handle,
            peer_contact_uri = ca.rootd.service_uri,
            sia_base = ca.rootd.repository.sia_base,
            sender_name = ca.handle,
            recipient_name = ca.handle,
            bpki_cms_cert = ca.rootd.certificate))

      except rpki.irdb.Rootd.DoesNotExist:
        pass

      rpkid_query.extend(rpki.left_right.parent_elt.make_pdu(
        action = "destroy", self_handle = ca.handle, parent_handle = p) for p in parent_pdus)

      # Children are simpler than parents, because they call us, so no URL
      # to construct and figuring out what certificate to use is their
      # problem, not ours.

      for child in ca.children.all():

        child_pdu = child_pdus.pop(child.handle, None)

        if (child_pdu is None or
            child_pdu.bsc_handle != bsc_handle or
            child_pdu.bpki_cert != child.certificate):
          rpkid_query.append(rpki.left_right.child_elt.make_pdu(
            action = "create" if child_pdu is None else "set",
            tag = child.handle,
            self_handle = ca.handle,
            child_handle = child.handle,
            bsc_handle = bsc_handle,
            bpki_cert = child.certificate))

      rpkid_query.extend(rpki.left_right.child_elt.make_pdu(
        action = "destroy", self_handle = ca.handle, child_handle = c) for c in child_pdus)

      # Publication setup.

      # Um, why are we doing this per resource holder?

      if self.run_pubd:

        for client in self.server_ca.clients.all():

          client_pdu = client_pdus.pop(client.handle, None)

          if (client_pdu is None or
              client_pdu.base_uri != client.sia_base or
              client_pdu.bpki_cert != client.certificate):
            pubd_query.append(rpki.publication.client_elt.make_pdu(
              action = "create" if client_pdu is None else "set",
              client_handle = client.handle,
              bpki_cert = client.certificate,
              base_uri = client.sia_base))

        pubd_query.extend(rpki.publication.client_elt.make_pdu(
            action = "destroy", client_handle = p) for p in client_pdus)

      # Poke rpkid to run immediately for any requested handles.

      rpkid_query.extend(rpki.left_right.self_elt.make_pdu(
        action = "set", self_handle = h, run_now = "yes") for h in handles_to_poke)

      # If we changed anything, ship updates off to daemons

      if rpkid_query:
        rpkid_reply = self.call_rpkid(*rpkid_query)
        bsc_pdus = dict((x.bsc_handle, x) for x in rpkid_reply if isinstance(x, rpki.left_right.bsc_elt))
        if bsc_handle in bsc_pdus and bsc_pdus[bsc_handle].pkcs10_request:
          bsc_req = bsc_pdus[bsc_handle].pkcs10_request
        self.check_error_report(rpkid_reply)

      if pubd_query:
        assert self.run_pubd
        pubd_reply = self.call_pubd(*pubd_query)
        self.check_error_report(pubd_reply)

    # Finally, clean up any <self/> objects rpkid might be holding
    # that don't match ResourceCA object.

    rpkid_reply = self.call_rpkid(rpki.left_right.self_elt.make_pdu(action = "list"))
    self.check_error_report(rpkid_reply)

    self_handles = set(s.self_handle for s in rpkid_reply)
    ca_handles   = set(ca.handle for ca in rpki.irdb.ResourceHolderCA.objects.all())
    assert ca_handles <= self_handles

    rpkid_query = [rpki.left_right.self_elt.make_pdu(action = "destroy", self_handle = handle)
                   for handle in (self_handles - ca_handles)]
    rpkid_reply = self.call_rpkid(*rpkid_query)
    self.check_error_report(rpkid_reply)
