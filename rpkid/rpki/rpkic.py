"""
This is a command line configuration and control tool for rpkid et al.

Type "help" on the prompt, or run the program with the --help option for an
overview of the available commands; type "help foo" for (more) detailed help
on the "foo" command.


This program is a rewrite of the old myrpki program, replacing ten
zillion XML and X.509 disk files and subprocess calls to the OpenSSL
command line tool with SQL data and direct calls to the rpki.POW
library.  This version abandons all pretense that this program might
somehow work without rpki.POW, lxml, and Django installed, but since
those packages are required for rpkid anyway, this seems like a small
price to pay for major simplification of the code and better
integration with the Django-based GUI interface.

$Id$

Copyright (C) 2009--2011  Internet Systems Consortium ("ISC")

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

# NB: As of this writing, I'm trying really hard to avoid having this
# program depend on a Django settings.py file.  This may prove to be a
# waste of time in the long run, but for for now, this means that one
# has to be careful about exactly how and when one imports Django
# modules, or anything that imports Django modules.  Bottom line is
# that we don't import such modules until we need them.


# We need context managers for transactions.  Well, unless we're
# willing to have this program depend on a Django settings.py file so
# that we can use decorators, which I'm not, at the moment.

from __future__ import with_statement

import subprocess, csv, re, os, getopt, sys, base64, time, glob, copy, warnings
import rpki.config, rpki.cli, rpki.sundial, rpki.log, rpki.oids
import rpki.http, rpki.resource_set, rpki.relaxng, rpki.exceptions
import rpki.left_right, rpki.x509, rpki.async

from lxml.etree import (Element, SubElement, ElementTree,
                        fromstring as ElementFromString,
                        tostring   as ElementToString)

from rpki.csv_utils import (csv_reader, csv_writer, BadCSVSyntax)



# Our XML namespace and protocol version.

namespace      = "http://www.hactrn.net/uris/rpki/myrpki/"
version        = "2"
namespaceQName = "{" + namespace + "}"

# A whole lot of exceptions

class BadCommandSyntax(Exception):      "Bad command line syntax."
class BadPrefixSyntax(Exception):       "Bad prefix syntax."
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

  def __init__(self, verbose = False):
    self.wrote = set()
    self.verbose = verbose

  def __call__(self, filename, obj):
    filename = os.path.realpath(filename)
    if filename in self.wrote:
      return
    tempname = filename
    if not filename.startswith("/dev/"):
      tempname += ".%s.tmp" % os.getpid()
    mode = 0400 if filename.endswith(".key") else 0444
    if self.verbose:
      print "Writing", filename
    f = os.fdopen(os.open(tempname, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode), "w")
    f.write(obj.get_PEM())
    f.close()
    if tempname != filename:
      os.rename(tempname, filename)
    self.wrote.add(filename)



def etree_write(e, filename, verbose = False, msg = None):
  """
  Write out an etree to a file, safely.

  I still miss SYSCAL(RENMWO).
  """

  filename = os.path.realpath(filename)
  tempname = filename
  if not filename.startswith("/dev/"):
    tempname += ".%s.tmp" % os.getpid()
  if verbose or msg:
    print "Writing", filename
  if msg:
    print msg
  e = copy.deepcopy(e)
  e.set("version", version)
  for i in e.getiterator():
    if i.tag[0] != "{":
      i.tag = namespaceQName + i.tag
    assert i.tag.startswith(namespaceQName)
  rpki.relaxng.myrpki.assertValid(e)
  ElementTree(e).write(tempname)
  if tempname != filename:
    os.rename(tempname, filename)

def etree_read(filename, verbose = False):
  """
  Read an etree from a file, verifying then stripping XML namespace
  cruft.
  """

  if verbose:
    print "Reading", filename
  e = ElementTree(file = filename).getroot()
  rpki.relaxng.myrpki.assertValid(e)
  for i in e.getiterator():
    if i.tag.startswith(namespaceQName):
      i.tag = i.tag[len(namespaceQName):]
    else:
      raise BadXMLMessage, "XML tag %r is not in namespace %r" % (i.tag, namespace)
  return e



class main(rpki.cli.Cmd):

  prompt = "rpkic> "

  completedefault = rpki.cli.Cmd.filename_complete

  show_xml = False

  def __init__(self):
    os.environ["TZ"] = "UTC"
    time.tzset()

    rpki.log.use_syslog = False

    self.cfg_file = None
    self.handle = None

    opts, argv = getopt.getopt(sys.argv[1:], "c:hi:?", ["config=", "help", "identity="])
    for o, a in opts:
      if o in ("-c", "--config"):
        self.cfg_file = a
      elif o in ("-h", "--help", "-?"):
        argv = ["help"]
      elif o in ("-i", "--identity"):
        self.handle = a

    if not argv or argv[0] != "help":
      rpki.log.init("rpkic")
      self.read_config()

    rpki.cli.Cmd.__init__(self, argv)

  def read_config(self):

    # For reasons I don't understand, importing this at the global
    # level isn't working properly today.  Importing it here works
    # fine.  WTF?

    import rpki.config
    
    self.cfg = rpki.config.parser(self.cfg_file, "myrpki")

    self.cfg.set_global_flags()

    if self.handle is None:
      self.handle  = self.cfg.get("handle")

    self.histfile  = self.cfg.get("history_file", ".rpkic_history")
    self.run_rpkid = self.cfg.getboolean("run_rpkid")
    self.run_pubd  = self.cfg.getboolean("run_pubd")
    self.run_rootd = self.cfg.getboolean("run_rootd")

    irdbd_section = "irdbd"

    from django.conf import settings

    settings.configure(
      DATABASES = { "default" : {
        "ENGINE"   : "django.db.backends.mysql",
        "NAME"     : self.cfg.get("sql-database", section = irdbd_section),
        "USER"     : self.cfg.get("sql-username", section = irdbd_section),
        "PASSWORD" : self.cfg.get("sql-password", section = irdbd_section),
        "HOST"     : "",
        "PORT"     : "",
        "OPTIONS"  : { "init_command": "SET storage_engine=INNODB" }}},
      INSTALLED_APPS = ("rpki.irdb",),
    )

    import rpki.irdb

    import django.core.management
    django.core.management.call_command("syncdb", verbosity = 0, load_initial_data = False)

    if self.run_rootd and (not self.run_pubd or not self.run_rpkid):
      raise CantRunRootd, "Can't run rootd unless also running rpkid and pubd"

    self.default_repository = self.cfg.get("default_repository", "")
    self.pubd_contact_info = self.cfg.get("pubd_contact_info", "")

    self.rsync_module = self.cfg.get("publication_rsync_module")
    self.rsync_server = self.cfg.get("publication_rsync_server")

    self.reset_identity()

  def reset_identity(self):
    try:
      self.resource_ca = rpki.irdb.ResourceHolderCA.objects.get(handle = self.handle)
    except rpki.irdb.ResourceHolderCA.DoesNotExist:
      self.resource_ca = None
    try:
      self.server_ca = rpki.irdb.ServerCA.objects.get()
    except rpki.irdb.ServerCA.DoesNotExist:
      self.server_ca = None

  def help_overview(self):
    """
    Show program __doc__ string.  Perhaps there's some clever way to
    do this using the textwrap module, but for now something simple
    and crude will suffice.
    """

    for line in __doc__.splitlines(True):
      self.stdout.write(" " * 4 + line)
    self.stdout.write("\n")

  def irdb_handle_complete(self, klass, text, line, begidx, endidx):
    return [obj.handle for obj in klass.objects.all() if obj.handle and obj.handle.startswith(text)]

  def do_select_identity(self, arg):
    """
    Select an identity handle for use with later commands.
    """

    argv = arg.split()
    if len(argv) != 1:
      raise BadCommandSyntax("This command expexcts one argument, not %r" % arg)
    self.handle = argv[0]
    self.reset_identity()

  def complete_select_identity(self, *args):
    return self.irdb_handle_complete(rpki.irdb.ResourceHolderCA, *args)


  def do_initialize(self, arg):
    """
    Initialize an RPKI installation.  This command reads the
    configuration file, creates the BPKI and EntityDB directories,
    generates the initial BPKI certificates, and creates an XML file
    describing the resource-holding aspect of this RPKI installation.
    """

    if arg:
      raise BadCommandSyntax, "This command takes no arguments"

    self.resource_ca, created = rpki.irdb.ResourceHolderCA.objects.get_or_certify(handle = self.handle)
    if created:
      print "Created new BPKI resource CA for identity %s" % self.handle

    if self.run_rpkid or self.run_pubd:
      self.server_ca, created = rpki.irdb.ServerCA.objects.get_or_certify()
      if created:
        print "Created new BPKI server CA"
      rpki.irdb.ServerEE.objects.get_or_certify(issuer = self.server_ca, purpose = "irbe")

    if self.run_rpkid:
      rpki.irdb.ServerEE.objects.get_or_certify(issuer = self.server_ca, purpose = "rpkid")
      rpki.irdb.ServerEE.objects.get_or_certify(issuer = self.server_ca, purpose = "irdbd")

    if self.run_pubd:
      rpki.irdb.ServerEE.objects.get_or_certify(issuer = self.server_ca, purpose = "pubd")

    # Build the identity.xml file.  Need to check for existing file so we don't
    # overwrite?  Worry about that later.

    run_rootd = self.run_rootd and self.handle == self.cfg.get("handle")

    e = Element("identity", handle = self.handle)
    B64Element(e, "bpki_ta", self.resource_ca.certificate)
    etree_write(e, "%s.identity.xml" % self.handle,
                msg = None if run_rootd else 'This is the "identity" file you will need to send to your parent')

    if run_rootd:
      assert self.run_rpkid and self.run_pubd

      rpki.irdb.Rootd.objects.get_or_certify(
        issuer = self.resource_ca,
        service_uri = "http://localhost:%s/" % self.cfg.get("rootd_server_port"))

      # The following assumes we'll set up the respository manually.
      # Not sure this is a reasonable assumption, particularly if we
      # ever fix rootd to use the publication protocol.

      try:
        self.resource_ca.repositories.get(handle = self.handle)

      except rpki.irdb.Repository.DoesNotExist:
        e = Element("repository", type = "offer", handle = self.handle, parent_handle = self.handle)
        B64Element(e, "bpki_client_ta", self.resource_ca.certificate)
        etree_write(e, "%s.%s.repository-request.xml" % (self.handle, self.handle),
                    msg = 'This is the "repository offer" file for you to use if you want to publish in your own repository')

    # Not (yet) sure whether we should be calling this here, try it for now
    self.write_bpki_files()


  def write_bpki_files(self):
    """
    Write out BPKI certificate, key, and CRL files for daemons that
    need them.
    """

    writer = PEM_writer()

    if self.run_rpkid:
      rpkid = self.server_ca.ee_certificates.get(purpose = "rpkid")
      writer(self.cfg.get("bpki-ta",    section = "rpkid"), self.server_ca.certificate)
      writer(self.cfg.get("rpkid-key",  section = "rpkid"), rpkid.private_key)
      writer(self.cfg.get("rpkid-cert", section = "rpkid"), rpkid.certificate)
      writer(self.cfg.get("irdb-cert",  section = "rpkid"),
             self.server_ca.ee_certificates.get(purpose = "irdbd").certificate)
      writer(self.cfg.get("irbe-cert",  section = "rpkid"),
             self.server_ca.ee_certificates.get(purpose = "irbe").certificate)

    if self.run_pubd:
      pubd = self.server_ca.ee_certificates.get(purpose = "pubd")
      writer(self.cfg.get("bpki-ta",   section = "pubd"), self.server_ca.certificate)
      writer(self.cfg.get("pubd-key",  section = "pubd"), pubd.private_key)
      writer(self.cfg.get("pubd-cert", section = "pubd"), pubd.certificate)
      writer(self.cfg.get("irbe-cert", section = "pubd"),
             self.server_ca.ee_certificates.get(purpose = "irbe").certificate)

    if self.run_rootd:
      rootd = rpki.irdb.ResourceHolderCA.objects.get(handle = self.cfg.get("handle", section = "myrpki")).rootd
      writer(self.cfg.get("bpki-ta",         section = "rootd"), self.server_ca.certificate)
      writer(self.cfg.get("rootd-bpki-crl",  section = "rootd"), self.server_ca.latest_crl)
      writer(self.cfg.get("rootd-bpki-key",  section = "rootd"), rootd.private_key)
      writer(self.cfg.get("rootd-bpki-cert", section = "rootd"), rootd.certificate)
      writer(self.cfg.get("child-bpki-cert", section = "rootd"), rootd.issuer.certificate)


  def do_update_bpki(self, arg):
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
        print "Regenerating certificate", obj.certificate.getSubject()
        obj.avow()

    print "Regenerating Server CRL"
    self.server_ca.generate_crl()
    
    for ca in rpki.irdb.ResourceHolderCA.objects.all():
      print "Regenerating CRL for", ca.handle
      ca.generate_crl()

    self.write_bpki_files()


  def do_configure_child(self, arg):
    """
    Configure a new child of this RPKI entity, given the child's XML
    identity file as an input.  This command extracts the child's data
    from the XML, cross-certifies the child's resource-holding BPKI
    certificate, and generates an XML file describing the relationship
    between the child and this parent, including this parent's BPKI
    data and up-down protocol service URI.
    """

    child_handle = None

    opts, argv = getopt.getopt(arg.split(), "", ["child_handle="])
    for o, a in opts:
      if o == "--child_handle":
        child_handle = a
    
    if len(argv) != 1:
      raise BadCommandSyntax, "Need to specify filename for child.xml"

    c = etree_read(argv[0])

    if child_handle is None:
      child_handle = c.get("handle")

    service_uri = "http://%s:%s/up-down/%s/%s" % (self.cfg.get("rpkid_server_host"),
                                                  self.cfg.get("rpkid_server_port"),
                                                  self.handle, child_handle)

    valid_until = rpki.sundial.now() + rpki.sundial.timedelta(days = 365)

    print "Child calls itself %r, we call it %r" % (c.get("handle"), child_handle)

    child, created = rpki.irdb.Child.objects.get_or_certify(
      issuer = self.resource_ca,
      handle = child_handle,
      ta = rpki.x509.X509(Base64 = c.findtext("bpki_ta")),
      valid_until = valid_until)

    e = Element("parent", parent_handle = self.handle, child_handle = child_handle,
                service_uri = service_uri, valid_until = str(valid_until))
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
      print "Couldn't find any usable repositories, not giving referral"

    elif repo.handle == self.handle:
      SubElement(e, "repository", type = "offer")

    else:
      proposed_sia_base = repo.sia_base + child_handle + "/"
      referral_cert, created = rpki.irdb.Referral.objects.get_or_certify(issuer = self.resource_ca)
      auth = rpki.x509.SignedReferral()
      auth.set_content(B64Element(None, namespaceQName + "referral", child.ta,
                                  version = version,
                                  authorized_sia_base = proposed_sia_base))
      auth.schema_check()
      auth.sign(referral_cert.private_key, referral_cert.certificate, self.resource_ca.latest_crl)

      r = SubElement(e, "repository", type = "referral")
      B64Element(r, "authorization", auth, referrer = repo.client_handle)
      SubElement(r, "contact_info")

    etree_write(e, "%s.%s.parent-response.xml" % (self.handle, child_handle),
                msg = "Send this file back to the child you just configured")


  def do_delete_child(self, arg):
    """
    Delete a child of this RPKI entity.
    """

    try:
      self.resource_ca.children.get(handle = arg).delete()
    except rpki.irdb.Child.DoesNotExist:
      print "No such child \"%s\"" % arg

  def complete_delete_child(self, *args):
    return self.irdb_handle_complete(rpki.irdb.Child, *args)


  def do_configure_parent(self, arg):
    """
    Configure a new parent of this RPKI entity, given the output of
    the parent's configure_child command as input.  This command reads
    the parent's response XML, extracts the parent's BPKI and service
    URI information, cross-certifies the parent's BPKI data into this
    entity's BPKI, and checks for offers or referrals of publication
    service.  If a publication offer or referral is present, we
    generate a request-for-service message to that repository, in case
    the user wants to avail herself of the referral or offer.
    """

    parent_handle = None

    opts, argv = getopt.getopt(arg.split(), "", ["parent_handle="])
    for o, a in opts:
      if o == "--parent_handle":
        parent_handle = a

    if len(argv) != 1:
      raise BadCommandSyntax, "Need to specify filename for parent.xml on command line"

    p = etree_read(argv[0])

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

    print "Parent calls itself %r, we call it %r" % (p.get("parent_handle"), parent_handle)
    print "Parent calls us %r" % p.get("child_handle")

    rpki.irdb.Parent.objects.get_or_certify(
      issuer = self.resource_ca,
      handle = parent_handle,
      child_handle = p.get("child_handle"),
      parent_handle = p.get("parent_handle"),
      service_uri = p.get("service_uri"),
      ta = rpki.x509.X509(Base64 = p.findtext("bpki_resource_ta")),
      repository_type = repository_type,
      referrer = referrer,
      referral_authorization = referral_authorization)

    if repository_type == "none":
      r = Element("repository", type = "none")
    r.set("handle", self.handle)
    r.set("parent_handle", parent_handle)
    B64Element(r, "bpki_client_ta", self.resource_ca.certificate)
    etree_write(r, "%s.%s.repository-request.xml" % (self.handle, parent_handle),
                msg = "This is the file to send to the repository operator")


  def do_delete_parent(self, arg):
    """
    Delete a parent of this RPKI entity.
    """

    try:
      self.resource_ca.parents.get(handle = arg).delete()
    except rpki.irdb.Parent.DoesNotExist:
      print "No such parent \"%s\"" % arg

  def complete_delete_parent(self, *args):
    return self.irdb_handle_complete(rpki.irdb.Parent, *args)


  def do_configure_publication_client(self, arg):
    """
    Configure publication server to know about a new client, given the
    client's request-for-service message as input.  This command reads
    the client's request for service, cross-certifies the client's
    BPKI data, and generates a response message containing the
    repository's BPKI data and service URI.
    """

    sia_base = None

    opts, argv = getopt.getopt(arg.split(), "", ["sia_base="])
    for o, a in opts:
      if o == "--sia_base":
        sia_base = a
    
    if len(argv) != 1:
      raise BadCommandSyntax, "Need to specify filename for client.xml"

    client = etree_read(argv[0])

    client_ta = rpki.x509.X509(Base64 = client.findtext("bpki_client_ta"))

    if sia_base is None and client.get("handle") == self.handle and self.resource_ca.certificate == client_ta:
      print "This looks like self-hosted publication"
      sia_base = "rsync://%s/%s/%s/" % (self.rsync_server, self.rsync_module, self.handle)

    if sia_base is None and client.get("type") == "referral":
      print "This looks like a referral, checking"
      try:
        auth = client.find("authorization")
        referrer = self.server_ca.clients.get(handle = auth.get("referrer"))
        referral_cms = rpki.x509.SignedReferral(Base64 = auth.text)
        referral_xml = referral_cms.unwrap(ta = (referrer.certificate, self.server_ca.certificate))
        if rpki.x509.X509(Base64 = referral_xml.text) != client_ta:
          raise BadXMLMessage, "Referral trust anchor does not match"
        sia_base = referral_xml.get("authorized_sia_base")
      except rpki.irdb.Client.DoesNotExist:
        print "We have no record of the client (%s) alleged to have made this referral" % auth.get("referrer")

    if sia_base is None and client.get("type") == "offer" and client.get("parent_handle") == self.handle:
      print "This looks like an offer, client claims to be our child, checking"
      try:
        child = self.resource_ca.children.get(ta = client_ta)
      except rpki.irdb.Child.DoesNotExist:
        print "Can't find a child matching this client"
      else:
        sia_base = "rsync://%s/%s/%s/%s/" % (self.rsync_server, self.rsync_module,
                                             self.handle, client.get("handle"))

    # If we still haven't figured out what to do with this client, it
    # gets a top-level tree of its own, no attempt at nesting.

    if sia_base is None:
      print "Don't know where to nest this client, defaulting to top-level"
      sia_base = "rsync://%s/%s/%s/" % (self.rsync_server, self.rsync_module, client.get("handle"))
      
    if not sia_base.startswith("rsync://"):
      raise BadXMLMessage, "Malformed sia_base parameter %r, should start with 'rsync://'" % sia_base

    client_handle = "/".join(sia_base.rstrip("/").split("/")[4:])

    parent_handle = client.get("parent_handle")

    print "Client calls itself %r, we call it %r" % (client.get("handle"), client_handle)
    print "Client says its parent handle is %r" % parent_handle

    rpki.irdb.Client.objects.get_or_certify(
      issuer = self.server_ca,
      handle = client_handle,
      ta = client_ta,
      sia_base = sia_base)

    e = Element("repository", type = "confirmed",
                client_handle = client_handle,
                parent_handle = parent_handle,
                sia_base = sia_base,
                service_uri = "http://%s:%s/client/%s" % (self.cfg.get("pubd_server_host"),
                                                          self.cfg.get("pubd_server_port"),
                                                          client_handle))

    B64Element(e, "bpki_server_ta", self.server_ca.certificate)
    B64Element(e, "bpki_client_ta", client_ta)
    SubElement(e, "contact_info").text = self.pubd_contact_info
    etree_write(e, "%s.repository-response.xml" % client_handle.replace("/", "."),
                msg = "Send this file back to the publication client you just configured")


  def do_delete_publication_client(self, arg):
    """
    Delete a publication client of this RPKI entity.
    """

    try:
      self.resource_ca.clients.get(handle = arg).delete()
    except rpki.irdb.Client.DoesNotExist:
      print "No such client \"%s\"" % arg

  def complete_delete_publication_client(self, *args):
    return self.irdb_handle_complete(rpki.irdb.Client, *args)


  def do_configure_repository(self, arg):
    """
    Configure a publication repository for this RPKI entity, given the
    repository's response to our request-for-service message as input.
    This command reads the repository's response, extracts and
    cross-certifies the BPKI data and service URI, and links the
    repository data with the corresponding parent data in our local
    database.
    """

    parent_handle = None

    opts, argv = getopt.getopt(arg.split(), "", ["parent_handle="])
    for o, a in opts:
      if o == "--parent_handle":
        parent_handle = a

    if len(argv) != 1:
      raise BadCommandSyntax, "Need to specify filename for repository.xml on command line"

    r = etree_read(argv[0])

    if parent_handle is None:
      parent_handle = r.get("parent_handle")

    print "Repository calls us %r" % (r.get("client_handle"))
    print "Repository response associated with parent_handle %r" % parent_handle

    try:
      if parent_handle == self.handle:
        turtle = self.resource_ca.rootd
      else:
        turtle = self.resource_ca.parents.get(handle = parent_handle)

    except (rpki.irdb.Parent.DoesNotExist, rpki.irdb.Rootd.DoesNotExist):
      print "Could not find parent %r in our database" % parent_handle

    else:
      rpki.irdb.Repository.objects.get_or_certify(
        issuer = self.resource_ca,
        handle = parent_handle,
        client_handle = r.get("client_handle"),
        service_uri = r.get("service_uri"),
        sia_base = r.get("sia_base"),
        ta = rpki.x509.X509(Base64 = r.findtext("bpki_server_ta")),
        turtle = turtle)

  def do_delete_repository(self, arg):
    """
    Delete a repository of this RPKI entity.

    This should check that the XML file it's deleting really is a
    repository, but doesn't, yet.
    """

    try:
      self.resource_ca.repositories.get(handle = arg).delete()
    except rpki.irdb.Repository.DoesNotExist:
      print "No such repository \"%s\"" % arg

  def complete_delete_repository(self, *args):
    return self.irdb_handle_complete(rpki.irdb.Repository, *args)


  def renew_children_common(self, arg, plural):
    """
    Common code for renew_child and renew_all_children commands.
    """

    valid_until = None

    opts, argv = getopt.getopt(arg.split(), "", ["valid_until"])
    for o, a in opts:
      if o == "--valid_until":
        valid_until = a

    if plural:
      if len(argv) != 0:
        raise BadCommandSyntax, "Unexpected arguments"
      children = self.resource_ca.children
    else:
      if len(argv) != 1:
        raise BadCommandSyntax, "Need to specify child handle"
      children = self.resource_ca.children.filter(handle = argv[0])

    if valid_until is None:
      valid_until = rpki.sundial.now() + rpki.sundial.timedelta(days = 365)
    else:
      valid_until = rpki.sundial.fromXMLtime(valid_until)
      if valid_until < rpki.sundial.now():
        raise PastExpiration, "Specified new expiration time %s has passed" % valid_until

    print "New validity date", valid_until

    for child in children:
      child.valid_until = valid_until
      child.save()

  def do_renew_child(self, arg):
    """
    Update validity period for one child entity.
    """

    return self.renew_children_common(arg, False)

  def complete_renew_child(self, *args):
    return self.irdb_handle_complete(rpki.irdb.Child, *args)

  def do_renew_all_children(self, arg):
    """
    Update validity period for all child entities.
    """

    return self.renew_children_common(arg, True)


  def do_synchronize_prefixes(self, arg):
    """
    Synchronize IRDB against prefixes.csv.
    """

    argv = arg.split()

    if len(argv) != 1:
      raise BadCommandSyntax("Need to specify prefixes.csv filename")

    grouped4 = {}
    grouped6 = {}

    for handle, prefix in csv_reader(argv[0], columns = 2):
      grouped = grouped6 if ":" in prefix else grouped4
      if handle not in grouped:
        grouped[handle] = []
      grouped[handle].append(prefix)

    import django.db.transaction

    with django.db.transaction.commit_on_success():

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


  def do_show_child_resources(self, arg):
    """
    Show resources assigned to children.
    """

    if arg.strip():
      raise BadCommandSyntax("This command takes no arguments")

    for child in self.resource_ca.children.all():

      asn = rpki.resource_set.resource_set_as.from_django(
        (a.start_as, a.end_as) for a in child.asns.all())
      ipv4 = rpki.resource_set.resource_set_ipv4.from_django(
        (a.start_ip, a.end_ip) for a in child.address_ranges.filter(version = 4))
      ipv6 = rpki.resource_set.resource_set_ipv6.from_django(
        (a.start_ip, a.end_ip) for a in child.address_ranges.filter(version = 6))

      print "Child:", child.handle
      if asn:
        print "  ASN:", asn
      if ipv4:
        print " IPv4:", ipv4
      if ipv6:
        print " IPv6:", ipv6


  def do_synchronize_asns(self, arg):
    """
    Synchronize IRDB against asns.csv.
    """

    argv = arg.split()

    if len(argv) != 1:
      raise BadCommandSyntax("Need to specify asns.csv filename")

    grouped = {}

    for handle, asn in csv_reader(argv[0], columns = 2):
      if handle not in grouped:
        grouped[handle] = []
      grouped[handle].append(asn)

    import django.db.transaction

    with django.db.transaction.commit_on_success():

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


  def do_synchronize_roa_requests(self, arg):
    """
    Synchronize IRDB against roa.csv.
    """

    argv = arg.split()

    if len(argv) != 1:
      raise BadCommandSyntax("Need to specify roa.csv filename")

    grouped = {}

    # format:  p/n-m asn group
    for pnm, asn, group in csv_reader(argv[0], columns = 3):
      key = (asn, group)
      if key not in grouped:
        grouped[key] = []
      grouped[key].append(pnm)

    import django.db.transaction

    with django.db.transaction.commit_on_success():

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


  def do_synchronize(self, arg):
    """
    Temporary testing hack (probably) to let me run .synchronize()
    manually.
    """

    if arg:
      raise BadCommandSyntax("Unexpected argument(s): %r" % arg)

    self.synchronize()


  def synchronize(self):
    """
    Configure RPKI daemons with the data built up by the other
    commands in this program.  Most commands which modify the IRDB
    should call this when they're done.
    """

    # We can use a single BSC for everything -- except BSC key
    # rollovers.  Drive off that bridge when we get to it.

    bsc_handle = "bsc"

    # Default values for CRL parameters are low, for testing.  Not
    # quite as low as they once were, too much expired CRL whining.

    self_crl_interval = self.cfg.getint("self_crl_interval", 2 * 60 * 60)
    self_regen_margin = self.cfg.getint("self_regen_margin", self_crl_interval / 4)
    pubd_base         = "http://%s:%s/" % (self.cfg.get("pubd_server_host"), self.cfg.get("pubd_server_port"))
    rpkid_base        = "http://%s:%s/" % (self.cfg.get("rpkid_server_host"), self.cfg.get("rpkid_server_port"))

    # Wrappers to simplify calling rpkid and pubd.

    irbe = self.server_ca.ee_certificates.get(purpose = "irbe")

    call_rpkid = rpki.async.sync_wrapper(rpki.http.caller(
      proto       = rpki.left_right,
      client_key  = irbe.private_key,
      client_cert = irbe.certificate,
      server_ta   = self.server_ca.certificate,
      server_cert = self.server_ca.ee_certificates.get(purpose = "rpkid").certificate,
      url         = rpkid_base + "left-right",
      debug       = self.show_xml))

    if self.run_pubd:

      call_pubd = rpki.async.sync_wrapper(rpki.http.caller(
        proto       = rpki.publication,
        client_key  = irbe.private_key,
        client_cert = irbe.certificate,
        server_ta   = self.server_ca.certificate,
        server_cert = self.server_ca.ee_certificates.get(purpose = "pubd").certificate,
        url         = pubd_base + "control",
        debug       = self.show_xml))

      # Make sure that pubd's BPKI CRL is up to date.

      call_pubd(rpki.publication.config_elt.make_pdu(
        action = "set",
        bpki_crl = self.server_ca.latest_crl))

    for ca in rpki.irdb.ResourceHolderCA.objects.all():

      # See what rpkid and pubd already have on file for this entity.

      if self.run_pubd:
        pubd_reply = call_pubd(rpki.publication.client_elt.make_pdu(action = "list"))
        client_pdus = dict((x.client_handle, x) for x in pubd_reply if isinstance(x, rpki.publication.client_elt))

      rpkid_reply = call_rpkid(
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
        rpkid_reply = call_rpkid(*rpkid_query)
        bsc_pdus = dict((x.bsc_handle, x)
                        for x in rpkid_reply
                        if isinstance(x, rpki.left_right.bsc_elt) and x.action == "list")
        bsc_pdu = bsc_pdus.pop(bsc_handle, None)
        for r in rpkid_reply:
          if isinstance(r, rpki.left_right.report_error_elt):
            print "rpkid reported failure:", r.error_code
            if r.error_text:
              print r.error_text
        if any(isinstance(r, rpki.left_right.report_error_elt) for r in rpkid_reply):
          raise CouldntTalkToDaemon

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

      # If we changed anything, ship updates off to daemons

      if rpkid_query:
        rpkid_reply = call_rpkid(*rpkid_query)
        bsc_pdus = dict((x.bsc_handle, x) for x in rpkid_reply if isinstance(x, rpki.left_right.bsc_elt))
        if bsc_handle in bsc_pdus and bsc_pdus[bsc_handle].pkcs10_request:
          bsc_req = bsc_pdus[bsc_handle].pkcs10_request
        for r in rpkid_reply:
          if isinstance(r, rpki.left_right.report_error_elt):
            print "rpkid reported failure:", r.error_code
            if r.error_text:
              print r.error_text
        if any(isinstance(r, rpki.left_right.report_error_elt) for r in rpkid_reply):
          raise CouldntTalkToDaemon

      if pubd_query:
        assert self.run_pubd
        pubd_reply = call_pubd(*pubd_query)
        for r in pubd_reply:
          if isinstance(r, rpki.publication.report_error_elt):
            print "pubd reported failure:", r.error_code
            if r.error_text:
              print r.error_text
        if any(isinstance(r, rpki.publication.report_error_elt) for r in pubd_reply):
          raise CouldntTalkToDaemon
